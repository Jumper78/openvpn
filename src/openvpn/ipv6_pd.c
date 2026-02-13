/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef TARGET_LINUX

#include "syshead.h"

#include "ipv6_pd.h"
#include "buffer.h"
#include "errlevel.h"
#include "error.h"
#include "fdmisc.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

/**
 * Mask an in6_addr to the given prefix length, zeroing out the host bits.
 */
static void
ipv6_pd_mask_prefix(struct in6_addr *addr, int prefix_len)
{
    for (int i = 0; i < 16; i++)
    {
        if (prefix_len >= 8)
        {
            prefix_len -= 8;
        }
        else if (prefix_len > 0)
        {
            addr->s6_addr[i] &= (uint8_t)(0xFF << (8 - prefix_len));
            prefix_len = 0;
        }
        else
        {
            addr->s6_addr[i] = 0;
        }
    }
}

/**
 * Format an in6_addr as text.  Uses a static buffer — not thread-safe,
 * intended for log messages only.
 */
static const char *
ipv6_pd_fmt_addr(const struct in6_addr *addr)
{
    static char buf[INET6_ADDRSTRLEN];

    return inet_ntop(AF_INET6, addr, buf, sizeof(buf));
}

/**
 * Process a single RTM_NEWADDR / RTM_DELADDR netlink message.
 *
 * If the message matches our monitored interface and carries a global-scope
 * IPv6 address whose prefix length matches the expected PD prefix, update
 * the monitor state and log the change.
 *
 * @param nlh   netlink message header
 * @param mon   the PD monitor
 * @param source  descriptive string for log messages ("query" or "event")
 */
static void
ipv6_pd_handle_addr_msg(const struct nlmsghdr *nlh, struct ipv6_pd_mon *mon,
                         const char *source)
{
    const struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    const struct rtattr *rta;
    int len;
    struct in6_addr addr;
    bool have_addr = false;

    /* only interested in IPv6 */
    if (ifa->ifa_family != AF_INET6)
    {
        return;
    }

    /* only interested in our interface */
    if ((int)ifa->ifa_index != mon->ifindex)
    {
        return;
    }

    /* only interested in global (universe) scope addresses */
    if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
    {
        return;
    }

    /* only interested in addresses that match the expected PD prefix length */
    if (mon->expected_prefix_len > 0 && (int)ifa->ifa_prefixlen != mon->expected_prefix_len)
    {
        return;
    }

    /* parse attributes to find IFA_ADDRESS */
    rta = (const struct rtattr *)((const char *)ifa + NLMSG_ALIGN(sizeof(*ifa)));
    len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

    while (RTA_OK(rta, len))
    {
        if (rta->rta_type == IFA_ADDRESS && RTA_PAYLOAD(rta) == sizeof(struct in6_addr))
        {
            memcpy(&addr, RTA_DATA(rta), sizeof(addr));
            have_addr = true;
            break;
        }
        rta = RTA_NEXT(rta, len);
    }

    if (!have_addr)
    {
        return;
    }

    /* extract the network prefix by masking host bits */
    struct in6_addr new_prefix = addr;
    int new_prefix_len = (int)ifa->ifa_prefixlen;
    ipv6_pd_mask_prefix(&new_prefix, new_prefix_len);

    if (nlh->nlmsg_type == RTM_NEWADDR)
    {
        if (mon->prefix_valid
            && memcmp(&mon->prefix, &new_prefix, sizeof(new_prefix)) == 0
            && mon->prefix_len == new_prefix_len)
        {
            /* prefix unchanged, nothing to do */
            msg(D_IFCONFIG_POOL, "IPv6-PD %s: prefix unchanged %s/%d on %s",
                source, ipv6_pd_fmt_addr(&new_prefix), new_prefix_len,
                mon->iface);
            return;
        }

        if (mon->prefix_valid)
        {
            msg(M_INFO, "IPv6-PD %s: prefix changed on %s: "
                "%s/%d -> %s/%d",
                source, mon->iface,
                ipv6_pd_fmt_addr(&mon->prefix), mon->prefix_len,
                ipv6_pd_fmt_addr(&new_prefix), new_prefix_len);
        }
        else
        {
            msg(M_INFO, "IPv6-PD %s: acquired prefix %s/%d on %s",
                source, ipv6_pd_fmt_addr(&new_prefix), new_prefix_len,
                mon->iface);
        }

        mon->prefix = new_prefix;
        mon->prefix_len = new_prefix_len;
        mon->prefix_valid = true;
    }
    else if (nlh->nlmsg_type == RTM_DELADDR)
    {
        if (mon->prefix_valid
            && memcmp(&mon->prefix, &new_prefix, sizeof(new_prefix)) == 0)
        {
            msg(M_INFO, "IPv6-PD %s: prefix %s/%d lost on %s (address removed)",
                source, ipv6_pd_fmt_addr(&mon->prefix), mon->prefix_len,
                mon->iface);
            mon->prefix_valid = false;
            memset(&mon->prefix, 0, sizeof(mon->prefix));
            mon->prefix_len = 0;
        }
    }
}

struct ipv6_pd_mon *
ipv6_pd_mon_init(const char *iface, int expected_prefix_len)
{
    struct ipv6_pd_mon *mon;
    struct sockaddr_nl local;
    int fd;
    int ifindex;
    int sndbuf = 2048;
    int rcvbuf = 4096;

    if (!iface || !iface[0])
    {
        msg(M_WARN, "IPv6-PD: no interface specified for prefix monitoring");
        return NULL;
    }

    ifindex = (int)if_nametoindex(iface);
    if (ifindex == 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD: cannot resolve interface '%s'", iface);
        return NULL;
    }

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD: cannot open netlink socket");
        return NULL;
    }

    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    set_cloexec(fd);
    set_nonblock(fd);

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_IPV6_IFADDR;

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD: cannot bind netlink socket");
        close(fd);
        return NULL;
    }

    ALLOC_OBJ_CLEAR(mon, struct ipv6_pd_mon);
    mon->nl_fd = fd;
    strncpy(mon->iface, iface, IFNAMSIZ - 1);
    mon->iface[IFNAMSIZ - 1] = '\0';
    mon->ifindex = ifindex;
    mon->expected_prefix_len = expected_prefix_len;
    mon->prefix_valid = false;

    msg(M_INFO, "IPv6-PD: monitoring interface %s (ifindex %d) for "
        "prefix changes (expected /%d)",
        mon->iface, mon->ifindex, mon->expected_prefix_len);

    return mon;
}

int
ipv6_pd_query_prefix(struct ipv6_pd_mon *mon)
{
    int fd;
    struct sockaddr_nl nladdr;
    struct
    {
        struct nlmsghdr n;
        struct ifaddrmsg i;
    } req;
    char buf[8192];
    struct iovec iov;
    struct msghdr nlmsg;
    bool found = false;

    if (!mon)
    {
        return -EINVAL;
    }

    msg(D_IFCONFIG_POOL, "IPv6-PD query: requesting IPv6 addresses on %s",
        mon->iface);

    /* open a separate socket for the dump request so we don't mix
     * dump replies with asynchronous events on the monitor socket */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD query: cannot open netlink socket");
        return -errno;
    }

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD query: cannot bind netlink socket");
        close(fd);
        return -errno;
    }

    /* build RTM_GETADDR dump request for AF_INET6 */
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_GETADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = (uint32_t)time(NULL);
    req.i.ifa_family = AF_INET6;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    iov.iov_base = &req;
    iov.iov_len = req.n.nlmsg_len;

    memset(&nlmsg, 0, sizeof(nlmsg));
    nlmsg.msg_name = &nladdr;
    nlmsg.msg_namelen = sizeof(nladdr);
    nlmsg.msg_iov = &iov;
    nlmsg.msg_iovlen = 1;

    if (sendmsg(fd, &nlmsg, 0) < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD query: sendmsg failed");
        close(fd);
        return -errno;
    }

    /* receive and process dump replies */
    while (1)
    {
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        ssize_t rcv_len = recvmsg(fd, &nlmsg, 0);
        if (rcv_len < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            msg(M_WARN | M_ERRNO, "IPv6-PD query: recvmsg failed");
            close(fd);
            return -errno;
        }
        if (rcv_len == 0)
        {
            break;
        }

        struct nlmsghdr *h = (struct nlmsghdr *)buf;

        while (NLMSG_OK(h, (size_t)rcv_len))
        {
            if (h->nlmsg_type == NLMSG_DONE)
            {
                goto done;
            }

            if (h->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *err = NLMSG_DATA(h);
                if (err->error)
                {
                    msg(M_WARN, "IPv6-PD query: netlink error: %s",
                        strerror(-err->error));
                }
                goto done;
            }

            if (h->nlmsg_type == RTM_NEWADDR)
            {
                ipv6_pd_handle_addr_msg(h, mon, "query");
                if (mon->prefix_valid)
                {
                    found = true;
                }
            }

            h = NLMSG_NEXT(h, rcv_len);
        }
    }

done:
    close(fd);

    if (!found && !mon->prefix_valid)
    {
        msg(M_INFO, "IPv6-PD query: no matching prefix found on %s "
            "(expected /%d, global scope)",
            mon->iface, mon->expected_prefix_len);
    }

    return 0;
}

int
ipv6_pd_process_event(struct ipv6_pd_mon *mon)
{
    char buf[4096];
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf),
    };
    struct sockaddr_nl nladdr;
    struct msghdr nlmsg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    if (!mon || mon->nl_fd < 0)
    {
        return -EINVAL;
    }

    ssize_t rcv_len = recvmsg(mon->nl_fd, &nlmsg, MSG_DONTWAIT);
    if (rcv_len < 0)
    {
        if (errno == EINTR || errno == EAGAIN)
        {
            return 0;
        }
        msg(M_WARN | M_ERRNO, "IPv6-PD event: recvmsg failed");
        return -errno;
    }
    if (rcv_len == 0)
    {
        return 0;
    }

    msg(D_IFCONFIG_POOL, "IPv6-PD event: received %zd bytes from netlink",
        rcv_len);

    struct nlmsghdr *h = (struct nlmsghdr *)buf;

    while (NLMSG_OK(h, (size_t)rcv_len))
    {
        if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
        {
            msg(D_IFCONFIG_POOL, "IPv6-PD event: received %s",
                h->nlmsg_type == RTM_NEWADDR ? "RTM_NEWADDR" : "RTM_DELADDR");
            ipv6_pd_handle_addr_msg(h, mon, "event");
        }

        h = NLMSG_NEXT(h, rcv_len);
    }

    return 0;
}

void
ipv6_pd_mon_close(struct ipv6_pd_mon *mon)
{
    if (!mon)
    {
        return;
    }

    if (mon->nl_fd >= 0)
    {
        close(mon->nl_fd);
        mon->nl_fd = -1;
    }

    msg(D_IFCONFIG_POOL, "IPv6-PD: monitor closed for %s", mon->iface);

    free(mon);
}

#endif /* TARGET_LINUX */
