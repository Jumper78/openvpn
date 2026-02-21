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
#include "socket_util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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
 * Process a single RTM_NEWADDR / RTM_DELADDR netlink message.
 * Updates monitor state and logs prefix changes.
 */
static void
ipv6_pd_handle_addr_msg(const struct nlmsghdr *nlh, struct ipv6_pd_mon *mon,
                         const char *source)
{
    const struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    const struct rtattr *rta;
    int len;
    struct gc_arena gc = gc_new();
    struct in6_addr addr;

    if (ifa->ifa_family != AF_INET6
        || (int)ifa->ifa_index != mon->ifindex
        || ifa->ifa_scope != RT_SCOPE_UNIVERSE)
    {
        goto out;
    }

    if (mon->expected_prefix_len > 0
        && (int)ifa->ifa_prefixlen != mon->expected_prefix_len)
    {
        goto out;
    }

    rta = (const struct rtattr *)((const char *)ifa + NLMSG_ALIGN(sizeof(*ifa)));
    len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

    while (RTA_OK(rta, len))
    {
        if (rta->rta_type == IFA_ADDRESS
            && RTA_PAYLOAD(rta) == sizeof(struct in6_addr))
        {
            memcpy(&addr, RTA_DATA(rta), sizeof(addr));
            goto found;
        }
        rta = RTA_NEXT(rta, len);
    }
    goto out;

found:;
    struct in6_addr new_prefix = addr;
    int plen = (int)ifa->ifa_prefixlen;
    ipv6_pd_mask_prefix(&new_prefix, plen);

    if (nlh->nlmsg_type == RTM_NEWADDR)
    {
        if (mon->prefix_valid
            && mon->prefix_len == plen
            && memcmp(&mon->prefix, &new_prefix, sizeof(new_prefix)) == 0)
        {
            msg(D_IFCONFIG_POOL, "IPv6-PD %s: prefix unchanged %s/%d on %s",
                source, print_in6_addr(new_prefix, 0, &gc),
                plen, mon->iface);
            goto out;
        }

        if (mon->prefix_valid)
        {
            msg(M_INFO, "IPv6-PD %s: prefix changed on %s: %s/%d -> %s/%d",
                source, mon->iface,
                print_in6_addr(mon->prefix, 0, &gc), mon->prefix_len,
                print_in6_addr(new_prefix, 0, &gc), plen);
        }
        else
        {
            msg(M_INFO, "IPv6-PD %s: acquired prefix %s/%d on %s",
                source, print_in6_addr(new_prefix, 0, &gc),
                plen, mon->iface);
        }

        mon->prefix = new_prefix;
        mon->prefix_len = plen;
        mon->prefix_valid = true;
    }
    else if (nlh->nlmsg_type == RTM_DELADDR)
    {
        if (mon->prefix_valid
            && memcmp(&mon->prefix, &new_prefix, sizeof(new_prefix)) == 0)
        {
            msg(M_INFO, "IPv6-PD %s: prefix %s/%d lost on %s",
                source, print_in6_addr(mon->prefix, 0, &gc),
                mon->prefix_len, mon->iface);
            mon->prefix_valid = false;
            CLEAR(mon->prefix);
            mon->prefix_len = 0;
        }
    }

out:
    gc_free(&gc);
}

/**
 * Read and process all pending netlink messages from a socket.
 * Works for both the initial dump (blocking) and async events (non-blocking).
 */
static int
ipv6_pd_recv_messages(int fd, struct ipv6_pd_mon *mon, const char *source,
                       int flags)
{
    char buf[4096];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct sockaddr_nl nladdr;
    struct msghdr nlmsg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    while (1)
    {
        iov.iov_len = sizeof(buf);
        ssize_t rcv_len = recvmsg(fd, &nlmsg, flags);
        if (rcv_len < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (errno == EAGAIN)
            {
                return 0;
            }
            msg(M_WARN | M_ERRNO, "IPv6-PD %s: recvmsg failed", source);
            return -errno;
        }
        if (rcv_len == 0)
        {
            return 0;
        }

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        while (NLMSG_OK(h, (size_t)rcv_len))
        {
            if (h->nlmsg_type == NLMSG_DONE)
            {
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *err = NLMSG_DATA(h);
                if (err->error)
                {
                    msg(M_WARN, "IPv6-PD %s: netlink error: %s",
                        source, strerror(-err->error));
                }
                return err->error;
            }
            if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
            {
                ipv6_pd_handle_addr_msg(h, mon, source);
            }
            h = NLMSG_NEXT(h, rcv_len);
        }
    }
}

struct ipv6_pd_mon *
ipv6_pd_mon_init(const char *iface, int expected_prefix_len)
{
    struct ipv6_pd_mon *mon;
    struct sockaddr_nl local = { .nl_family = AF_NETLINK,
                                 .nl_groups = RTMGRP_IPV6_IFADDR };
    int fd, ifindex;

    if (!iface || !iface[0])
    {
        msg(M_WARN, "IPv6-PD: no interface specified");
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
    set_cloexec(fd);
    set_nonblock(fd);

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD: cannot bind netlink socket");
        close(fd);
        return NULL;
    }

    ALLOC_OBJ_CLEAR(mon, struct ipv6_pd_mon);
    mon->nl_fd = fd;
    strncpy(mon->iface, iface, IFNAMSIZ - 1);
    mon->ifindex = ifindex;
    mon->expected_prefix_len = expected_prefix_len;

    msg(M_INFO, "IPv6-PD: monitoring %s for prefix changes (expected /%d)",
        mon->iface, mon->expected_prefix_len);

    return mon;
}

int
ipv6_pd_query_prefix(struct ipv6_pd_mon *mon)
{
    struct
    {
        struct nlmsghdr n;
        struct ifaddrmsg i;
    } req;
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = &req, .iov_len = 0 };
    struct msghdr nlmsg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    int fd, ret;

    if (!mon)
    {
        return -EINVAL;
    }

    /* Use a separate socket so dump replies don't mix with async events */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD query: cannot open netlink socket");
        return -errno;
    }
    if (bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD query: cannot bind netlink socket");
        close(fd);
        return -errno;
    }

    CLEAR(req);
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_GETADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = (uint32_t)time(NULL);
    req.i.ifa_family = AF_INET6;
    iov.iov_len = req.n.nlmsg_len;

    if (sendmsg(fd, &nlmsg, 0) < 0)
    {
        msg(M_WARN | M_ERRNO, "IPv6-PD query: sendmsg failed");
        close(fd);
        return -errno;
    }

    ret = ipv6_pd_recv_messages(fd, mon, "query", 0);
    close(fd);

    if (!mon->prefix_valid)
    {
        msg(M_INFO, "IPv6-PD query: no matching prefix on %s (expected /%d)",
            mon->iface, mon->expected_prefix_len);
    }

    return ret;
}

int
ipv6_pd_process_event(struct ipv6_pd_mon *mon)
{
    if (!mon || mon->nl_fd < 0)
    {
        return -EINVAL;
    }
    return ipv6_pd_recv_messages(mon->nl_fd, mon, "event", MSG_DONTWAIT);
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
    }
    msg(D_IFCONFIG_POOL, "IPv6-PD: monitor closed for %s", mon->iface);
    free(mon);
}

#endif /* TARGET_LINUX */
