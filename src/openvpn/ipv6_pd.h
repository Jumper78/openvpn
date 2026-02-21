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

#ifndef IPV6_PD_H
#define IPV6_PD_H

#ifdef TARGET_LINUX

#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>

struct ipv6_pd_mon
{
    int              nl_fd;
    char             iface[IFNAMSIZ];
    int              ifindex;
    int              expected_prefix_len;
    bool             prefix_valid;
    struct in6_addr  prefix;
    int              prefix_len;
};

struct ipv6_pd_mon *ipv6_pd_mon_init(const char *iface, int expected_prefix_len);

int ipv6_pd_query_prefix(struct ipv6_pd_mon *mon);

int ipv6_pd_process_event(struct ipv6_pd_mon *mon);

void ipv6_pd_mon_close(struct ipv6_pd_mon *mon);

static inline int
ipv6_pd_get_fd(const struct ipv6_pd_mon *mon)
{
    return mon ? mon->nl_fd : -1;
}

#endif /* TARGET_LINUX */
#endif /* IPV6_PD_H */
