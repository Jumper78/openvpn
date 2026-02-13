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

/**
 * IPv6 Prefix Delegation monitor.
 *
 * Monitors a network interface for IPv6 global-scope addresses via netlink
 * and extracts the delegated prefix.  The netlink socket receives
 * asynchronous RTM_NEWADDR / RTM_DELADDR events so that prefix changes
 * (e.g. from DHCPv6-PD lease renewals) are detected immediately.
 */
struct ipv6_pd_mon
{
    int              nl_fd;               /**< Netlink socket fd for monitoring */
    char             iface[IFNAMSIZ];     /**< Interface to watch */
    int              ifindex;             /**< Cached interface index */
    int              expected_prefix_len; /**< Expected prefix length (e.g. 48, 56) */
    bool             prefix_valid;        /**< Do we have a valid prefix? */
    struct in6_addr  prefix;              /**< Current delegated prefix (network part) */
    int              prefix_len;          /**< Actual prefix length of current prefix */
};

/**
 * Initialise the IPv6 PD monitor.
 *
 * Opens a NETLINK_ROUTE socket subscribed to RTMGRP_IPV6_IFADDR and
 * resolves the interface index.
 *
 * @param iface              Interface name to monitor (e.g. "eth0")
 * @param expected_prefix_len  Expected delegated prefix length (e.g. 56)
 * @return allocated monitor, or NULL on error
 */
struct ipv6_pd_mon *ipv6_pd_mon_init(const char *iface, int expected_prefix_len);

/**
 * Perform a one-shot query of all current IPv6 addresses on the monitored
 * interface and extract the delegated prefix.
 *
 * @param mon  the PD monitor
 * @return 0 on success, negative on error
 */
int ipv6_pd_query_prefix(struct ipv6_pd_mon *mon);

/**
 * Process pending netlink events on the monitor socket.
 *
 * Call this when the netlink fd becomes readable.  Parses
 * RTM_NEWADDR / RTM_DELADDR messages and updates the stored prefix.
 *
 * @param mon  the PD monitor
 * @return 0 on success, negative on error
 */
int ipv6_pd_process_event(struct ipv6_pd_mon *mon);

/**
 * Return the netlink fd for integration into an event loop.
 */
static inline int
ipv6_pd_get_fd(const struct ipv6_pd_mon *mon)
{
    return mon ? mon->nl_fd : -1;
}

/**
 * Close the monitor and free all resources.
 */
void ipv6_pd_mon_close(struct ipv6_pd_mon *mon);

#endif /* TARGET_LINUX */
#endif /* IPV6_PD_H */
