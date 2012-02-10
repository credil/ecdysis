/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Copyright (C) 2010 Viagenie Inc. http://www.viagenie.ca
 *
 * Authors:
 *      Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca>
 *      Simon Perreault <simon.perreault@viagenie.ca>
 *      Marc Blanchet <marc.blanchet@viagenie.ca>
 *
 * NAT64 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NAT64 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with NAT64.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _NF_NAT64_SESSION_H
#define _NF_NAT64_SESSION_H

#include <linux/time.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <linux/rbtree.h>

struct nat64_binding {
        struct rb_node           b_entry_by_ipv4;
        struct rb_node           b_entry_by_ipv6;
        unsigned int             b_sessions;
        struct in6_addr          b_saddr6;  /*  X' */
        struct in_addr           b_saddr4;  /*  T  */
        uint16_t                 b_sport6;  /*  x  */
        uint16_t                 b_sport4;  /*  t  */
        uint8_t                  b_proto;
};


struct nat64_session {
        struct rb_node           s_entry_by_ipv6;
        struct rb_node           s_entry_by_ipv4;
        struct rb_node           s_entry_by_expiry;
        struct timespec          s_expiry;
        struct nat64_binding    *s_binding;
        struct in_addr           s_daddr;   /* Y',Z */
        uint16_t                 s_dport;   /* y,z  */
        uint8_t                  s_state;
};

const struct timespec * nat64_next_expiry(void);
void nat64_expire(void);

struct nat64_session *
nat64_ipv6_udp_session(struct ipv6hdr *ip6, struct udphdr *uh, int recur);

struct nat64_session *
nat64_ipv4_udp_session(struct iphdr *ip4, struct udphdr *uh, int recur);

struct nat64_session *
nat64_ipv6_tcp_session(struct ipv6hdr *ip6, struct tcphdr *th, int recur);

struct nat64_session *
nat64_ipv4_tcp_session(struct iphdr *ip4, struct tcphdr *th, int recur);

struct nat64_session *
nat64_ipv6_icmp_session(struct ipv6hdr *ip6, struct icmp6hdr *icmp6, int recur);

struct nat64_session *
nat64_ipv4_icmp_session(struct iphdr *ip4, struct icmphdr *icmp4, int recur);

#endif

