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

#ifndef _NF_NAT64_CONFIG_H
#define _NF_NAT64_CONFIG_H

#include <linux/in.h>
#include <linux/in6.h>

void nat64_config_set_prefix(struct in6_addr prefix, int prefix_len);
void nat64_config_set_nat_addr(struct in_addr);

int nat64_config_prefix_len(void);
struct in6_addr * nat64_config_prefix(void);
struct in_addr * nat64_config_nat_addr(void);

struct in_addr nat64_extract(const struct in6_addr *a6);
void nat64_embed(struct in_addr a4, struct in6_addr *a6);

#endif

