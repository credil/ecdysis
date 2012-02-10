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

#include <linux/module.h>	/* Needed by all modules */
#include <linux/moduleparam.h>  /* Needed for module_param */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */

#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/if_arp.h>

#include <net/ip.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>

#include "nf_nat64_config.h"
#include "nf_nat64_session.h"

#define NAT64_NETDEV_NAME "nat64"
#define NAT64_VERSION "0.1"

/* XXX Missing defines in kernel headers */
#define ICMP_MINLEN 8
#define ICMP_ROUTERADVERT       9   
#define ICMP_ROUTERSOLICIT      10 
#define ICMP_INFOTYPE(type) \
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
	 (type) == ICMP_ROUTERADVERT || (type) == ICMP_ROUTERSOLICIT || \
	 (type) == ICMP_TIMESTAMP || (type) == ICMP_TIMESTAMPREPLY || \
	 (type) == ICMP_INFO_REQUEST || (type) == ICMP_INFO_REPLY || \
	 (type) == ICMP_ADDRESS || (type) == ICMP_ADDRESSREPLY)

/* TODO Set this parameter through netlink */
static int nat64_prefix_len = 96;
static char *nat64_prefix_addr = "0064:FF9B::";
static char *nat64_ipv4_addr = NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jean-Philippe Dionne <jpdionne@viagenie.ca>");
MODULE_DESCRIPTION("nf_nat64");

module_param(nat64_prefix_addr, charp, 0000);
MODULE_PARM_DESC(nat64_prefix_addr, "nat64 prefix (default: 0064:FF9B::)");
module_param(nat64_prefix_len, int, 0000);
MODULE_PARM_DESC(nat64_prefix_len, "nat64 prefix len (default: 96)");
module_param(nat64_ipv4_addr, charp, 0000);
MODULE_PARM_DESC(nat64_ipv4_addr, "nat64 ipv4 address (must be set manually)");

struct nat64_struct
{
        struct net_device *dev;
};

struct net_device *nat64_dev;
/**
 * \return	The payload length of the translated packet.
 */
static int
nat64_input_ipv6_recur(int recur, struct ipv6hdr *ip6, int len,
		struct nat64_session **s)
{
	struct ipv6_opt_hdr     *ip6e;
	struct udphdr		*uh;
	struct tcphdr		*th;
	struct icmp6hdr		*icmp6;
	uint16_t		 hlen;
	uint8_t			 proto;

	hlen  = sizeof(*ip6);
	proto = ip6->nexthdr;

next_header:
	switch (proto) {

	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
		ip6e = (struct ipv6_opt_hdr*)((char *)ip6 + hlen);

		if ((len -= sizeof(*ip6e)) < 0)
			return 0;

		proto = ip6e->nexthdr;
		hlen += ip6e->hdrlen * 8;

		goto next_header;

	case IPPROTO_FRAGMENT:
		/* The kernel should be handling fragments for us. DROP. */
		WARN_ON_ONCE(1);
		return 0;

	case IPPROTO_UDP:
		uh = (struct udphdr *)((char *)ip6 + hlen);

		if ((len -= sizeof(*uh)) < 0 ||
				!(*s = nat64_ipv6_udp_session(ip6, uh, recur)))
			return 0;

		return len + sizeof(*uh);

	case IPPROTO_TCP:
		th = (struct tcphdr *)((char *)ip6 + hlen);

		if ((len -= sizeof(*th)) < 0 ||
				!(*s = nat64_ipv6_tcp_session(ip6, th, recur)))
			return 0;

		return len + sizeof(*th);

	case IPPROTO_ICMPV6:
		icmp6 = (struct icmp6hdr *)((char *)ip6 + hlen);

		if ((len -= sizeof(*icmp6)) < 0)
			return 0;

		if (icmp6->icmp6_type & ICMPV6_INFOMSG_MASK) {
			if (!(*s = nat64_ipv6_icmp_session(ip6, icmp6, recur)))
				return 0;
			return len + 8;
		} else {
			int size = nat64_input_ipv6_recur(recur + 1,
					(struct ipv6hdr *)(icmp6 + 1), len, s);
			return size ? size + sizeof(struct iphdr) + 8 : 0;
		}

	default:
		/* Ignore other protocols. */
		return 0;
	}

	/* Should never get here. */
	WARN_ON_ONCE(1);
	return 0;
}

static struct sk_buff*
nat64_alloc_skb(int tlen, int paylen)
{
        struct sk_buff *skb;
        skb = alloc_skb(LL_MAX_HEADER + tlen + paylen, GFP_ATOMIC); 

        if (!skb) {
                return NULL;
        }

        skb_reserve(skb, LL_MAX_HEADER);
        skb_reset_mac_header(skb);
        skb_reset_network_header(skb);

        skb_set_transport_header(skb, tlen);

        skb_put(skb, tlen + paylen);

        return skb;
}

inline void *
ip_data(struct iphdr *ip4)
{
	return (char *)ip4 + ip4->ihl*4;
}


static void
checksum_adjust(uint16_t *sum, uint16_t old, uint16_t new, int udp)
{
        uint32_t s;

        if (udp && !*sum)
                return;

        s = *sum + old - new;
        *sum = (s & 0xffff) + (s >> 16);

        if (udp && !*sum)
                *sum = 0xffff;
}

static void
checksum_remove(uint16_t *sum, uint16_t *begin, uint16_t *end, int udp)
{
        while (begin < end)
                checksum_adjust(sum, *begin++, 0, udp);
}

static void
checksum_add(uint16_t *sum, uint16_t *begin, uint16_t *end, int udp)
{
        while (begin < end)
                checksum_adjust(sum, 0, *begin++, udp);
}


static void
adjust_checksum_ipv6_to_ipv4(uint16_t *sum, struct ipv6hdr *ip6, 
		struct iphdr *ip4, int udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);
}

static void
adjust_checksum_ipv4_to_ipv6(uint16_t *sum, struct iphdr *ip4, 
		struct ipv6hdr *ip6, int udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);
}


static void
checksum_change(uint16_t *sum, uint16_t *x, uint16_t new, int udp)
{
        checksum_adjust(sum, *x, new, udp);
        *x = new;
}

static struct iphdr *
nat64_xlate_ipv6_to_ipv4(struct ipv6hdr *ip6, struct iphdr *ip4, int plen,
		struct nat64_session *s, int recur)
{
	struct ipv6_opt_hdr *ip6e;
	struct udphdr *uh;
	struct tcphdr *th;
	struct icmphdr *ih;

	ip4->version = 4;
	ip4->ihl = 5;
	ip4->tos = ip6->priority; 
	ip4->tot_len = htons(sizeof(*ip4) + plen);
	ip4->id = 0;
	ip4->frag_off = htons(IP_DF);
	ip4->ttl = ip6->hop_limit;
	ip4->protocol = ip6->nexthdr;

	/* Skip extension headers. */
	ip6e = (struct ipv6_opt_hdr *)(ip6 + 1);
	while (ip4->protocol == 0 
		|| ip4->protocol == 43 
		|| ip4->protocol == 60) {
		ip4->protocol = ip6e->nexthdr;
		ip6e = (struct ipv6_opt_hdr *)((char *)ip6e + ip6e->hdrlen * 8);
	}

	if (recur % 2 == 0) {
		ip4->saddr = s->s_binding->b_saddr4.s_addr;
		*(struct in_addr*)&ip4->daddr = nat64_extract(&ip6->daddr);
	} else {
		*(struct in_addr*)&ip4->saddr = nat64_extract(&ip6->saddr);
		ip4->daddr = s->s_binding->b_saddr4.s_addr;
	}

	switch (ip4->protocol) {
	case IPPROTO_UDP:
		uh = ip_data(ip4);
		memcpy(uh, ip6e, plen);
		checksum_change(&uh->check, recur % 2 ? &uh->dest :
				&uh->source, s->s_binding->b_sport4, 1);
		adjust_checksum_ipv6_to_ipv4(&uh->check, ip6, ip4, 1);
		break;
	case IPPROTO_TCP:
		th = ip_data(ip4);
		memcpy(th, ip6e, plen);
		checksum_change(&th->check, recur % 2 ? &th->dest :
				&th->source, s->s_binding->b_sport4, 0);
		adjust_checksum_ipv6_to_ipv4(&th->check, ip6, ip4, 0);
		break;
	case IPPROTO_ICMPV6:
		ih = ip_data(ip4);
		memcpy(ih, ip6e, plen);
		if (ih->type & ICMPV6_INFOMSG_MASK) {
			switch (ih->type) {
			case ICMPV6_ECHO_REQUEST:
				ih->type = ICMP_ECHO;
				break;
			case ICMPV6_ECHO_REPLY:
				ih->type = ICMP_ECHOREPLY;
				break;
			default:
				return NULL;
			}
		} else {
			switch (ih->type) {
			case ICMPV6_DEST_UNREACH:
				ih->type = ICMP_DEST_UNREACH;
				switch (ih->code) {
				case ICMPV6_NOROUTE:
				case ICMPV6_NOT_NEIGHBOUR:
				case ICMPV6_ADDR_UNREACH:
					ih->code = ICMP_HOST_UNREACH;
					break;
				case ICMPV6_ADM_PROHIBITED:
					ih->code = ICMP_HOST_ANO;
					break;
				case ICMPV6_PORT_UNREACH:
					ih->code = ICMP_PORT_UNREACH;
					break;
				default:
					return NULL;
				}
				break;
			case ICMPV6_PKT_TOOBIG:
				ih->type = ICMP_DEST_UNREACH;
				ih->code = ICMP_FRAG_NEEDED;
				ih->un.frag.mtu -= 20;
				break;
			case ICMPV6_TIME_EXCEED:
				ih->type = ICMP_TIME_EXCEEDED;
				break;
			case ICMPV6_PARAMPROB:
				if (ih->code == ICMPV6_UNK_NEXTHDR)
				{
					ih->type = ICMP_DEST_UNREACH;
					ih->code = ICMP_PROT_UNREACH;
				} else {
					ih->type = ICMP_PARAMETERPROB;
					ih->code = 0;
				}
				/* TODO update pointer */
				break;
			default:
				return NULL;
			}
			nat64_xlate_ipv6_to_ipv4(
				(struct ipv6hdr *)((char *)ip6e + 8),
				(struct iphdr *)(ih + 1), 
				plen - ((char *)ip6e + 8 - (char *)ip6), s,
					recur + 1);
			
		}
		ih->checksum = 0;
		ih->checksum = ip_compute_csum(ih, plen);
		ip4->protocol = IPPROTO_ICMP;
		break;
	default:
		WARN_ON_ONCE(1);
	}

	/* Compute the ip header checksum */
	ip4->check = 0;
	ip4->check = ip_fast_csum(ip4, ip4->ihl);

	return ip4;
}

static void
nat64_output_ipv4(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	struct rtable *rt;

	skb->protocol = htons(ETH_P_IP);

	memset(&fl, 0, sizeof(fl));
	fl.fl4_dst = iph->daddr;
	fl.fl4_tos = RT_TOS(iph->tos);
	fl.proto = skb->protocol;
	if (ip_route_output_key(&init_net, &rt, &fl))
	{
		printk("nf_nat64: ip_route_output_key failed\n");
		return;
	}
	
	if (!rt)
	{
		printk("nf_nat64: rt null\n");
		return;
	}

	skb->dev = rt->u.dst.dev;
	skb_dst_set(skb, (struct dst_entry *)rt);
	if(ip_local_out(skb)) {
	       printk("nf_nat64: ip_local_out failed\n");
	       return;
	}

}

static void
nat64_output_ipv6(struct sk_buff *skb)
{
	skb->protocol = htons(ETH_P_IPV6);
	skb->dev = nat64_dev;
	nat64_dev->stats.tx_packets++;
	nat64_dev->stats.tx_bytes += skb->len;
	netif_rx(skb);
}

static unsigned int
nat64_input_ipv6(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *ip4;
	struct ipv6hdr *ip6;
	struct in6_addr *daddr;
	struct nat64_session *s;
	struct sk_buff *nskb;
	
	int len = skb->len;
	int plen;

	if ((len -= sizeof(*ip6)) < 0)
		return -1;

	ip6 = ipv6_hdr(skb);
	daddr = &ip6->daddr;

	/* Match only the nat64_prefix */
	if (memcmp(daddr, nat64_config_prefix(), nat64_config_prefix_len()/8)) {
		return -1;
	}
	
	/* Check for expired sessions */
	nat64_expire();

	/* Find the corresponding session. Create one if none exist. */
	if (!(plen = nat64_input_ipv6_recur(0, ip6, len, &s)))
		return -1;

	/* Allocate a new sk_buff */
	nskb = nat64_alloc_skb(sizeof(struct iphdr), plen);
	ip4 = ip_hdr(nskb);

	if(!nskb) {
		if(printk_ratelimit())
			printk(KERN_DEBUG "nat_nat64: can't alloc a new skb\n");
		return -1;
	}

	/* Translate the packet. */
	if (!nat64_xlate_ipv6_to_ipv4(ip6, ip4, plen, s, 0)) {
		kfree_skb(nskb);
		return -1;
	}


	nat64_output_ipv4(nskb);

	/* Free the incoming packet */
	kfree_skb(skb);
	return 0;
}

static int
nat64_input_ipv4_recur(int recur, struct iphdr *ip4, int len,
		struct nat64_session **s)
{
	struct udphdr           *uh;
	struct tcphdr           *th;
	struct icmphdr *icmp;
	uint16_t hlen;

	hlen = ip4->ihl * 4;

	switch (ip4->protocol) {

	case IPPROTO_UDP:
		uh = (struct udphdr *)((char *)ip4 + hlen);

		if ((len -= sizeof(*uh)) < 0 ||
				!(*s = nat64_ipv4_udp_session(ip4, uh, recur)))
			return 0;

		return len + sizeof(*uh);

	case IPPROTO_TCP:
		th = (struct tcphdr *)((char *)ip4 + hlen);

		if((len -= sizeof(*th)) < 0 ||
				!(*s = nat64_ipv4_tcp_session(ip4, th, recur)))
			return 0;

		return len + sizeof(*th);

	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)((char *)ip4 + hlen);

		if ((len -= ICMP_MINLEN) < 0)
			return 0;

		if (ICMP_INFOTYPE(icmp->type)) {
			if (!(*s = nat64_ipv4_icmp_session(ip4, icmp, recur)))
				return 0;
			return len + sizeof(struct icmp6hdr);
		} else {
			len = nat64_input_ipv4_recur(recur + 1,
					(struct iphdr*)(icmp + 1), 
					len - sizeof(*ip4), s);
			return len ? len + sizeof(struct ipv6hdr) +
				sizeof(struct icmp6hdr) : 0;
		}

	default:
		/* Ignore other protocols. */
		return 0;
	}

	/* Should never get here. */
	WARN_ON_ONCE(1);
	return 0;
}

static struct ipv6hdr *
nat64_xlate_ipv4_to_ipv6(struct iphdr *ip4, struct ipv6hdr *ip6, int plen,
		struct nat64_session *s, int recur)
{
	struct udphdr		*uh;
	struct tcphdr		*th;
	struct icmp6hdr *icmp6;

	ip6->version = 6;
	ip6->priority = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;
	
	ip6->payload_len = htons(plen);
	ip6->nexthdr  = ip4->protocol;
	ip6->hop_limit = ip4->ttl;

	if (recur % 2 == 0) {
		nat64_embed(*(struct in_addr *)&ip4->saddr, &ip6->saddr);
		ip6->daddr = s->s_binding->b_saddr6;
	} else {
		ip6->saddr = s->s_binding->b_saddr6;
		nat64_embed(*(struct in_addr *)&ip4->daddr, &ip6->daddr);
	}

	switch(ip6->nexthdr) {
	case IPPROTO_UDP:
		uh = (struct udphdr *)(ip6 + 1);
		memcpy(uh, ip_data(ip4), plen);
		checksum_change(&uh->check, recur % 2 ? &uh->source :
				&uh->dest, s->s_binding->b_sport6, 1);
		if(uh->check) {
			adjust_checksum_ipv4_to_ipv6(&uh->check, ip4, ip6, 1);
		} else {	
			uh->check = csum_ipv6_magic(
					&ip6->saddr, &ip6->daddr,
					plen, IPPROTO_UDP, 
					csum_partial(uh, plen, 0));
		}
		break;
	case IPPROTO_TCP:
		th = (struct tcphdr *)(ip6 + 1);
		memcpy(th, ip_data(ip4), plen);
		checksum_change(&th->check, recur % 2 ? &th->source :
				&th->dest, s->s_binding->b_sport6, 0);
		adjust_checksum_ipv4_to_ipv6(&th->check, ip4, ip6, 0);
		break;
	case IPPROTO_ICMP:
		icmp6 = (struct icmp6hdr *)(ip6 + 1);
		memcpy(icmp6, ip_data(ip4), plen);
		if (ICMP_INFOTYPE(icmp6->icmp6_type)) {
			switch (icmp6->icmp6_type) {
			case ICMP_ECHO:
				icmp6->icmp6_type = ICMPV6_ECHO_REQUEST;
				break;
			case ICMP_ECHOREPLY:
				icmp6->icmp6_type = ICMPV6_ECHO_REPLY;
				break;
			default:
				return NULL;
			}
		} else {
			switch (icmp6->icmp6_type) {
			case ICMP_DEST_UNREACH:
				icmp6->icmp6_type = ICMPV6_DEST_UNREACH;
				switch (icmp6->icmp6_code) {
				case ICMP_NET_UNREACH:
				case ICMP_HOST_UNREACH:
					icmp6->icmp6_code = ICMPV6_NOROUTE;
					break;
				case ICMP_PORT_UNREACH:
					icmp6->icmp6_code = ICMPV6_PORT_UNREACH;
					break;
				case ICMP_SR_FAILED:
				case ICMP_NET_UNKNOWN:
				case ICMP_HOST_UNKNOWN:
				case ICMP_HOST_ISOLATED:
				case ICMP_NET_UNR_TOS:
				case ICMP_HOST_UNR_TOS:
					icmp6->icmp6_code = ICMPV6_NOROUTE;
					break;
				case ICMP_NET_ANO:
				case ICMP_HOST_ANO:
					icmp6->icmp6_code =
						ICMPV6_ADM_PROHIBITED;
					break;
				case ICMP_PROT_UNREACH:
					icmp6->icmp6_type = ICMPV6_PARAMPROB;
					icmp6->icmp6_code =
						ICMPV6_UNK_NEXTHDR;
					icmp6->icmp6_pointer =
						(char *)&ip6->nexthdr -
						(char *)ip6;
					break;
				case ICMP_FRAG_NEEDED:
					icmp6->icmp6_type = ICMPV6_PKT_TOOBIG;
					icmp6->icmp6_code = 0;
					icmp6->icmp6_mtu += 20;
					/* TODO handle icmp_nextmtu == 0 */
					break;
				default:
					return NULL;
				}
				break;
			case ICMP_TIME_EXCEEDED:
				icmp6->icmp6_type = ICMPV6_TIME_EXCEED;
				break;
			case ICMP_PARAMETERPROB:
				icmp6->icmp6_type = ICMPV6_PARAMPROB;
				/* TODO update pointer */
				break;
			default:
				return NULL;
			}
			nat64_xlate_ipv4_to_ipv6(ip_data(ip4) + 8,
					(struct ipv6hdr *)(icmp6 + 1),
					plen - sizeof(*icmp6) - sizeof(*ip6), s,
					recur + 1);
		}
		icmp6->icmp6_cksum = 0;
		ip6->nexthdr = IPPROTO_ICMPV6;
		icmp6->icmp6_cksum = csum_ipv6_magic(&ip6->saddr, &ip6->daddr,
				plen, IPPROTO_ICMPV6,
				csum_partial(icmp6, plen, 0));
		break;
	default:
		WARN_ON_ONCE(1);
	}

	return ip6;
}

static unsigned int
nat64_input_ipv4(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct nat64_session *s;
	struct iphdr *ip4 = ip_hdr(skb);
	struct ipv6hdr *ip6;
	struct sk_buff *nskb;
	int len = skb->len;
	int plen;

	if ((len -= sizeof(*ip4)) < 0)
		return NF_ACCEPT;

	/* XXX What about fragments ? */

	/* Check for expired sessions */
	nat64_expire();

	/* Find the corresponding session. Create one if none exist. */
	if(!(plen = nat64_input_ipv4_recur(0, ip_hdr(skb), len, &s)))
		return NF_ACCEPT;

	/* Allocate a new sk_buff */
	nskb = nat64_alloc_skb(sizeof(struct ipv6hdr), plen);

	if(!nskb) {
		if(printk_ratelimit())
			printk(KERN_DEBUG "nat_nat64: can't alloc a new skb\n");
		return NF_DROP;
	}

	ip6 = ipv6_hdr(nskb);

	/* Translate the packet. */
	if (!nat64_xlate_ipv4_to_ipv6(ip4, ip6, plen, s, 0)) {
		kfree_skb(nskb);
		return NF_DROP;
	}

	nat64_output_ipv6(nskb);

	return NF_DROP;
}

static struct nf_hook_ops nf_nat64_ops[] __read_mostly = {
	{
		.hook           = nat64_input_ipv4,
		.owner          = THIS_MODULE,
		.pf             = NFPROTO_IPV4,
		.hooknum        = NF_INET_LOCAL_IN,
		.priority       = NF_IP_PRI_NAT_SRC,
	}
};

static int __init nat64_init_config(void)
{
	struct in_addr ipv4_addr;
	struct in6_addr prefix;

	int ret = 0;
	ret = in6_pton(nat64_prefix_addr, -1, 
			(u8*) &(prefix.in6_u.u6_addr8), 
			'\x0', NULL);
	if (!ret) {
		printk(KERN_INFO "nf_nat64: can't init prefix\n");
		return -EINVAL;
	}

	nat64_config_set_prefix(prefix, nat64_prefix_len);

	if(nat64_prefix_len % 8) {
		printk(KERN_INFO "nf_nat64: nat64_prefix_len must be a multiple of 8\n");
		return -EINVAL;
	}

	if(nat64_ipv4_addr == NULL) {
		printk(KERN_INFO "nf_nat64: module parameter \'nat64_ipv4_addr\' is undefined\n");
		return -EINVAL;
	}

	ret = in4_pton(nat64_ipv4_addr, -1, (u8*)&(ipv4_addr.s_addr), 
			'\x0', NULL);

	/* XXX with ip_route_output_key we can determine the right address */
	nat64_config_set_nat_addr(ipv4_addr);

	return 0;
}

static int
nat64_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
        cmd->supported          = 0;
        cmd->advertising        = 0;
        cmd->speed              = SPEED_10;
        cmd->duplex             = DUPLEX_FULL;
        cmd->port               = PORT_TP;
        cmd->phy_address        = 0;
        cmd->transceiver        = XCVR_INTERNAL;
        cmd->autoneg            = AUTONEG_DISABLE;
        cmd->maxtxpkt           = 0;
        cmd->maxrxpkt           = 0;
        return 0;
}

static void
nat64_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
        strcpy(info->driver, NAT64_NETDEV_NAME);
        strcpy(info->version, NAT64_VERSION);
        strcpy(info->fw_version, "N/A");

        strcpy(info->bus_info, "nat64");
}

static const struct ethtool_ops nat64_ethtool_ops = {
        .get_settings   = nat64_get_settings,
        .get_drvinfo    = nat64_get_drvinfo,
};

static int nat64_netdev_open(struct net_device *dev)
{
        netif_start_queue(dev);
        return 0;
}

static int nat64_netdev_close(struct net_device *dev)
{
        netif_stop_queue(dev);
        return 0;
}

static int
nat64_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
        struct ipv6hdr *ip6 = ipv6_hdr(skb);

        if(ip6->version != 6) {
		goto drop;
	}

	if(nat64_input_ipv6(skb, dev))
	{
		goto drop;
	}

	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;
        return NETDEV_TX_OK;

drop:
        dev->stats.rx_dropped++;
        kfree_skb(skb);
        return NETDEV_TX_OK;

}

static const struct net_device_ops nat64_netdev_ops = {
        .ndo_open               = nat64_netdev_open,
        .ndo_stop               = nat64_netdev_close,
        .ndo_start_xmit         = nat64_netdev_xmit,
};

static void nat64_free_netdev(struct net_device *dev)
{
}

static void nat64_netdev_setup(struct net_device *dev)
{
        dev->ethtool_ops = &nat64_ethtool_ops;
        dev->netdev_ops = &nat64_netdev_ops;

        dev->hard_header_len = 0;
        dev->addr_len = 0;
        dev->mtu = 1500;

        dev->type = ARPHRD_NONE;
        dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

        dev->destructor = nat64_free_netdev;
}

/* XXX ??? */
static int nat64_netdev_validate(struct nlattr *tb[], struct nlattr *data[])
{
	return -EINVAL;
}

static struct rtnl_link_ops nat64_link_ops __read_mostly = {
	.kind           = NAT64_NETDEV_NAME,
	.priv_size      = sizeof(struct nat64_struct),
	.setup          = nat64_netdev_setup,
	.validate       = nat64_netdev_validate,
};

int nat64_netdev_init(void)
{
        struct nat64_struct *nat64;
	struct net_device *dev;
	int err = 0;
	err = rtnl_link_register(&nat64_link_ops);
	if (err) {
		printk(KERN_ERR "nf_nat64: Can't register link_ops\n");
	}

	dev = alloc_netdev(sizeof(struct nat64_struct), NAT64_NETDEV_NAME,
			nat64_netdev_setup);
	if (!dev)
		return -ENOMEM;

        nat64 = netdev_priv(dev);
	nat64->dev = dev;
	nat64_dev = dev;

	dev_net_set(dev, &init_net);
	dev->rtnl_link_ops = &nat64_link_ops;

	return register_netdev(dev);
}

void nat64_netdev_uninit(void)
{
	rtnl_link_unregister(&nat64_link_ops);
}

static int __init nat64_init(void)
{
	int err = 0;

	err = nat64_init_config();
	if(err) {
		return err;
	} else {
		printk(KERN_INFO "nf_nat64: nat64_prefix=%pI6c/%d\n", 
			nat64_config_prefix(), nat64_config_prefix_len());
	}

	err = nat64_netdev_init();
	if(err) {
		return err;
	}

	//ret = nf_register_hooks(nf_nat64_ops, ARRAY_SIZE(nf_nat64_ops));
	err = nf_register_hook(nf_nat64_ops);
	if(err) {
		printk("nf_nat64: can't register hooks.\n");
	}
	return 0;
}

static void __exit nat64_fini(void)
{
	//nf_unregister_hooks(nf_nat64_ops, ARRAY_SIZE(nf_nat64_ops));
	nf_unregister_hook(nf_nat64_ops);
	nat64_netdev_uninit();
	printk(KERN_INFO "nf_nat64: module removed\n");
}

module_init(nat64_init);
module_exit(nat64_fini);


