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

#include <linux/bug.h>

#include "nf_nat64_config.h"
#include "nf_nat64_session.h"

#ifndef CMP
#define CMP(a,b)        ((a) < (b) ? -1 : (a) > (b) ? 1 : 0)
#endif

#define malloc(a) kmalloc(a, GFP_ATOMIC)
#define free(a) kfree(a)

enum {
	nat64_session_state_tcp_closed          = 0,
	nat64_session_state_tcp_v4_syn_rcv      = 1,
	nat64_session_state_tcp_v6_syn_rcv      = 2,
	nat64_session_state_tcp_established     = 3,
	nat64_session_state_tcp_v4_fin_rcv      = 4,
	nat64_session_state_tcp_v6_fin_rcv      = 5,
	nat64_session_state_tcp_v6_v4_fin_rcv   = 6,
	nat64_session_state_tcp_rst_rcv         = 7,
};


static int
nat64_binding_cmp_transport_ipv4(const struct nat64_binding *b1,
		                 const struct nat64_binding *b2)
{
	int			 c;

	if ((c = CMP(b1->b_proto,         b2->b_proto))
	 || (c = CMP(b1->b_saddr4.s_addr, b2->b_saddr4.s_addr))
	 || (c = CMP(b1->b_sport4,        b2->b_sport4)))
		return c;

	return 0;
}

static int
nat64_binding_cmp_transport_ipv6(const struct nat64_binding *b1,
		                 const struct nat64_binding *b2)
{
	int			 c;

	if ((c =    CMP( b1->b_proto,   b2->b_proto))
	 || (c = memcmp(&b1->b_saddr6, &b2->b_saddr6, sizeof(b1->b_saddr6)))
	 || (c =    CMP( b1->b_sport6,  b2->b_sport6)))
		return c;

	return 0;
}

static int
nat64_binding_cmp_ipv6(const struct nat64_binding *b1,
		       const struct nat64_binding *b2)
{
	int			 c;

	if ((c = nat64_binding_cmp_transport_ipv6(b1, b2))
	 || (c = nat64_binding_cmp_transport_ipv4(b1, b2)))
		return c;

	return 0;
}

static int
nat64_binding_cmp_ipv4(const struct nat64_binding *b1,
		       const struct nat64_binding *b2)
{
	int			 c;

	if ((c = nat64_binding_cmp_transport_ipv4(b1, b2))
	 || (c = nat64_binding_cmp_transport_ipv6(b1, b2)))
		return c;

	return 0;
}

static int
nat64_session_cmp_ipv6(const struct nat64_session *s1,
		       const struct nat64_session *s2)
{
	int			 c;

	if ((c = nat64_binding_cmp_transport_ipv6(s1->s_binding, s2->s_binding))
	 || (c = CMP(s1->s_daddr.s_addr, s2->s_daddr.s_addr))
	 || (c = CMP(s1->s_dport, s2->s_dport)))
		return c;

	return 0;
}

static int
nat64_session_cmp_ipv4(const struct nat64_session *s1,
		       const struct nat64_session *s2)
{
	int			 c;

	if ((c = nat64_binding_cmp_transport_ipv4(s1->s_binding, s2->s_binding))
	 || (c = CMP(s1->s_daddr.s_addr, s2->s_daddr.s_addr))
	 || (c = CMP(s1->s_dport, s2->s_dport)))
		return c;

	return 0;
}

static int
nat64_session_cmp_expiry(const struct nat64_session *s1,
		         const struct nat64_session *s2)
{
	int			 c;

	if ((c = CMP(s1->s_expiry.tv_sec,  s2->s_expiry.tv_sec ))
	 || (c = CMP(s1->s_expiry.tv_nsec, s2->s_expiry.tv_nsec))
	 || (c = nat64_session_cmp_ipv4(s1, s2)))
		return c;

	return 0;
}

struct rb_root nat64_bindings_by_ipv6 = RB_ROOT;
struct rb_root nat64_bindings_by_ipv4 = RB_ROOT;
struct rb_root nat64_sessions_by_ipv6 = RB_ROOT;
struct rb_root nat64_sessions_by_ipv4 = RB_ROOT;
struct rb_root nat64_sessions_by_expiry = RB_ROOT;


#define RB_GENERATE_ACCESSORS(name, type, root, field, cmp)		\
RB_GENERATE_FIND(name##_find, type, root, field, cmp)			\
RB_GENERATE_INSERT(name##_insert, type, root, field, cmp)		\
RB_GENERATE_REMOVE(name##_remove, type, root, field, cmp)

#define RB_GENERATE_FIND(name, type, root, field, cmp)			\
static struct type *							\
name(struct type *k)							\
{									\
	struct rb_node *node = root.rb_node;				\
									\
        while (node) {							\
		struct type *b = container_of(node, struct type, field);\
		int result;						\
                result = (cmp)(k, b);					\
                if (result < 0)						\
                        node = node->rb_left;				\
                else if (result > 0)					\
                        node = node->rb_right;				\
                else {							\
                        return b;					\
		}							\
        }								\
        return NULL;							\
}					

#define RB_GENERATE_INSERT(name, type, root, field, cmp)		\
struct type * name(struct type *data)					\
{									\
	struct rb_node **new = &(root.rb_node), *parent = NULL;		\
									\
	/* Figure out where to put new node */				\
	while (*new) {							\
		struct type *this = container_of(*new, struct type, field);\
		int result = (cmp)(data, this);				\
									\
		parent = *new;						\
		if (result < 0)						\
			new = &((*new)->rb_left);			\
		else if (result > 0)					\
			new = &((*new)->rb_right);			\
		else							\
			return this;					\
	}								\
									\
	/* Add new node and rebalance tree. */				\
	rb_link_node(&data->field, parent, new);			\
	rb_insert_color(&data->field, &root);				\
									\
	return NULL;							\
}									

#define RB_GENERATE_REMOVE(name, type, root, field, cmp)		\
static void name(struct type *data)					\
{									\
	if (data) {							\
		rb_erase(&data->field, &root);				\
	}								\
}

#define RB_GENERATE_MIN(name, type, root, field)			\
static struct type *							\
name(void)								\
{									\
	struct rb_node *node = root.rb_node;				\
									\
	if(!node || !node->rb_left)					\
		return NULL;						\
									\
        do {								\
		node = node->rb_left;					\
        } while(node->rb_left);						\
	return container_of(node, struct type, field);			\
}

RB_GENERATE_ACCESSORS(nat64_binding_by_ipv6, nat64_binding,
			nat64_bindings_by_ipv6, b_entry_by_ipv6,
			nat64_binding_cmp_ipv6)

RB_GENERATE_ACCESSORS(nat64_binding_by_ipv4, nat64_binding,
			nat64_bindings_by_ipv4, b_entry_by_ipv4,
			nat64_binding_cmp_ipv4)

RB_GENERATE_ACCESSORS(nat64_session_by_ipv6, nat64_session, 
		  nat64_sessions_by_ipv6, s_entry_by_ipv6, 
		  nat64_session_cmp_ipv6)

RB_GENERATE_ACCESSORS(nat64_session_by_ipv4, nat64_session, 
		  nat64_sessions_by_ipv4, s_entry_by_ipv4, 
		  nat64_session_cmp_ipv4)

RB_GENERATE_INSERT(nat64_session_by_expiry_insert, nat64_session,
		nat64_sessions_by_expiry, s_entry_by_expiry,
		nat64_session_cmp_expiry)
RB_GENERATE_REMOVE(nat64_session_by_expiry_remove, nat64_session,
		nat64_sessions_by_expiry, s_entry_by_expiry,
		nat64_session_cmp_expiry)
RB_GENERATE_MIN(nat64_session_by_expiry_min, nat64_session, 
		nat64_sessions_by_expiry, s_entry_by_expiry)

static void
nat64_binding_delete(struct nat64_binding *b)
{
	nat64_binding_by_ipv6_remove(b);
	nat64_binding_by_ipv4_remove(b);

	free(b);
}

static void
nat64_binding_ref(struct nat64_binding *b)
{
	++b->b_sessions;
}

static void
nat64_binding_deref(struct nat64_binding *b)
{
	/* TODO support manually configured BIB entries */

	if (--b->b_sessions == 0)
		nat64_binding_delete(b);
}

static void
nat64_session_delete(struct nat64_session *s)
{
	nat64_session_by_ipv6_remove(s);
	nat64_session_by_ipv4_remove(s);
	nat64_session_by_expiry_remove(s);
	nat64_binding_deref(s->s_binding);
	free(s);
}

static void
nat64_session_set_expiry(struct nat64_session *s, struct timespec tv)
{
	if (s->s_expiry.tv_sec || s->s_expiry.tv_nsec)
		nat64_session_by_expiry_remove(s);

	s->s_expiry = tv;

	s = nat64_session_by_expiry_insert(s);
	WARN_ON_ONCE(s);
}

/*
 * Returns the earliest time at which a session will expire. If there are no
 * sessions, returns NULL.
 */
const struct timespec *
nat64_next_expiry(void)
{
	struct nat64_session	*s;

	s = nat64_session_by_expiry_min();

	return s ? &s->s_expiry : NULL;
}

/*
 * Remove all sessions/bindings that are expired.
 */
void
nat64_expire(void)
{
	struct timespec		 now;
	struct nat64_session	*s;

	getnstimeofday(&now);

	while ((s = nat64_session_by_expiry_min())) {
		if (s->s_expiry.tv_sec > now.tv_sec ||
				s->s_expiry.tv_nsec > now.tv_nsec)
			return;

		nat64_session_delete(s);
	}
	
}

static struct nat64_binding *
nat64_bib_insert(struct nat64_binding *b)
{
	struct nat64_binding	*old;

	if ((old = nat64_binding_by_ipv4_insert(b)))
		return old;

	old = nat64_binding_by_ipv6_insert(b);
	WARN_ON_ONCE(old);

	return old;
}

static struct nat64_session *
nat64_session_table_insert(struct nat64_session *s)
{
	struct nat64_session	*old;

	if ((old = nat64_session_by_ipv6_insert(s)))
		return old;

	old = nat64_session_by_ipv4_insert(s);
	WARN_ON_ONCE(old);

	return old;
}

static int
nat64_binding_alloc_port(struct nat64_binding *b, int from, int to)
{
	int sport;

	for (sport = from; sport < to; sport += 2) {
		b->b_sport4 = sport;
		if (!nat64_bib_insert(b))
			return 1;
	}

	return 0;
}


/**
 * Allocate a new binding. Try using the same port as on the IPv6 side.
 * If it's already in use, allocate one randomly. The binding is inserted into
 * the Binding Information Base (BIB).
 *
 * \param bkey	Initializer for the created binding.
 *
 * \return	A pointer to the created binding if successful, NULL otherwise.
 */
static struct nat64_binding *
nat64_binding_create(const struct nat64_binding *bkey)
{
	struct nat64_binding	*b;
	int			 min;
	int			 max;
	int			 first;

	b = malloc(sizeof(*b));
	if(!b) {
		if(printk_ratelimit())
			printk(KERN_DEBUG "nat64_binding_create: kmalloc failed");
		return NULL;
	}

	*b = *bkey;
	b->b_saddr4 = *(nat64_config_nat_addr());  
	b->b_sport4 = b->b_sport6;

	if (!nat64_bib_insert(b))
		return b;

	min = b->b_sport6 < 1024 ? 0 : 1024;
	max = b->b_sport6 < 1024 ? 1024 : 65536;

 	first = min + ((random32() % ((max - min) / 2) * 2) | (b->b_sport6 & 1));

	if (nat64_binding_alloc_port(b, first, max) ||
			nat64_binding_alloc_port(b, min, first))
		return b;

	kfree(b);
	return NULL;
}

/**
 * Create a new session. The binding must already be in the BIB.
 *
 * \param skey	Initializer for new session.
 *
 * \return	The created session.
 */
static struct nat64_session *
nat64_session_create(const struct nat64_session *skey)
{
	struct nat64_session	*s;

	s = malloc(sizeof(*s));
	*s = *skey;

	nat64_binding_ref(s->s_binding);

	if (nat64_session_table_insert(s)) {
		nat64_binding_deref(s->s_binding);
		free(s);
		return NULL;
	}

	return s;
}

static void
nat64_session_refresh(struct nat64_session *s, int seconds)
{
	struct timespec tv;

	getnstimeofday(&tv);
	tv.tv_sec += seconds;

	nat64_session_set_expiry(s, tv);
}

struct nat64_session *
nat64_ipv6_udp_session(struct ipv6hdr *ip6, struct udphdr *uh, int recur)
{
	struct nat64_binding	 bkey;
	struct nat64_session	 skey;
	struct nat64_session	*s;

	memset(&bkey, 0, sizeof(bkey));
	memset(&skey, 0, sizeof(skey));

	skey.s_binding = &bkey;

	bkey.b_proto  = IPPROTO_UDP;
	bkey.b_saddr6 = recur % 2 ? ip6->daddr : ip6->saddr;
	bkey.b_sport6 = recur % 2 ? uh->dest : uh->source;
	skey.s_daddr = nat64_extract(recur % 2 ? &ip6->saddr : &ip6->daddr);
	skey.s_dport = recur % 2 ? uh->source : uh->dest;

	s = nat64_session_by_ipv6_find(&skey);

	if (recur)
		return s;

	if (!s) {
		if (!(skey.s_binding = nat64_binding_by_ipv6_find(&bkey))
				&& !(skey.s_binding =
					nat64_binding_create(&bkey)))
			return NULL;

		if (!(s = nat64_session_create(&skey)))
			return NULL;
	}

	nat64_session_refresh(s, 5*60);

	return s;
}

struct nat64_session *
nat64_ipv4_udp_session(struct iphdr *ip4, struct udphdr *uh, int recur)
{
	struct nat64_binding	 bkey;
	struct nat64_session	 skey;
	struct nat64_session	*s;

	memset(&bkey, 0, sizeof(bkey));
	memset(&skey, 0, sizeof(skey));

	skey.s_binding = &bkey;

	bkey.b_proto  = IPPROTO_UDP;
	bkey.b_saddr4.s_addr = recur % 2 ? ip4->saddr : ip4->daddr;
	bkey.b_sport4 = recur % 2 ? uh->source : uh->dest;
	skey.s_daddr.s_addr  = recur % 2 ? ip4->daddr : ip4->saddr;
	skey.s_dport  = recur % 2 ? uh->dest : uh->source;

	/* TODO implement filtering */

	s = nat64_session_by_ipv4_find(&skey);

	if (recur)
		return s;

	if (!s) {
		if (!(skey.s_binding = nat64_binding_by_ipv4_find(&bkey)))
			/* TODO send ICMP unreachable */
			return NULL;

		if (!(s = nat64_session_create(&skey)))
			return NULL;
	}

	nat64_session_refresh(s, 5*60);

	return s;
}

struct nat64_session *
nat64_ipv6_tcp_session(struct ipv6hdr *ip6, struct tcphdr *th, int recur)
{
	struct nat64_binding	 bkey;
	struct nat64_session	 skey;
	struct nat64_session	*s;

	memset(&bkey, 0, sizeof(bkey));
	memset(&skey, 0, sizeof(skey));

	skey.s_binding = &bkey;

	bkey.b_proto  = IPPROTO_TCP;
	bkey.b_saddr6 = recur % 2 ? ip6->daddr : ip6->saddr;
	bkey.b_sport6 = recur % 2 ? th->dest : th->source;
	skey.s_daddr = nat64_extract(recur % 2 ? &ip6->saddr : &ip6->daddr);
	skey.s_dport = recur % 2 ? th->source : th->dest;

	s = nat64_session_by_ipv6_find(&skey);

	if (recur)
		return s;

	if (!s) {
		if (!th->syn)
			return NULL;

		skey.s_state = nat64_session_state_tcp_v6_syn_rcv;
		if (!(skey.s_binding = nat64_binding_by_ipv6_find(&bkey))
				&& !(skey.s_binding =
					nat64_binding_create(&bkey)))
			return NULL;

		if (!(s = nat64_session_create(&skey)))
			return NULL;

		nat64_session_refresh(s, 4*60);

		return s;
	}

	switch (s->s_state) {

	case nat64_session_state_tcp_v6_syn_rcv:
		return s;

	case nat64_session_state_tcp_v4_syn_rcv:
		if (!th->syn)
			return s;

		s->s_state = nat64_session_state_tcp_established;
		nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	case nat64_session_state_tcp_established:
		if (th->rst) {
			s->s_state = nat64_session_state_tcp_rst_rcv;
			nat64_session_refresh(s, 4*60);
		} else {
			if (th->fin)
				s->s_state = nat64_session_state_tcp_v6_fin_rcv;
			nat64_session_refresh(s, 2*60*60 + 4*60);
		}
		return s;

	case nat64_session_state_tcp_v4_fin_rcv:
		if (th->fin) {
			s->s_state = nat64_session_state_tcp_v6_v4_fin_rcv;
			nat64_session_refresh(s, 4*60);
		} else
			nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	case nat64_session_state_tcp_v6_fin_rcv:
		nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	case nat64_session_state_tcp_v6_v4_fin_rcv:
		return s;

	case nat64_session_state_tcp_rst_rcv:
		s->s_state = nat64_session_state_tcp_established;
		nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	default:
		WARN_ON_ONCE(1);
	}

	return NULL;  /* DROP */
}

struct nat64_session *
nat64_ipv4_tcp_session(struct iphdr *ip4, struct tcphdr *th, int recur)
{
	struct nat64_binding	 bkey;
	struct nat64_session	 skey;
	struct nat64_session	*s;

	memset(&bkey, 0, sizeof(bkey));
	memset(&skey, 0, sizeof(skey));

	skey.s_binding = &bkey;

	bkey.b_proto  = IPPROTO_TCP;
	bkey.b_saddr4.s_addr = recur % 2 ? ip4->saddr : ip4->daddr;
	bkey.b_sport4 = recur % 2 ? th->source : th->dest;
	skey.s_daddr.s_addr  = recur % 2 ? ip4->daddr : ip4->saddr;
	skey.s_dport  = recur % 2 ? th->dest : th->source;

	s = nat64_session_by_ipv4_find(&skey);

	if (recur)
		return s;

	if (!s) {
		if (!th->syn)
			return NULL;

		skey.s_state = nat64_session_state_tcp_v4_syn_rcv;
		if (!(skey.s_binding = nat64_binding_by_ipv4_find(&bkey)))
			/* TODO send ICMP unreachable */
			return NULL;

		if (!(s = nat64_session_create(&skey)))
			return NULL;

		nat64_session_refresh(s, 6);

		return NULL;
	}

	switch (s->s_state) {

	case nat64_session_state_tcp_v4_syn_rcv:
		return s;

	case nat64_session_state_tcp_v6_syn_rcv:
		if (!th->syn)
			return s;

		s->s_state = nat64_session_state_tcp_established;
		nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	case nat64_session_state_tcp_established:
		if (th->rst) {
			s->s_state = nat64_session_state_tcp_rst_rcv;
			nat64_session_refresh(s, 4*60);
		} else {
			if (th->fin)
				s->s_state = nat64_session_state_tcp_v4_fin_rcv;
			nat64_session_refresh(s, 2*60*60 + 4*60);
		}
		return s;

	case nat64_session_state_tcp_v4_fin_rcv:
		nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	case nat64_session_state_tcp_v6_fin_rcv:
		if (th->fin) {
			s->s_state = nat64_session_state_tcp_v6_v4_fin_rcv;
			nat64_session_refresh(s, 4*60);
		} else
			nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	case nat64_session_state_tcp_v6_v4_fin_rcv:
		return s;

	case nat64_session_state_tcp_rst_rcv:
		s->s_state = nat64_session_state_tcp_established;
		nat64_session_refresh(s, 2*60*60 + 4*60);
		return s;

	default:
		WARN_ON_ONCE(1);
	}

	return NULL;  /* DROP */
}


struct nat64_session *
nat64_ipv6_icmp_session(struct ipv6hdr *ip6, struct icmp6hdr *icmp6, int recur)
{
        struct nat64_binding     bkey;
        struct nat64_session     skey;
        struct nat64_session    *s;

        memset(&bkey, 0, sizeof(bkey));
        memset(&skey, 0, sizeof(skey));

        skey.s_binding = &bkey;

        bkey.b_proto  = IPPROTO_ICMP;  /* not IPPROTO_ICMPV6 */
        bkey.b_saddr6 = recur % 2 ? ip6->daddr : ip6->saddr;
        bkey.b_sport6 = icmp6->icmp6_identifier;
        skey.s_daddr = nat64_extract(recur % 2 ? &ip6->saddr : &ip6->daddr);
        skey.s_dport = icmp6->icmp6_identifier;

	s = nat64_session_by_ipv6_find(&skey);

        if (recur)
                return s;

        if (!s) {
                if (!(skey.s_binding = nat64_binding_by_ipv6_find(&bkey))
                                && !(skey.s_binding =
                                        nat64_binding_create(&bkey)))
                        return NULL;

                skey.s_dport = skey.s_binding->b_sport4;

                if (!(s = nat64_session_create(&skey)))
                        return NULL;
        }

        nat64_session_refresh(s, 60);

        /* TODO configurable session lifetime */

        return s;
}

struct nat64_session *
nat64_ipv4_icmp_session(struct iphdr *ip4, struct icmphdr *icmp4, int recur)
{
	struct nat64_binding	 bkey;
	struct nat64_session	 skey;
	struct nat64_session	*s;

	memset(&bkey, 0, sizeof(bkey));
	memset(&skey, 0, sizeof(skey));

	skey.s_binding = &bkey;

	bkey.b_proto  = IPPROTO_ICMP;
	bkey.b_saddr4.s_addr = recur % 2 ? ip4->saddr : ip4->daddr;
	bkey.b_sport4 = icmp4->un.echo.id;
	skey.s_daddr.s_addr  = recur % 2 ? ip4->daddr : ip4->saddr;
	skey.s_dport  = icmp4->un.echo.id;

	s = nat64_session_by_ipv4_find(&skey);

	if (recur)
		return s;

	if (!s) {
		if (!(skey.s_binding = nat64_binding_by_ipv4_find(&bkey)))
			/* TODO send ICMP unreachable */
			return NULL;

		if (!(s = nat64_session_create(&skey)))
			return NULL;
	}

	nat64_session_refresh(s, 5*60);

	return s;
}
