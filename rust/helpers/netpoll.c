// SPDX-License-Identifier: GPL-2.0

/*
 * Rust helpers for netpoll.
 */

#include <linux/netpoll.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#ifdef CONFIG_NETPOLL

int rust_helper_netpoll_send_udp(struct netpoll *np, const char *msg, int len)
{
	return netpoll_send_udp(np, msg, len);
}

int rust_helper_netpoll_setup(struct netpoll *np)
{
	return netpoll_setup(np);
}

void rust_helper_netpoll_cleanup(struct netpoll *np)
{
	netpoll_cleanup(np);
}

void rust_helper_do_netpoll_cleanup(struct netpoll *np)
{
	do_netpoll_cleanup(np);
}

void rust_helper_skb_queue_head_init(struct sk_buff_head *list)
{
	skb_queue_head_init(list);
}

bool rust_helper_netif_running(const struct net_device *dev)
{
	return netif_running(dev);
}

void rust_helper_eth_broadcast_addr(u8 *addr)
{
	eth_broadcast_addr(addr);
}

#endif /* CONFIG_NETPOLL */
