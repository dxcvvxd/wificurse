/*
    wificurse - WiFi Jamming tool
    Copyright (C) 2012  oblique

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include "error.h"
#include "iw.h"


/* --- minimal libnl-compatible macros (kernel headers don't ship libnl) --- */

#define GENLMSG_DATA(nlh)	((void *)((char *)(nlh) + NLMSG_HDRLEN + GENL_HDRLEN))
#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#ifndef NLA_HDRLEN
#define NLA_HDRLEN		((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif
#define NLA_OK(nla, len)	((len) >= (int)sizeof(struct nlattr) && \
				 (nla)->nla_len >= sizeof(struct nlattr) && \
				 (nla)->nla_len <= (len))
#define NLA_NEXT(nla, len)	((len) -= NLA_ALIGN((nla)->nla_len), \
				 (struct nlattr *)((char *)(nla) + NLA_ALIGN((nla)->nla_len)))


/* --- nl80211 raw netlink helpers (no libnl dependency) --- */

static void nla_put(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct nlattr *nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));

	nla->nla_type = type;
	nla->nla_len = (uint16_t)(NLA_HDRLEN + len);
	if (len > 0)
		memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = (uint32_t)(NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla->nla_len));
}

static void nla_put_u32(struct nlmsghdr *nlh, int type, uint32_t v)
{
	nla_put(nlh, type, &v, sizeof(v));
}

static void nla_put_str(struct nlmsghdr *nlh, int type, const char *s)
{
	nla_put(nlh, type, s, strlen(s) + 1);
}

static int nla_parse(struct nlattr **tb, int maxtype, void *data, int len)
{
	struct nlattr *nla;
	int rem = len;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));
	for (nla = (struct nlattr *)data; NLA_OK(nla, rem); nla = NLA_NEXT(nla, rem)) {
		if (nla->nla_type <= maxtype)
			tb[nla->nla_type] = nla;
	}
	return 0;
}

/* send a generic netlink command and wait for ack/response
 * returns: 0 on success, negative errno on failure
 * if reply_attr >= 0 and resp != NULL, stores pointer to first attr payload
 */
static int nl_send_cmd(struct iw_dev *dev, uint8_t cmd, uint16_t flags,
		       void (*fill)(struct nlmsghdr *nlh, void *arg), void *arg,
		       int reply_attr, void **resp, int *resp_len)
{
	struct sockaddr_nl snl;
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr gnlh;
		char buf[1024];
	} msg;
	char rbuf[8192];
	struct nlmsghdr *nlh;
	struct nlattr *tb[64];
	int len;

	memset(&msg, 0, sizeof(msg));
	msg.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.nlh.nlmsg_type = dev->nlk_family;
	msg.nlh.nlmsg_flags = flags | NLM_F_REQUEST | NLM_F_ACK;
	msg.nlh.nlmsg_seq = 1;
	msg.gnlh.cmd = cmd;

	if (fill)
		fill(&msg.nlh, arg);

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	if (sendto(dev->nlk_fd, &msg, msg.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&snl, sizeof(snl)) < 0)
		return -errno;

	for (;;) {
		len = recv(dev->nlk_fd, rbuf, sizeof(rbuf), 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		for (nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_seq != 1)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
				return err->error; /* 0 == success */
			}
			if (reply_attr >= 0) {
				nla_parse(tb, 63, (char *)GENLMSG_DATA(nlh), nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
				if (tb[reply_attr]) {
					*resp = (char *)tb[reply_attr] + NLA_HDRLEN;
					*resp_len = tb[reply_attr]->nla_len - NLA_HDRLEN;
					return 0;
				}
			}
		}
	}
}

/* resolve the "nl80211" generic netlink family id */
static int nl80211_family_id(struct iw_dev *dev)
{
	struct sockaddr_nl snl;
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr gnlh;
		char buf[64];
	} msg;
	char rbuf[4096];
	struct nlmsghdr *nlh;
	struct nlattr *tb[32];
	int len;

	memset(&msg, 0, sizeof(msg));
	msg.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.nlh.nlmsg_type = GENL_ID_CTRL;
	msg.nlh.nlmsg_flags = NLM_F_REQUEST;
	msg.nlh.nlmsg_seq = 2;
	msg.gnlh.cmd = CTRL_CMD_GETFAMILY;
	nla_put_str(&msg.nlh, CTRL_ATTR_FAMILY_NAME, "nl80211");

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	if (sendto(dev->nlk_fd, &msg, msg.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&snl, sizeof(snl)) < 0)
		return -errno;

	for (;;) {
		len = recv(dev->nlk_fd, rbuf, sizeof(rbuf), 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		for (nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_seq != 2)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
				return err->error;
			}
			nla_parse(tb, 31, (char *)GENLMSG_DATA(nlh), nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
			if (tb[CTRL_ATTR_FAMILY_ID])
				return *(uint16_t *)((char *)tb[CTRL_ATTR_FAMILY_ID] + NLA_HDRLEN);
		}
	}
}

static int nl80211_open(struct iw_dev *dev)
{
	struct sockaddr_nl snl;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0)
		return -errno;

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&snl, sizeof(snl)) < 0) {
		close(fd);
		return -errno;
	}
	dev->nlk_fd = fd;

	dev->nlk_family = nl80211_family_id(dev);
	if (dev->nlk_family <= 0) {
		close(fd);
		dev->nlk_fd = -1;
		return dev->nlk_family < 0 ? dev->nlk_family : -EOPNOTSUPP;
	}
	return 0;
}

/* channel <-> frequency (2.4GHz, channels 1-14) */
static int chan_to_freq(int chan)
{
	if (chan >= 1 && chan <= 13)
		return 2412 + (chan - 1) * 5;
	if (chan == 14)
		return 2484;
	return -1;
}

static void set_ifindex_cb(struct nlmsghdr *nlh, void *arg)
{
	nla_put_u32(nlh, NL80211_ATTR_IFINDEX, *(int *)arg);
}

static void set_ifindex_iftype_cb(struct nlmsghdr *nlh, void *arg)
{
	int *i = arg;
	nla_put_u32(nlh, NL80211_ATTR_IFINDEX, i[0]);
	nla_put_u32(nlh, NL80211_ATTR_IFTYPE, i[1]);
}

static void set_ifindex_freq_cb(struct nlmsghdr *nlh, void *arg)
{
	struct iw_dev *dev = arg;
	int freq = chan_to_freq(dev->chan);
	nla_put_u32(nlh, NL80211_ATTR_IFINDEX, dev->ifindex);
	nla_put_u32(nlh, NL80211_ATTR_WIPHY_FREQ, freq);
}


void iw_init_dev(struct iw_dev *dev) {
	memset(dev, 0, sizeof(*dev));
	dev->fd_in = -1;
	dev->fd_out = -1;
	dev->nlk_fd = -1;
	dev->old_iftype = -1;
}

/* man 7 netdevice
 * man 7 packet
 */
int iw_open(struct iw_dev *dev) {
	struct ifreq ifr, ifidx;
	struct sockaddr_ll sll;
	struct packet_mreq mreq;
	void *resp = NULL;
	int rlen = 0, ret;
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return_error("socket");
	dev->fd_in = fd;

	dev->fd_out = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (dev->fd_out < 0)
		return_error("socket");

	/* save current interface flags */
	memset(&dev->old_flags, 0, sizeof(dev->old_flags));
	strncpy(dev->old_flags.ifr_name, dev->ifname, sizeof(dev->old_flags.ifr_name)-1);
	if (ioctl(fd, SIOCGIFFLAGS, &dev->old_flags) < 0) {
		dev->old_flags.ifr_name[0] = '\0';
		return_error("ioctl(SIOCGIFFLAGS)");
	}

	/* get interface index */
	memset(&ifidx, 0, sizeof(ifidx));
	strncpy(ifidx.ifr_name, dev->ifname, sizeof(ifidx.ifr_name)-1);
	if (ioctl(fd, SIOCGIFINDEX, &ifidx) < 0)
		return_error("ioctl(SIOCGIFINDEX)");
	dev->ifindex = ifidx.ifr_ifindex;

	/* save current interface mode via nl80211 */
	if (nl80211_open(dev) < 0)
		return_error("nl80211: open");

	ret = nl_send_cmd(dev, NL80211_CMD_GET_INTERFACE, 0,
			  set_ifindex_cb, &dev->ifindex,
			  NL80211_ATTR_IFTYPE, &resp, &rlen);
	if (ret < 0) {
		errno = -ret;
		return_error("nl80211: GET_INTERFACE");
	}
	if (resp && rlen >= 4)
		dev->old_iftype = *(int *)resp;

	/* set interface down (ifr_flags = 0) */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* set monitor mode via nl80211 */
	{
		int arg[2] = { dev->ifindex, NL80211_IFTYPE_MONITOR };
		ret = nl_send_cmd(dev, NL80211_CMD_SET_INTERFACE, 0,
				  set_ifindex_iftype_cb, arg, -1, NULL, NULL);
		if (ret < 0) {
			if (ret == -EOPNOTSUPP)
				fputs("hint: monitor not supported - this Android driver needs "
				      "con_mode=4 (ip link set down; echo 4 > "
				      "/sys/module/wlan/parameters/con_mode; ip link set up)\n",
				      stderr);
			errno = -ret;
			return_error("nl80211: SET_INTERFACE(monitor)");
		}
	}

	/* set interface up, broadcast and running */
	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* bind interface to fd_in socket */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = dev->ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(dev->fd_in, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	/* bind interface to fd_out socket */
	if (bind(dev->fd_out, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	shutdown(dev->fd_in, SHUT_WR);
	shutdown(dev->fd_out, SHUT_RD);

	/* set fd_in in promiscuous mode */
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = dev->ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(dev->fd_in, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		return_error("setsockopt(PACKET_MR_PROMISC)");

	return 0;
}

void iw_close(struct iw_dev *dev) {
	struct ifreq ifr;

	if (dev->fd_in == -1)
		return;

	if (dev->fd_out == -1) {
		close(dev->fd_in);
		return;
	}

	if (dev->old_flags.ifr_name[0] != '\0') {
		/* set interface down (ifr_flags = 0) */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
		ioctl(dev->fd_in, SIOCSIFFLAGS, &ifr);
		/* restore old mode (best effort) */
		if (dev->old_iftype >= 0 && dev->nlk_fd >= 0) {
			int arg[2] = { dev->ifindex, dev->old_iftype };
			nl_send_cmd(dev, NL80211_CMD_SET_INTERFACE, 0,
				    set_ifindex_iftype_cb, arg, -1, NULL, NULL);
		}
		/* restore old flags */
		ioctl(dev->fd_in, SIOCSIFFLAGS, &dev->old_flags);
	}

	close(dev->fd_in);
	close(dev->fd_out);
	if (dev->nlk_fd >= 0)
		close(dev->nlk_fd);
}

ssize_t iw_write(struct iw_dev *dev, void *buf, size_t count) {
	unsigned char *pbuf, *pkt;
	struct radiotap_hdr *rt_hdr;
	struct write_radiotap_data *w_rt_data;
	ssize_t r;

	pbuf = malloc(sizeof(*rt_hdr) + sizeof(*w_rt_data) + count);
	if (pbuf == NULL)
		return_error("malloc");

	rt_hdr = (struct radiotap_hdr*)pbuf;
	w_rt_data = (struct write_radiotap_data*)(pbuf + sizeof(*rt_hdr));
	pkt = pbuf + sizeof(*rt_hdr) + sizeof(*w_rt_data);

	/* radiotap header */
	memset(rt_hdr, 0, sizeof(*rt_hdr));
	rt_hdr->len = sizeof(*rt_hdr) + sizeof(*w_rt_data);
	rt_hdr->present = RADIOTAP_F_PRESENT_RATE | RADIOTAP_F_PRESENT_TX_FLAGS;
	/* radiotap fields */
	memset(w_rt_data, 0, sizeof(*w_rt_data));
	w_rt_data->rate = 2; /* 1 Mb/s */
	w_rt_data->tx_flags = RADIOTAP_F_TX_FLAGS_NOACK | RADIOTAP_F_TX_FLAGS_NOSEQ;
	/* packet */
	memcpy(pkt, buf, count);

	r = send(dev->fd_out, pbuf, rt_hdr->len + count, 0);
	if (r < 0) {
		free(pbuf);
		return_error("send");
	} else if (r > 0) {
		r -= rt_hdr->len;
		if (r <= 0)
			r = 0;
	}

	free(pbuf);

	return r;
}

ssize_t iw_read(struct iw_dev *dev, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz) {
	struct radiotap_hdr *rt_hdr;
	int r;

	*pkt = NULL;
	*pkt_sz = 0;

	/* read packet */
	r = recv(dev->fd_in, buf, count, 0);
	if (r < 0)
		return_error("recv");
	else if (r == 0)
		return 0;

	rt_hdr = buf;
	if (sizeof(*rt_hdr) >= r || rt_hdr->len >= r)
		return ERRNODATA;

	*pkt = buf + rt_hdr->len;
	*pkt_sz = r - rt_hdr->len;

	return r;
}

int iw_set_channel(struct iw_dev *dev, int chan) {
	int ret;

	if (chan_to_freq(chan) < 0)
		return_error("invalid channel %d", chan);

	dev->chan = chan;
	ret = nl_send_cmd(dev, NL80211_CMD_SET_CHANNEL, 0,
			  set_ifindex_freq_cb, dev, -1, NULL, NULL);
	if (ret < 0) {
		if (ret == -EBUSY)
			fputs("hint: channel is busy - disable wifi (svc wifi disable), "
			      "then set con_mode=4 with the interface down, "
			      "bringing it up before running wificurse\n", stderr);
		errno = -ret;
		return_error("nl80211: SET_CHANNEL");
	}

	return 0;
}
