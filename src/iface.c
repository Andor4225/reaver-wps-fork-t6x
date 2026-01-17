/*
 * Reaver - Wireless interface functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "iface.h"
#include "globule.h"
#include <net/if.h>
#include <netinet/in.h>
#ifdef LIBNL3
#include <net/ethernet.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#else
#include "lwe/iwlib.h"
#endif
#include <sys/ioctl.h>
#include <stdlib.h>

#if defined(__FreeBSD__) || defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if_dl.h>
int read_iface_mac() {
	struct ifaddrs* iflist;
	int found = 0;
	if (getifaddrs(&iflist) == 0) {
		struct ifaddrs* cur;
		for (cur = iflist; cur; cur = cur->ifa_next) {
			if ((cur->ifa_addr->sa_family == AF_LINK) &&
				(strcmp(cur->ifa_name, get_iface()) == 0) &&
				cur->ifa_addr) {
				struct sockaddr_dl* sdl = (struct sockaddr_dl*)cur->ifa_addr;
				set_mac(LLADDR(sdl));
				found = 1;
				break;
			}
		}
		freeifaddrs(iflist);
	}
	return found;
}
#else
/* Populates globule->mac with the MAC address of the interface globule->iface */
int read_iface_mac()
{
	struct ifreq ifr;
	struct ether_addr *eth = NULL;
	int sock = 0, ret_val = 0;

	/* Need a socket for the ioctl call */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(sock != -1)
	{
		eth = malloc(sizeof(struct ether_addr));
		if(eth)
		{
			memset(eth, 0, sizeof(struct ether_addr));

			/* Prepare request */
			memset(&ifr, 0, sizeof(struct ifreq));
			strncpy(ifr.ifr_name, get_iface(), IFNAMSIZ);

			/* Do it */
			if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
			{
				set_mac((unsigned char *) &ifr.ifr_hwaddr.sa_data);
				ret_val = 1;
			}

			free(eth);
		}

		close(sock);
	}

	return ret_val;
}
#endif

/*
 * IEEE 802.11 Channel to Frequency conversion
 * Supports 2.4GHz, 5GHz, and 6GHz bands per IEEE 802.11-2020
 */
int ieee80211_channel_to_frequency(int channel, int band)
{
	/* 2.4 GHz band (802.11b/g/n) */
	if (band == BG_BAND || (channel >= 1 && channel <= 14)) {
		if (channel >= 1 && channel <= 13)
			return 2407 + channel * 5;
		if (channel == 14)
			return 2484;
	}

	/* 5 GHz band (802.11a/n/ac/ax) */
	if (band == AN_BAND || (channel >= 32 && channel <= 196)) {
		if (channel >= 32 && channel <= 68)
			return 5000 + channel * 5;  /* UNII-1 and UNII-2A */
		if (channel >= 96 && channel <= 144)
			return 5000 + channel * 5;  /* UNII-2C (DFS) */
		if (channel >= 149 && channel <= 177)
			return 5000 + channel * 5;  /* UNII-3 */
		/* Japan 4.9 GHz band */
		if (channel >= 183 && channel <= 196)
			return 4000 + channel * 5;
	}

	/* 6 GHz band (802.11ax WiFi 6E) - channels 1-233 */
	if (band == AX_BAND || (channel >= 1 && channel <= 233 && band & AX_BAND)) {
		return 5950 + channel * 5;
	}

	/* Fallback for unknown channels */
	return (channel + 1000) * 5;
}

/*
 * IEEE 802.11 Frequency to Channel conversion
 * Supports 2.4GHz, 5GHz, and 6GHz bands
 */
int ieee80211_frequency_to_channel(int freq)
{
	/* 2.4 GHz band */
	if (freq >= 2412 && freq <= 2472)
		return (freq - 2407) / 5;
	if (freq == 2484)
		return 14;

	/* 5 GHz band */
	if (freq >= 5170 && freq <= 5825)
		return (freq - 5000) / 5;

	/* 4.9 GHz band (Japan) */
	if (freq >= 4915 && freq <= 4980)
		return (freq - 4000) / 5;

	/* 6 GHz band (WiFi 6E) */
	if (freq >= 5955 && freq <= 7115)
		return (freq - 5950) / 5;

	/* 60 GHz band (802.11ad/ay) */
	if (freq >= 58320 && freq <= 70200)
		return (freq - 56160) / 2160;

	return 0;
}

/*
 * Goes to the next 802.11 channel.
 * This is mostly required for APs that hop channels, which usually hop between channels 1, 6, and 11.
 * We just hop channels until we successfully associate with the AP.
 * The AP's actual channel number is parsed and set by parse_beacon_tags() in 80211.c.
 */
int next_channel()
{
/* 2.4 GHz channels (802.11b/g/n) */
#define BG_CHANNELS	14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13

/* 5 GHz channels (802.11a/n/ac/ax) - Updated for modern standards */
/* UNII-1: 36-48, UNII-2A: 52-64, UNII-2C (DFS): 100-144, UNII-3: 149-165, UNII-4: 169-177 */
#define AN_CHANNELS	36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177

        static int i;
        static const short bg_channels[] = {BG_CHANNELS};
	static const short an_channels[] = {AN_CHANNELS};
	static const short bgan_channels[] = {BG_CHANNELS, AN_CHANNELS};
	static const int band_chan_count[] = {
		[BG_BAND] = sizeof(bg_channels)/sizeof(bg_channels[0]),
		[AN_BAND] = sizeof(an_channels)/sizeof(an_channels[0]),
		[BG_BAND|AN_BAND] = sizeof(bgan_channels)/sizeof(bgan_channels[0]),
	};
	static const short* band_select[] = {
		[BG_BAND] = bg_channels,
		[AN_BAND] = an_channels,
		[BG_BAND|AN_BAND] = bgan_channels,
	};

	int band = get_wifi_band();
	const short *channels = band_select[band];
	int n = band_chan_count[band];

	/* Only switch channels if fixed channel operation is disabled */
	if(!get_fixed_channel())
	{
		i++;
		if((i >= n) || i < 0) i = 0;
		return change_channel(channels[i]);
	}

	return 0;
}

/* Sets the 802.11 channel for the selected interface */
#ifdef __APPLE__
int change_channel(int channel)
{
	cprintf(VERBOSE, "[+] Switching %s to channel %d\n", get_iface(), channel);
	// Unfortunately, there is no API to change the channel
	pid_t pid = fork();
	if (!pid) {
		char chan_arg[32];
		snprintf(chan_arg, sizeof(chan_arg), "-c%d", channel);
		char* argv[] = {"/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport", chan_arg, NULL};
		execve("/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport", argv, NULL);
	}
	int status;
	waitpid(pid,&status,0);
	set_channel(channel);
	return 0;
}
#else
#ifdef LIBNL3

int change_channel(int channel)
{
	int ret_val = 0;
	unsigned int freq;
	struct nl_sock *sckt = NULL;
	struct nl_msg *mesg = NULL;
	int nl80211_id;

	cprintf(VERBOSE, "[+] Switching %s to channel %d\n", get_iface(), channel);

	/* Convert channel to frequency using proper band detection */
	freq = ieee80211_channel_to_frequency(channel, get_wifi_band());

	/* Create the socket and connect to it */
	sckt = nl_socket_alloc();
	if (!sckt) {
		cprintf(CRITICAL, "[-] Failed to allocate netlink socket\n");
		return 0;
	}

	if (genl_connect(sckt) < 0) {
		cprintf(CRITICAL, "[-] Failed to connect to generic netlink\n");
		goto cleanup;
	}

	/* Resolve nl80211 interface */
	nl80211_id = genl_ctrl_resolve(sckt, "nl80211");
	if (nl80211_id < 0) {
		cprintf(CRITICAL, "[-] nl80211 interface not found (driver may not support nl80211)\n");
		goto cleanup;
	}

	/* Allocate a new message */
	mesg = nlmsg_alloc();
	if (!mesg) {
		cprintf(CRITICAL, "[-] Failed to allocate netlink message\n");
		goto cleanup;
	}

	/* Create the message to set channel/frequency */
	genlmsg_put(mesg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);

	/* Add interface index and frequency attributes */
	NLA_PUT_U32(mesg, NL80211_ATTR_IFINDEX, if_nametoindex(get_iface()));
	NLA_PUT_U32(mesg, NL80211_ATTR_WIPHY_FREQ, freq);

	/* Send the message */
	if (nl_send_auto_complete(sckt, mesg) < 0) {
		cprintf(VERBOSE, "[!] Failed to send channel change request (freq=%d MHz)\n", freq);
		goto nla_put_failure;
	}

	set_channel(channel);
	ret_val = 1;

nla_put_failure:
	if (mesg)
		nlmsg_free(mesg);

cleanup:
	if (sckt)
		nl_socket_free(sckt);

	return ret_val;
}
#else // !LIBNL3
int change_channel(int channel)
{
        int skfd = 0, ret_val = 0;
        struct iwreq wrq;

        memset((void *) &wrq, 0, sizeof(struct iwreq));

        /* Open NET socket */
        if((skfd = iw_sockets_open()) < 0)
        {
                perror("iw_sockets_open");
        }
        else if(get_iface())
        {
                /* Convert channel to a frequency */
                iw_float2freq((double) channel, &(wrq.u.freq));

                /* Fixed frequency */
                wrq.u.freq.flags = IW_FREQ_FIXED;

        	cprintf(VERBOSE, "[+] Switching %s to channel %d\n", get_iface(), channel);

                /* Set frequency */
                if(iw_set_ext(skfd, get_iface(), SIOCSIWFREQ, &wrq) >= 0)
                {
			set_channel(channel);
                        ret_val = 1;
                }

                iw_sockets_close(skfd);
        }

        return ret_val;
}
#endif // LIBNL3
#endif
