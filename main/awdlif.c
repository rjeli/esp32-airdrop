#include <string.h>
#include <math.h>
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/snmp.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
// #include "netif/etharp.h"
#include "esp_wifi.h"
#include "esp_phy_init.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"

#include "freertos/FreeRTOS.h"

#include "macros.h"
#include "utils.h"
#include "khash.h"
#include "awdlif.h"

// tu = time unit
// aw = availability window
// awc = aw cycle

#define TU_PER_AW 16
#define AW_PER_AWC 64

#define TU_US 1024
#define AW_US (TU_US*TU_PER_AW)
#define AWC_US (AW_US*AW_PER_AWC)

// can be 10ms off (should be 5 but idk if possible)
#define MAX_SYNC_STDEV_US 10000

static int64_t wifi_init_ts = 0;

char *mac_bytes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

uint8_t airdrop_ble_data[] = {
	0x02, 0x01, 0x1b, 0x17,
    0xff, 0x4c, 0x00, 0x05,
    0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x00,
};

ESP_EVENT_DEFINE_BASE(AWDL_EVENT);

static int awdl_netif_idx = 0;
static esp_event_loop_handle_t loop;

KHASH_MAP_INIT_STR(dns_map, ip_addr_t);
static khash_t(dns_map) *dns_map;
static SemaphoreHandle_t dns_mtx;

static esp_timer_handle_t awdl_timer;

void 
awdl_timer_cb(void *arg)
{
	printf("timer cb\n");
}

err_t
awdl_dns_lookup(const char *name, ip_addr_t *addr, u8_t dns_addrtype)
{
	printf("performing dns lookup for %s\n", name);
	xSemaphoreTake(dns_mtx, portMAX_DELAY);
	khiter_t k = kh_get(dns_map, dns_map, name);
	if (k == kh_end(dns_map)) {
		printf("did not find dns entry for %s\n", name);
		char *dummyaddr = "fe80::1234:5678";
		ipaddr_aton(dummyaddr, addr);
	} else {
		*addr = kh_val(dns_map, k);
		printf("found entry\n");
	}
	xSemaphoreGive(dns_mtx);
	return ERR_OK;
}

enum AWDL_TAGS {
	AWDL_TAG_SRV_RESP 		= 0x02,
	AWDL_TAG_SYNC_PARAMS	= 0x04,
	AWDL_TAG_SRV_PARAMS 	= 0x06,
	AWDL_TAG_CH_SEQ 		= 0x12,
};

typedef struct {
	uint8_t tag;
	char *val;
} dns_entry_t ;

dns_entry_t DNS_ENTRIES[] = {
	{ 0x01, "_airplay._tcp.local" },
	{ 0x07, "_airdrop._tcp.local"},
	{ 0x0a, "_tcp.local"},
};

char *
lookup_dns_entry(uint8_t tag)
{
	for (int i = 0; i < COUNTOF(DNS_ENTRIES); i++) {
		if (tag == DNS_ENTRIES[i].tag) {
			return DNS_ENTRIES[i].val;
		}
	}
	return NULL;
}

// Master MACs to timing info
KHASH_MAP_INIT_INT64(masters, running_stats_t);
static khash_t(masters) *masters;

typedef struct {
	mac_t master;
	uint8_t chseq[16];
} neigh_info_t;

void
neigh_info_init(neigh_info_t *ni)
{
	ni->master = MAC(0,0,0,0,0,0);
	for (int i = 0; i < 16; i++) {
		ni->chseq[i] = 0;
	}
}

// Neighbor MACs to info
KHASH_MAP_INIT_INT64(neighbors, neigh_info_t);
static khash_t(neighbors) *neighbors;

// must hold masters_mtx while calling
neigh_info_t *
get_or_create_neighbor(mac_t mac)
{
	int ret;
	khiter_t k = kh_put(neighbors, neighbors, wrap_mac(mac), &ret);
	neigh_info_t *ni = &kh_value(neighbors, k);
	if (ret > 0) {
		neigh_info_init(ni);
	}
	return ni;
}

neigh_info_t *
get_neighbor(mac_t mac)
{
	khiter_t k = kh_get(neighbors, neighbors, wrap_mac(mac));
	if (k == kh_end(neighbors)) {
		return NULL;
	} else {
		return &kh_value(neighbors, k);
	}
}

static SemaphoreHandle_t masters_mtx;

void
update_master(mac_t addr, mac_t maddr, int64_t offset, int64_t next_aw_seqnum)
{
	xSemaphoreTake(masters_mtx, portMAX_DELAY);
	// update master offset
	int64_t key = wrap_mac(maddr);
	int ret;
	khiter_t k = kh_put(masters, masters, key, &ret);
	running_stats_t *rs = &kh_value(masters, k);
	if (ret > 0) {
		// nonexistent or deleted
		running_stats_init(rs, 16);
	}
	running_stats_update(rs, offset);
	rs->recent_awc_seqnum = (next_aw_seqnum/1024)*1024;
	// update neighbor's master
	neigh_info_t *ni = get_or_create_neighbor(addr);
	ni->master = maddr;
	xSemaphoreGive(masters_mtx);
}

void
handle_srv_resp(uint8_t *pkt_payload, uint8_t *tlv_payload)
{
	mac_t txaddr = mac_from_bytes(&pkt_payload[10]);
	print_mac(txaddr);
	printf(" ");

	// printf(" ");
	uint8_t name_len = tlv_payload[0];
	uint8_t name_len_unknown = tlv_payload[1];
	if (name_len_unknown != 0) {
		// printf("byte after name_len not 0x00, not sure what to do\n");
		return;
	}
	uint8_t *name_end = &tlv_payload[name_len+1];
	uint8_t *name_literal = &tlv_payload[2];
	uint8_t buf[256];
	int pos = 0;
	while (name_literal < name_end) {
		if (name_literal[0] == 0xc0) {
			char *dns = lookup_dns_entry(name_literal[1]);
			if (dns) {
				// printf("%s", dns);
				pos += sprintf((char *) &buf[pos], "%s", dns);
			} else {
				pos += sprintf((char *) &buf[pos], "UNKNOWN(%u)", name_literal[1]);
			}
			name_literal += 2;
		} else {
			for (int i = 0; i < name_literal[0]; i++) {
				// printf("%c", name_literal[i+1]);
				buf[pos++] = name_literal[i+1];
			}
			name_literal += name_literal[0]+1;
		}
		// printf(".");
		buf[pos++] = '.';
	}
	// printf("\n");
	buf[pos] = '\0';
	printf("%s", buf);
	if (name_end[0] == 0x21) {
		uint16_t port = *((uint16_t *) &name_end[9]);
		printf(" SRV port %d", port);
		char airdrop_url[] = "_airdrop._tcp.local.";
		size_t urllen = sizeof(airdrop_url) - 1;
		if (!memcmp(&buf[pos]-urllen, airdrop_url, urllen)) {
			printf(" posting");
			awdl_airdrop_addr_t evt_data;
			strcpy(evt_data.hostname, (char *) buf);
			evt_data.port = port;
			ESP_ERROR_CHECK(esp_event_post_to(loop, 
				AWDL_EVENT, AWDL_FOUND_AIRDROP, 
				&evt_data, sizeof(evt_data), portMAX_DELAY));
			xSemaphoreTake(dns_mtx, portMAX_DELAY);
			int ret;
			khiter_t k = kh_put(dns_map, dns_map, (char *) buf, &ret);
			kh_value(dns_map, k) = mac_to_ip(txaddr, awdl_netif_idx);
			xSemaphoreGive(dns_mtx);
		}
	}
	printf("\n");
}

void
handle_sync_params(uint8_t *pkt_payload, uint8_t *tlv_payload, uint32_t timestamp)
{
	// uint8_t txaddr[6], masteraddr[6];
	// memcpy(&txaddr[0], &pkt_payload[10], 6);
	mac_t txaddr = mac_from_bytes(&pkt_payload[10]);
	uint8_t *fparams = &pkt_payload[28];
	uint32_t phy_tx_time = *((uint32_t *) (fparams+4));
	uint32_t tgt_tx_time = *((uint32_t *) (fparams+8));
	// printf("phy_tx_time: %" PRIu32 " tgt_tx_time: %" PRIu32 "\n", phy_tx_time, tgt_tx_time);
	mac_t masteraddr = mac_from_bytes(&tlv_payload[21]);
	// memcpy(&masteraddr[0], tlv_payload+21, 6);

	int64_t remaining_tus = *((uint16_t *) (tlv_payload+15));
	int64_t next_aw_ts = wifi_init_ts + timestamp + remaining_tus*TU_US - (phy_tx_time-tgt_tx_time);
	int64_t next_aw_seqnum = *((uint16_t *) (tlv_payload+29)) + 1;
	int64_t next_aw_misalignment = next_aw_seqnum % AW_PER_AWC;
	int64_t awc_start = next_aw_ts - (next_aw_misalignment*AW_US);
	int64_t offset = awc_start % AWC_US;

	printf("update from ");
	print_mac(txaddr);
	printf(" master: ");
	print_mac(masteraddr);
	printf(" remaining_tus: %d next_aw: %d offset: %f\n", 
		(int) remaining_tus, (int) next_aw_seqnum,
		(double) offset);
	update_master(txaddr, masteraddr, offset, next_aw_seqnum);
}

void
wifi_pkt_handler(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *pkt = buf;

	if (pkt->payload[0] == 0x08) {
		if (!memcmp(&pkt->payload[16], "\x00\x25\x00\xff\x94\x73", 6)) {
			printf("got awdl_data packet for");
			print_mac(mac_from_bytes(&pkt->payload[4]));
			printf("\n");
			if (!memcmp(&pkt->payload[4], mac_bytes, 6)) {
				for (int i = 0; i < 100; i++) {
					printf("I GOT A DATA PACKET! \n");
				}
				printf("\n");
				DELAY(100000);
			}
		}
		return;
	}

	if (pkt->payload[0] != 0xd0) return; // MGMT, ACTION frame
	uint8_t mgmt_params[] = "\x7f\x00\x17\xf2"; // Vendor specific, Apple
	if (memcmp(&pkt->payload[24], &mgmt_params[0], sizeof(mgmt_params)-1)) return;
	// printf("got AWDL rssi: %d len: %u\n",
		// pkt->rx_ctrl.rssi, pkt->rx_ctrl.sig_len);
	// printf("  rx time: %u now: %llu\n", pkt->rx_ctrl.timestamp, esp_timer_get_time());
	uint8_t *payload_end = &pkt->payload[pkt->rx_ctrl.sig_len];
	// printf("  phy_tx_t: %u tgt_txt_t: %u\n", phy_tx_time, tgt_tx_time);
	uint8_t *tlvs = &pkt->payload[40];
	uint8_t *tlv = tlvs;
	while (tlv < payload_end) {
		uint16_t tlv_len = *((uint16_t *) (tlv+1));
		// printf("  tlv len: %u ", tlv_len);
		uint8_t *tlv_payload = tlv + 3;
		switch (tlv[0]) {
		ENUMCASEO(AWDL_TAG_SRV_RESP);
			handle_srv_resp(pkt->payload, tlv_payload);
			break;
		ENUMCASEO(AWDL_TAG_SYNC_PARAMS);
			handle_sync_params(pkt->payload, tlv_payload, pkt->rx_ctrl.timestamp);
			break;
		ENUMCASE(AWDL_TAG_SRV_PARAMS);
		ENUMCASEO(AWDL_TAG_CH_SEQ);
			printf("channel seq:");
			uint8_t *chseq = &tlv_payload[6];
			for (int i = 0; i < 16; i++) {
				printf(" %d", chseq[i*2]);
			}
			printf("\n");
			xSemaphoreTake(masters_mtx, portMAX_DELAY);
			mac_t txaddr = mac_from_bytes(&pkt->payload[10]);
			neigh_info_t *ni = get_or_create_neighbor(txaddr);
			for (int i = 0; i < 16; i++) {
				ni->chseq[i] = chseq[i*2];
			}
			xSemaphoreGive(masters_mtx);
			break;
		ENUMDEFAULT(tlv[0]);
		}
		tlv += tlv_len+3;
		// printf("\n");
	}
	// add_pcap_pkt(pkt->payload, pkt->rx_ctrl.sig_len, pkt->rx_ctrl.timestamp);
}

err_t
awdl_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
	/*
	printf("awdl ipv4 unimplemented\n");
	fflush(stdout);
	DELAY(100);
	abort();
	*/

	char addrbuf[256];
	ip4addr_ntoa_r(ipaddr, addrbuf, sizeof(addrbuf));
	printf("awdl_output4: sending frame to %s\n", addrbuf);
	/*
	etharp_output(netif, p, ipaddr);
	*/
	return ERR_OK;
}

uint8_t wlan_hdr[] = {
	0x08, 0x00, // frame control: data
	0x00, 0x00, // duration
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src
	0x00, 0x25, 0x00, 0xff, 0x94, 0x73, // bssid (apple)
	0x00, 0x00, // seq ctrl
};

uint8_t llc_hdr[] = {
	0xaa, 0xaa, // dsap, ssap
	0x03, // ctrl
	0x00, 0x17, 0xf2, // OUI (apple)
	0x08, 0x00, // protocol
};

uint8_t awdl_hdr[] = {
	0x03, 0x04, // magic
	0x00, 0x00, // seqnum
	0x00, 0x00, // reserved
	0x86, 0xdd, // ethertype
};

void
print_buf(uint8_t *buf, size_t len)
{
	for (int i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
		if (i % 8 == 0) printf(" ");
		if (i % 16 == 0) printf("\n");
	}
	printf("\n");
}

err_t
awdl_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ip6addr)
{
	char addrbuf[256];
	ip6addr_ntoa_r(ip6addr, addrbuf, sizeof(addrbuf));
	printf("awdl_output6: sending frame to %s (len %d, next: %d)\n", addrbuf, p->len, p->next!=NULL);

	mac_t mac;
	ip6_to_mac(ip6addr, &mac);
	printf("mac: ");
	print_mac(mac);
	printf("\n");

	xSemaphoreTake(masters_mtx, portMAX_DELAY);

	running_stats_t *rs = NULL;
	neigh_info_t *ni = get_neighbor(mac);
	if (ni == NULL) {
		printf("neighbor not found\n");
		goto fail;
	}

	printf("found neighbor\n");
	printf("  master: ");
	print_mac(ni->master);
	printf("\n");
	printf("  chseq:");
	for (int i = 0; i < 16; i++) {
		printf(" %d", ni->chseq[i]);
	}
	printf("\n");

	mac_t null_mac = NULL_MAC;
	if (!memcmp(&ni->master, &null_mac, sizeof(null_mac))) {
		printf("  null master\n");
		goto fail;
	}
	khint_t k = kh_get(masters, masters, wrap_mac(ni->master));
	if (k == kh_end(masters)) {
		printf("  unknown master\n");
		goto fail;
	}
	rs = &kh_value(masters, k);

	float mean, stdev;
	running_stats_calc(rs, &mean, &stdev);
	if (stdev > MAX_SYNC_STDEV_US) {
		printf("stdev %f too large to attempt tx\n", stdev);
		goto fail;
	}

	printf("synchronized to master, ready to tx\n");

	int ch6idx = -1;
	for (int i = 0; i < 16; i++) {
		if (ni->chseq[i] == 6) {
			ch6idx = i;
			break;
		}
	}
	if (ch6idx == -1) {
		printf("never on channel 6\n");
		goto fail;
	}

	goto send;

fail:
	xSemaphoreGive(masters_mtx);
	return ERR_OK;

send:
	xSemaphoreGive(masters_mtx);
	int64_t target_aw_offset = ch6idx*4*AW_US;
	int64_t current_offset = (esp_timer_get_time() + (int64_t) mean) % AWC_US;
	printf("tgt_aw_offset: %" PRIu64 " cur_offset: %" PRIu64 "\n", target_aw_offset, current_offset);
	if (current_offset < target_aw_offset) {
		printf("waiting to transmit this cycle\n");
		DELAY((target_aw_offset-current_offset)/1000+5);
	} else if (current_offset < target_aw_offset + AW_US*4) {
		printf("immediate tx\n");
	} else {
		printf("have to wait until next cycle\n");
		DELAY((AWC_US-current_offset+target_aw_offset)/1000+5);
	}
	int64_t new_offset = (esp_timer_get_time() + (int64_t) mean) % AWC_US;
	printf("new_offset: %" PRIu64 "\n", new_offset);

	// ethip6_output(netif, p, ipaddr);

	uint8_t *buf = malloc(4096);
	uint8_t *pos = buf;
	memcpy(pos, wlan_hdr, sizeof(wlan_hdr));
	pos += sizeof(wlan_hdr);
	memcpy(pos, llc_hdr, sizeof(llc_hdr));
	pos += sizeof(llc_hdr);
	memcpy(pos, awdl_hdr, sizeof(awdl_hdr));
	pos += sizeof(awdl_hdr);
	memcpy(pos, p->payload, p->len);
	pos += p->len;

	memcpy(&buf[4], mac.addr, 6); // dst
	memcpy(&buf[10], mac_bytes, 6); // src

	ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, buf, pos-buf, true)); // try true for now?

	free(buf);
	printf("sent\n");
	return ERR_OK;
}

err_t
awdl_link_output(struct netif *netif, struct pbuf *p)
{
	printf("awdl_link_output (len %d, next: %d)\n", p->len, p->next!=NULL);
	for (int i = 0; i < p->len; i++) {
		printf("%02x ", ((uint8_t *) p->payload)[i]);
		if (i % 8 == 0) printf(" ");
		if (i % 16 == 0) printf("\n");
	}
	printf("\n");
	return ERR_OK;
}

err_t
awdlif_init(struct netif *netif)
{
	netif->hostname = "awdl-lwip";
 	netif->output = awdl_output;
  	netif->output_ip6 = awdl_output6;
 	netif->linkoutput = awdl_link_output;
  	netif->hwaddr_len = ETHARP_HWADDR_LEN;
  	memcpy(netif->hwaddr, mac_bytes, ETHARP_HWADDR_LEN);
	netif->mtu = 1500;
  	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_LINK_UP | NETIF_FLAG_ETHERNET;
  	netif_create_ip6_linklocal_address(netif, 1);
  	netif_ip6_addr_set_state(netif, 0, IP6_ADDR_PREFERRED);
	return ERR_OK;
}

typedef struct {
	ip4_addr_t ipaddr, netmask, gw;
	struct netif netif;
} awdl_state_t;

void
print_awc_stats_task(void *params)
{
	float mean, stdev;
	for (;;) {
		int64_t t0 = esp_timer_get_time();
		xSemaphoreTake(masters_mtx, portMAX_DELAY);
		for (khiter_t k = kh_begin(masters); k != kh_end(masters); k++) {
			if (!kh_exist(masters, k)) continue;
			mac_t addr = unwrap_mac(kh_key(masters, k));
			running_stats_t *rs = &kh_value(masters, k);
			running_stats_calc(rs, &mean, &stdev);
			printf("master ");
			print_mac(addr);
			printf(" mean: %f stdev: %f\n", mean, stdev);
		}
		xSemaphoreGive(masters_mtx);
		int64_t t1 = esp_timer_get_time();
		double ms = (double) (t1-t0) / 1000;
		printf("done in %f ms\n", ms);
		DELAY(1000);
	}
}

uint8_t wlan_action_hdr[] = {
	// 802.11 
	0xd0, 0x00, // action
	0x00, 0x00, // duration
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src
	0x00, 0x25, 0x00, 0xff, 0x94, 0x73, // bssid (apple)
	0x00, 0x00, // seq ctrl

	// 802.11 action
	0x7f, 0x00, 0x17, 0xf2, // oui (apple)

	// awdl fixed params
	0x08, 0x10, // awdl, version 1.0
	0x00, 0x00, // PSF, reserved
	0x00, 0x00, 0x00, 0x00, // phy tx time
	0x00, 0x00, 0x00, 0x00, // tgt tx time
};

size_t
add_chlist(uint8_t *buf)
{
	for (int i = 0; i < 16; i++) {
		buf[i*2] = 0x06;
		buf[i*2+1] = 0x51;
	}
	return 32;
}

uint8_t sync_params[] = {
	0x04, 0x49, 0x00, // sync tag, 73 bytes
	0x06, // next aw channel
	0x00, 0x00, // tx counter
	0x06, // master channel
	0x00, // guard time
	0x10, 0x00, // aw period
	0x6e, 0x00, // af period
	0x00, 0x18, // awdl flags?
	0x10, 0x00, // aw ext len
	0x10, 0x00, // aw common len
	0x00, 0x00, // remaining aw len
	0x03, 0x03, 0x03, 0x03, // min ext, & multi, uni, af
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // master addr
	0x04, 0x00, // presence mode, unknown
	0x05, 0x0d, // aw seq num
	0x00, 0x00, // ap beacon alignment delta
	0x0f, // num channels
	0x03, // encoding legacy
	0x00, // duplicate
	0x03, // step cnt
	0xff, 0xff, // fill repeat
};

uint8_t elec_params[] = {
	0x05, 0x15, 0x00, // elec tag, 21 bytes
	0x00, 0x00, 0x00, // flags, id
	0x01, // dist to master
	0x00, // unknown
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // master addr
	0x12, 0x02, 0x00, 0x00, // master metric: 530
	0x10, 0x02, 0x00, 0x00, // self metric: 528
	0x00, 0x00, // padding
};

uint8_t chseq_params[] = {
	0x12, 0x29, 0x00, // chseq tag, 41 bytes
	0x0f, // num ch
	0x03, // encoding opclass
	0x00, // duplicate
	0x03, // step cnt
	0xff, 0xff, // fill repeat
};

uint8_t version_params[] = {
	0x15, 0x02, 0x00, // version tag, 2 bytes
	0x40, 0x02, // awdl 4.0 device iOS or watchOS
};

uint8_t ping_pkt[] = {
	0x60, 0x03, 0x0c, 0xde, // ipv6 hdr
	0x00, 0x10, // payload len 16
	0x3a, // icmpv6
	0x40, // hop limit 64
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src
	0x03, 0x02, 0x03, 0xff, 0xfe, 0x04, 0x05, 0x06,
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

	0x80, // ping request
	0x00, // code
	0xfc, 0x27, // checksum
	0x58, 0xa1, // identifier
	0x00, 0x00, // seqnum
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // data??
};

void
awdl_periodic_sync_task(void *params)
{
	int iter = 0;
	uint8_t *buf = malloc(4096);
	for (;;) {
		// pick best master
		mac_t best_master_addr = NULL_MAC;
		float best_master_stdev = MAX_SYNC_STDEV_US;
		float best_master_mean = 0;
		int64_t best_awc_seqnum = 0;
		float mean, stdev;
		xSemaphoreTake(masters_mtx, portMAX_DELAY);
		for (khiter_t k = kh_begin(masters); k != kh_end(masters); k++) {
			if (!kh_exist(masters, k)) continue;
			mac_t maddr = unwrap_mac(kh_key(masters, k));
			running_stats_t *rs = &kh_value(masters, k);
			running_stats_calc(rs, &mean, &stdev);
			if (stdev < best_master_stdev) {
				best_master_addr = maddr;
				best_master_mean = mean;
				best_master_stdev = stdev;
				best_awc_seqnum = rs->recent_awc_seqnum;
			}
		}
		xSemaphoreGive(masters_mtx);
		if (best_master_stdev == MAX_SYNC_STDEV_US) {
			printf("no master\n");
			goto done;
		}

		int64_t current_offset = (esp_timer_get_time() + (int64_t) best_master_mean) % AWC_US;
		int64_t current_aw = current_offset / AW_US;
		int64_t current_aw_seqnum = best_awc_seqnum + current_aw;

		uint8_t *pos = buf;

		memcpy(pos, wlan_action_hdr, sizeof(wlan_action_hdr));
		memcpy(&pos[10], mac_bytes, 6); // src mac
		int64_t now = esp_timer_get_time();
		memcpy(&pos[32], (uint32_t *) &now, 4);
		memcpy(&pos[36], (uint32_t *) &now, 4);
		pos += sizeof(wlan_action_hdr);

		memcpy(pos, sync_params, sizeof(sync_params));
		memcpy(&pos[24], best_master_addr.addr, 6);
		// memcpy(&pos[32])
		*((uint32_t *) &pos[24]) = (uint32_t) (current_aw_seqnum & 0xffffffff) + 1;
		pos += sizeof(sync_params);
		pos += add_chlist(pos);
		memcpy(pos, "\x00\x00", 2);
		pos += 2;

		memcpy(pos, elec_params, sizeof(elec_params));
		memcpy(&pos[8], best_master_addr.addr, 6);
		pos += sizeof(elec_params);

		memcpy(pos, chseq_params, sizeof(chseq_params));
		pos += sizeof(chseq_params);
		pos += add_chlist(pos);
		memcpy(pos, "\x00\x00\x00", 3);
		pos += 3;

		memcpy(pos, version_params, sizeof(version_params));
		pos += sizeof(version_params);

		if (iter % 10 == 0) {
			printf("sending PSF for master: ");
			print_mac(best_master_addr);
			printf("\n");
		}
		ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, buf, pos-buf, false));

		// ping ff02::1
		pos = buf;
		memcpy(pos, wlan_hdr, sizeof(wlan_hdr));
		memcpy(&pos[4], "\x33\x33\x00\x00\x00\x01", 6); // dst (ipv6 mcast)
		memcpy(&pos[10], mac_bytes, 6); // src
		pos += sizeof(wlan_hdr);
		memcpy(pos, llc_hdr, sizeof(llc_hdr));
		pos += sizeof(llc_hdr);
		memcpy(pos, awdl_hdr, sizeof(awdl_hdr));
		pos += sizeof(awdl_hdr);
		memcpy(pos, ping_pkt, sizeof(ping_pkt));
		pos += sizeof(ping_pkt);
		ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, buf, pos-buf, false));

done:
		iter++;
		DELAY(100);
	}
}

void
ble_handler(esp_gap_ble_cb_event_t evt, esp_ble_gap_cb_param_t *param)
{
	printf("got ble event: ");
	switch (evt) {
	ENUMCASEO(ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT);
		printf(" status: %d", param->adv_data_raw_cmpl.status);
		break;
	ENUMCASEO(ESP_GAP_BLE_ADV_START_COMPLETE_EVT);
		printf(" status: %d", param->adv_start_cmpl.status);
		break;
	ENUMCASEO(ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT);
		printf(" status: %d", param->adv_stop_cmpl.status);
		break;
	ENUMCASE(ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_RESULT_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_START_COMPLETE_EVT);
	ENUMCASE(ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT);
	ENUMDEFAULT(evt);
	}
	printf("\n");
}

esp_event_loop_handle_t
awdl_init()
{
	awdl_state_t *state = malloc(sizeof(awdl_state_t));

	masters = kh_init(masters);
	neighbors = kh_init(neighbors);
	masters_mtx = xSemaphoreCreateMutex();

	dns_map = kh_init(dns_map);
	dns_mtx = xSemaphoreCreateMutex();

	esp_event_loop_args_t loop_args = {
		.queue_size = 1024,
		.task_name = "awdl_loop",
		.task_priority = 1,
		.task_stack_size = 8192,
		.task_core_id = 0,
	};
	ESP_ERROR_CHECK(esp_event_loop_create(&loop_args, &loop));

    // init wifi
    printf("initializing wifi\n");
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    wifi_config_t ap_cfg = {
    	.ap = {
    		.ssid = "esp32-fakebeacon",
    		.ssid_len = 0,
    		.password = "dummypass",
    		.channel = 1,
    		.authmode = WIFI_AUTH_WPA2_PSK,
    		.ssid_hidden = 1,
    		.max_connection = 4,
    		.beacon_interval = 60000,
    	},
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    DELAY(100);

    printf("initializing promiscuous mode\n");
    wifi_promiscuous_filter_t promisc_filter = {
    	.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&promisc_filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_pkt_handler));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    DELAY(100);

    printf("switching to channel 6\n");
	ESP_ERROR_CHECK(esp_wifi_set_channel(6, 0));

	// init bt
	printf("initializing bluetooth\n");
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BTDM));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());
    // init ble
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(ble_handler));
    ESP_ERROR_CHECK(esp_ble_gap_config_adv_data_raw(airdrop_ble_data, sizeof(airdrop_ble_data)));
    esp_ble_adv_params_t adv_params = {
    	.adv_int_min = 300,
    	.adv_int_max = 300,
    	.adv_type = ADV_TYPE_NONCONN_IND,
    	.own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    	.peer_addr = {0},
    	.peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
    	.channel_map = ADV_CHNL_ALL,
    	.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };
    ESP_ERROR_CHECK(esp_ble_gap_start_advertising(&adv_params));

	printf("initializing awdl");
	tcpip_init(NULL, NULL);
	IP4_ADDR(&state->ipaddr, 192, 168, 55, 2);
	IP4_ADDR(&state->netmask, 255, 255, 255, 0);
	IP4_ADDR(&state->gw, 192, 168, 55, 1);

	printf("adding awdl iface\n");
	netif_add(&state->netif, &state->ipaddr, &state->netmask, &state->gw, NULL, awdlif_init, tcpip_input);
	netif_set_default(&state->netif);
	netif_set_up(&state->netif);
	netif_set_default(&state->netif);
	awdl_netif_idx = netif_get_index(&state->netif);

	wifi_init_ts = esp_phy_rf_get_on_ts();

	esp_timer_create_args_t timer_args = {
		.callback = awdl_timer_cb,
		.arg = NULL,

	};
	ESP_ERROR_CHECK(esp_timer_create(&timer_args, &awdl_timer));

    xTaskCreate(print_awc_stats_task, "print_awc_stats", 8192, NULL, 5, NULL);
    xTaskCreate(awdl_periodic_sync_task, "awdl_periodic_sync", 8192, NULL, 5, NULL);

    DELAY(100);

    return loop;
}
