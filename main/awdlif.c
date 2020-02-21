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

char *mac_bytes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

ESP_EVENT_DEFINE_BASE(AWDL_EVENT);

static int awdl_netif_idx = 0;
static esp_event_loop_handle_t loop;

KHASH_MAP_INIT_STR(dns_map, ip_addr_t);
static khash_t(dns_map) *dns_map;
static SemaphoreHandle_t dns_mtx;

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
	ip6_addr_set_zone(ip_2_ip6(addr), awdl_netif_idx);
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

KHASH_MAP_INIT_INT64(masters, running_stats_t);
static khash_t(masters) *masters;

KHASH_MAP_INIT_INT64(master_map, int32_t);
static khash_t(master_map) *master_map;

static SemaphoreHandle_t masters_mtx;

void
update_master(uint8_t *addr, uint8_t *maddr, int32_t offset)
{
	xSemaphoreTake(masters_mtx, portMAX_DELAY);
	// update master offset
	uint64_t key = wrap_mac(maddr);
	int ret;
	khiter_t k = kh_put(masters, masters, key, &ret);
	running_stats_t *rs = &kh_value(masters, k);
	if (ret > 0) {
		// nonexistent or deleted
		running_stats_init(rs, 16);
	}
	running_stats_update(rs, offset);
	// update master map
	key = wrap_mac(addr);
	k = kh_put(master_map, master_map, key, &ret);
	kh_value(master_map, k) = wrap_mac(maddr);
	xSemaphoreGive(masters_mtx);
}

void
handle_srv_resp(uint8_t *pkt_payload, uint8_t *tlv_payload)
{
	uint8_t txaddr[6];
	memcpy(&txaddr[0], &pkt_payload[10], 6);
	print_mac(&pkt_payload[10]);
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
			kh_value(dns_map, k) = mac_to_ip(txaddr);
			xSemaphoreGive(dns_mtx);
		}
	}
	printf("\n");
}

void
handle_sync_params(uint8_t *pkt_payload, uint8_t *tlv_payload, uint32_t timestamp)
{
	uint8_t txaddr[6], masteraddr[6];
	memcpy(&txaddr[0], &pkt_payload[10], 6);
	uint8_t *fparams = &pkt_payload[28];
	uint32_t phy_tx_time = *((uint32_t *) (fparams+4));
	uint32_t tgt_tx_time = *((uint32_t *) (fparams+8));
	memcpy(&masteraddr[0], tlv_payload+21, 6);

	uint32_t remaining_tus = *((uint16_t *) (tlv_payload+15));
	uint32_t next_aw_ts = timestamp + remaining_tus*TU_US - (phy_tx_time-tgt_tx_time);
	uint32_t next_aw_seqnum = *((uint16_t *) (tlv_payload+29)) + 1;
	uint32_t next_aw_misalignment = next_aw_seqnum % AW_PER_AWC;
	uint32_t awc_start = next_aw_ts - (next_aw_misalignment*AW_US);
	uint32_t offset = awc_start % AWC_US;

	printf("update from ");
	print_mac(txaddr);
	printf(" master: ");
	print_mac(masteraddr);
	printf(" remaining_tus: %d next_aw: %d offset: %f\n", 
		(int) remaining_tus, (int) next_aw_seqnum,
		(double) offset);
	update_master(txaddr, masteraddr, offset);
}

void
wifi_pkt_handler(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *pkt = buf;

	if (pkt->payload[0] == 0x08) {
		if (!memcmp(&pkt->payload[16], "\x00\x25\x00\xff\x94\x73", 6)) {
			printf("got awdl_data packet for");
			print_mac(&pkt->payload[4]);
			printf("\n");
			if (!memcmp(&pkt->payload[4], mac_bytes, 6)) {
				for (int i = 0; i < 10; i++) {
					printf("I GOT A PACKET! ");
				}
				printf("\n");
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
		ENUMCASE(AWDL_TAG_CH_SEQ);
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
	0x08, 0x00, 0x00, 0x00, 0x33, 0x33, 0x80, 0x00,
	0x00, 0xfb, 0x06, 0x7a, 0x51, 0x14, 0xf8, 0xb7,
	0x00, 0x25, 0x00, 0xff, 0x94, 0x73, 0x50, 0x65,
};

uint8_t llc_hdr[] = {
	0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00,
};

uint8_t awdl_hdr[] = {
	0x03, 0x04, 0x7d, 0x00, 0x00, 0x00, 0x86, 0xdd,
};

err_t
awdl_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
	char addrbuf[256];
	ip6addr_ntoa_r(ipaddr, addrbuf, sizeof(addrbuf));
	printf("awdl_output6: sending frame to %s (len %d, next: %d)\n", addrbuf, p->len, p->next!=NULL);
	for (int i = 0; i < p->len; i++) {
		printf("%02x ", ((uint8_t *) p->payload)[i]);
		if (i % 8 == 0) printf(" ");
		if (i % 16 == 0) printf("\n");
	}
	printf("\n");
	// ethip6_output(netif, p, ipaddr);

	uint8_t *buf = malloc(1024);
	uint8_t *pos = buf;
	memcpy(pos, wlan_hdr, sizeof(wlan_hdr));
	pos += sizeof(wlan_hdr);
	memcpy(pos, llc_hdr, sizeof(llc_hdr));
	pos += sizeof(llc_hdr);
	memcpy(pos, awdl_hdr, sizeof(awdl_hdr));
	pos += sizeof(awdl_hdr);
	memcpy(pos, p->payload, p->len);
	pos += p->len;

	ESP_ERROR_CHECK(esp_wifi_80211_tx(ESP_IF_ETH, buf, pos-buf, false));

	return ERR_OK;
}

err_t
awdl_link_output(struct netif *netif, struct pbuf *p)
{
	/*
	printf("awdl mac unimplemented\n");
	fflush(stdout);
	DELAY(100);
	abort();
	*/
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
			uint64_t *addr = &kh_key(masters, k);
			running_stats_t *rs = &kh_value(masters, k);
			running_stats_calc(rs, &mean, &stdev);
			printf("master ");
			print_mac((uint8_t *) addr);
			printf(" mean: %f stdev: %f\n", mean, stdev);
		}
		xSemaphoreGive(masters_mtx);
		int64_t t1 = esp_timer_get_time();
		double ms = (double) (t1-t0) / 1000;
		printf("done in %f ms\n", ms);
		DELAY(1000);
	}
}

esp_event_loop_handle_t
awdl_init()
{
	awdl_state_t *state = malloc(sizeof(awdl_state_t));
	// running_stats_init(&awc_offset_stats, 64);
	masters = kh_init(masters);
	master_map = kh_init(master_map);
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

    // init wifi
    printf("initializing wifi\n");
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_start());
    DELAY(100);

    printf("initializing promiscuous mode\n");
    wifi_promiscuous_filter_t promisc_filter = {
    	.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&promisc_filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_pkt_handler));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    DELAY(100);

    printf("switching to channel 6\n");
	ESP_ERROR_CHECK(esp_wifi_set_channel(6, 0));

    xTaskCreate(print_awc_stats_task, "print_awc_stats", 8192, NULL, 5, NULL);

    DELAY(100);

    return loop;
}
