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

// tu = time unit
// aw = availability window
// awc = aw cycle

#define TU_PER_AW 16
#define AW_PER_AWC 64

#define TU_US 1024
#define AW_US (TU_US*TU_PER_AW)
#define AWC_US (AW_US*AW_PER_AWC)

static volatile int awdl_netif_idx = 0;

err_t
awdl_dns_lookup(const char *name, ip_addr_t *addr, u8_t dns_addrtype)
{
	printf("performing dns lookup for %s\n", name);
	char *addrbuf = "fe80::1234:5678";
	ipaddr_aton(addrbuf, addr);
	ip6_addr_set_zone(ip_2_ip6(addr), awdl_netif_idx);
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
static SemaphoreHandle_t masters_mtx;

void
update_master(uint8_t *addr, int32_t offset)
{
	xSemaphoreTake(masters_mtx, portMAX_DELAY);
	uint64_t key = 0;
	memcpy(&key, addr, 6);
	int ret;
	khiter_t k = kh_put(masters, masters, key, &ret);
	running_stats_t *rs = &kh_value(masters, k);
	if (ret > 0) {
		// nonexistent or deleted
		running_stats_init(rs, 16);
	}
	running_stats_update(rs, offset);
	xSemaphoreGive(masters_mtx);
}

void
wifi_pkt_handler(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *pkt = buf;
	if (pkt->payload[0] != 0xd0) return; // MGMT, ACTION frame
	uint8_t mgmt_params[] = "\x7f\x00\x17\xf2"; // Vendor specific, Apple
	if (memcmp(&pkt->payload[24], &mgmt_params[0], sizeof(mgmt_params)-1)) return;
	uint8_t txaddr[6], masteraddr[6];
	memcpy(&txaddr[0], &pkt->payload[10], 6);
	// printf("got AWDL rssi: %d len: %u\n",
		// pkt->rx_ctrl.rssi, pkt->rx_ctrl.sig_len);
	// printf("  rx time: %u now: %llu\n", pkt->rx_ctrl.timestamp, esp_timer_get_time());
	uint8_t *payload_end = &pkt->payload[pkt->rx_ctrl.sig_len];
	uint8_t *fparams = &pkt->payload[28];
	uint32_t phy_tx_time = *((uint32_t *) (fparams+4));
	uint32_t tgt_tx_time = *((uint32_t *) (fparams+8));
	// printf("  phy_tx_t: %u tgt_txt_t: %u\n", phy_tx_time, tgt_tx_time);
	uint8_t *tlvs = &pkt->payload[40];
	uint8_t *tlv = tlvs;
	while (tlv < payload_end) {
		uint16_t tlv_len = *((uint16_t *) (tlv+1));
		// printf("  tlv len: %u ", tlv_len);
		uint8_t *tlv_payload = tlv + 3;
		switch (tlv[0]) {
		ENUMCASEO(AWDL_TAG_SRV_RESP);
			// printf(" ");
			uint8_t name_len = tlv_payload[0];
			uint8_t name_len_unknown = tlv_payload[1];
			if (name_len_unknown != 0) {
				// printf("byte after name_len not 0x00, not sure what to do\n");
				break;
			}
			uint8_t *name_end = &tlv_payload[name_len+1];
			uint8_t *name_literal = &tlv_payload[2];
			while (name_literal < name_end) {
				if (name_literal[0] == 0xc0) {
					char *dns = lookup_dns_entry(name_literal[1]);
					if (dns) {
						// printf("%s", dns);
					} else {
						// printf("UNKNOWN(%u)", name_literal[1]);
					}
					name_literal += 2;
				} else {
					for (int i = 0; i < name_literal[0]; i++) {
						// printf("%c", name_literal[i+1]);
					}
					name_literal += name_literal[0]+1;
				}
				// printf(".");
			}
			break;
		ENUMCASEO(AWDL_TAG_SYNC_PARAMS);
			uint64_t remaining_tus = *((uint16_t *) (tlv_payload+15));
			uint64_t next_aw_ts = pkt->rx_ctrl.timestamp + remaining_tus*TU_US - (phy_tx_time-tgt_tx_time);
			uint64_t next_aw_seqnum = *((uint16_t *) (tlv_payload+29)) + 1;
			// printf(" remaining_tus: %d next_aw_seqnum: %d", remaining_tus, next_aw_seqnum);
			uint64_t next_aw_misalignment = next_aw_seqnum % AW_PER_AWC;
			uint64_t awc_start = next_aw_ts - (next_aw_misalignment*AW_US);
			uint64_t offset = awc_start % AWC_US;
			memcpy(&masteraddr[0], tlv_payload+21, 6);
			printf("update from ");
			print_mac(txaddr);
			printf(" master: ");
			print_mac(masteraddr);
			printf(" remaining_tus: %d next_aw: %d offset: %f\n", 
				(int) remaining_tus, (int) next_aw_seqnum,
				(double) offset);
			update_master(masteraddr, offset);
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

err_t
awdl_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
	char addrbuf[256];
	ip6addr_ntoa_r(ipaddr, addrbuf, sizeof(addrbuf));
	printf("awdl_output6: sending frame to %s\n", addrbuf);
	// ethip6_output(netif, p, ipaddr);
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
	printf("awdl_link_output\n");
	return ERR_OK;
}

char *mac_bytes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

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

void
awdl_init()
{
	awdl_state_t *state = malloc(sizeof(awdl_state_t));
	// running_stats_init(&awc_offset_stats, 64);
	masters = kh_init(masters);
	masters_mtx = xSemaphoreCreateMutex();

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
}
