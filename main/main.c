#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_spi_flash.h"
#include "nvs_flash.h"

#define MIN(x, y) ((x)<(y)?(x):(y))
#define COUNTOF(x) (sizeof(x)/sizeof(x[0]))
#define DELAY(x) vTaskDelay((x)/portTICK_PERIOD_MS)

#define ENUMCASE(evtname) case evtname: printf(#evtname); break
#define ENUMCASEO(evtname) case evtname: printf(#evtname)
#define ENUMDEFAULT(x) default: printf("unknown (%d)", (int) x)

void
event_handler(void *handler_arg, esp_event_base_t base, int32_t id, void *evt_data)
{
	printf("got wifi event: ");
	switch (id) {
	ENUMCASE(WIFI_EVENT_WIFI_READY);
	ENUMDEFAULT(id);
	}
	printf("\n");
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
	ENUMCASE(ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT);
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

uint8_t airpods_data[] = {
	0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x01, 0x02, 
	0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
	0x00, 0x00, 0x00, // left, right, case
	0xda, 0x29, 0x58, 0xab, 0x8d, 0x29, 0x40, 0x3d, 
	0x5c, 0x1b, 0x93, 0x3a,
};

typedef struct {
	uint32_t magic;
	uint16_t major, minor;
	int32_t zone;
	uint32_t sigfigs, snaplen, network;
} pcap_hdr_t;

typedef struct {
	uint32_t ts_sec, ts_usec;
	uint32_t incl_len, orig_len;
} pcaprec_hdr_t ;

#define PCAP_BUF_SZ (16*1024)
SemaphoreHandle_t pcap_mutex;
uint8_t *pcap_buf;
int pcap_buf_idx;
int pcap_done;

void
init_pcap()
{
	pcap_mutex = xSemaphoreCreateMutex();
	pcap_buf = malloc(PCAP_BUF_SZ);
	pcap_hdr_t hdr = {
		.magic = 0xa1b2c3d4,
		.major = 2,
		.minor = 4,
		.zone = 0,
		.sigfigs = 0,
		.snaplen = 4096,
		.network = 105, // 802.11
	};
	memcpy(pcap_buf, &hdr, sizeof(hdr));
	pcap_buf_idx = sizeof(hdr);
	pcap_done = 0;
}

void
add_pcap_pkt(uint8_t *buf, int len, unsigned int timestamp)
{
	xSemaphoreTake(pcap_mutex, portMAX_DELAY);
	if (pcap_done) {
		xSemaphoreGive(pcap_mutex);
		return;
	}
	int incl_len = MIN(len, 4096);
	if (pcap_buf_idx + sizeof(pcaprec_hdr_t) + incl_len > PCAP_BUF_SZ) {
		printf("pcap buf full\n");
		pcap_done = 1;
		xSemaphoreGive(pcap_mutex);
		return;
	}
	pcaprec_hdr_t hdr = {
		.ts_sec = timestamp / 1000000U,
		.ts_usec = timestamp % 1000000U,
		.incl_len = incl_len,
		.orig_len = len,
	};
	memcpy(pcap_buf+pcap_buf_idx, &hdr, sizeof(hdr));
	pcap_buf_idx += sizeof(hdr);
	memcpy(pcap_buf+pcap_buf_idx, buf, incl_len);
	pcap_buf_idx += incl_len;
	xSemaphoreGive(pcap_mutex);
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

void
wifi_pkt_handler(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *pkt = buf;
	if (pkt->payload[0] != 0xd0) return; // MGMT, ACTION frame
	uint8_t mgmt_params[] = "\x7f\x00\x17\xf2"; // Vendor specific, Apple
	if (memcmp(&pkt->payload[24], &mgmt_params[0], sizeof(mgmt_params)-1)) return;
	printf("got AWDL rssi: %d len: %u\n",
		pkt->rx_ctrl.rssi, pkt->rx_ctrl.sig_len);
	uint8_t *payload_end = &pkt->payload[pkt->rx_ctrl.sig_len];
	uint8_t *fparams = &pkt->payload[28];
	uint8_t *tlvs = &pkt->payload[40];
	uint8_t *tlv = tlvs;
	while (tlv < payload_end) {
		uint16_t tlv_len = *((uint16_t *) (tlv+1));
		printf("  tlv len: %u ", tlv_len);
		uint8_t *tlv_payload = tlv + 3;
		switch (tlv[0]) {
		ENUMCASEO(AWDL_TAG_SRV_RESP);
			printf(" ");
			uint8_t name_len = tlv_payload[0];
			uint8_t name_len_unknown = tlv_payload[1];
			if (name_len_unknown != 0) {
				printf("byte after name_len not 0x00, not sure what to do\n");
				break;
			}
			uint8_t *name_end = &tlv_payload[name_len+1];
			uint8_t *name_literal = &tlv_payload[2];
			while (name_literal < name_end) {
				if (name_literal[0] == 0xc0) {
					char *dns = lookup_dns_entry(name_literal[1]);
					if (dns) {
						printf("%s", dns);
					} else {
						printf("UNKNOWN(%u)", name_literal[1]);
					}
					name_literal += 2;
				} else {
					for (int i = 0; i < name_literal[0]; i++) {
						printf("%c", name_literal[i+1]);
					}
					name_literal += name_literal[0]+1;
				}
				printf(".");
			}
			break;
		ENUMCASE(AWDL_TAG_SYNC_PARAMS);
		ENUMCASE(AWDL_TAG_SRV_PARAMS);
		ENUMCASE(AWDL_TAG_CH_SEQ);
		ENUMDEFAULT(tlv[0]);
		}
		tlv += tlv_len+3;
		printf("\n");
	}
	// add_pcap_pkt(pkt->payload, pkt->rx_ctrl.sig_len, pkt->rx_ctrl.timestamp);
}

void 
app_main()
{
    printf("Hello world! YOLO!!!!!!\n");

    init_pcap();

    // print chip information 
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is ESP32 chip with %d CPU cores, WiFi%s%s, ",
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");
    printf("silicon revision %d, ", chip_info.revision);
    printf("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    // init nvs
    ESP_ERROR_CHECK(nvs_flash_init());

    // init default event loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_event_handler_register(
    	WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, NULL));

    // init wifi
    printf("initializing wifi\n");
    tcpip_adapter_init();
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    DELAY(1000);

    printf("initializing promiscuous mode\n");
    wifi_promiscuous_filter_t promisc_filter = {
    	.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&promisc_filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_pkt_handler));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    DELAY(1000);

    printf("switching to channel 6\n");
	ESP_ERROR_CHECK(esp_wifi_set_channel(6, 0));

    for (;;) {
    	printf("idle...\n");
    	xSemaphoreTake(pcap_mutex, portMAX_DELAY);
    	if (pcap_done) {
    		printf("pcap is done, stopping wifi\n");
    		ESP_ERROR_CHECK(esp_wifi_stop());
    		DELAY(1000);
    		printf("printing pcap hex\n");
    		for (int i = 0; i < pcap_buf_idx; i++) {
    			printf("%02x", pcap_buf[i]);
    		}
    		printf("waiting forever");
    		fflush(stdout);
    		for (;;) {
    			DELAY(1000);
    		}
    	}
    	xSemaphoreGive(pcap_mutex);
    	DELAY(1000);
    }

    /*
    // init bt
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BTDM));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());
    // init ble
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(ble_handler));

    airpods_data[16] = 23;
    airpods_data[17] = 45;
    airpods_data[18] = 173;
    ESP_ERROR_CHECK(esp_ble_gap_config_adv_data_raw(airpods_data, 31));

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

    for (;;) {
    	printf("advertising\n");
	    ESP_ERROR_CHECK(esp_ble_gap_start_advertising(&adv_params));
    	DELAY(2000);
    	printf("stopping\n");
    	ESP_ERROR_CHECK(esp_ble_gap_stop_advertising());
    	DELAY(2000);
    }
	*/

    // ESP_ERROR_CHECK(esp_ble_gap_stop(&adv_params));

    // scan
    /*
    esp_ble_scan_params_t scan_params = {
    	.scan_type = BLE_SCAN_TYPE_ACTIVE,
    	.own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    	.scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    	.scan_interval = 0x50,
    	.scan_window = 0x30,
    };
    ESP_ERROR_CHECK(esp_ble_gap_set_scan_params(&scan_params));
    for (;;) {
	    printf("scanning...");
	    ESP_ERROR_CHECK(esp_ble_gap_start_scanning(5));
	    printf("done");
    	DELAY(1000);
    }
	*/

    // adv airpods


    /*
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    wifi_config_t ap_cfg = {
    	.ap = {
    		.ssid = "esp32-beaconspam",
    		.ssid_len = 0,
    		.password = "dummypassword",
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

    xTaskCreate(&spam_task, "spam_task", 2048, NULL, 5, NULL);
	*/
}
