#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_spi_flash.h"
#include "esp_tls.h"
#include "nvs_flash.h"

#include "lwip/dns.h"

#include "macros.h"
#include "awdlif.h"

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

uint8_t airdrop_ble_data[] = {
	0x02, 0x01, 0x1b, 0x17,
	0xff, 0x4c, 0x00, 0x05, // swap apple bytes?
	0x12, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x00,
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

#define PCAP_BUF_SZ (64*1024)
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

// #define WEB_URL "https://19f574e3714b._airdrop._tcp.local"
#define HOSTNAME "19f574e3714b._airdrop._tcp.local"

void
https_task(void *params)
{
	while (1) {
		esp_tls_cfg_t cfg = {
			.skip_common_name = true,
		};
		printf("connecting tls\n");
		esp_tls_t *tls = esp_tls_init();
		int ret = esp_tls_conn_new_sync(HOSTNAME, sizeof(HOSTNAME), 443, &cfg, tls);
		if (ret == -1) {
			printf("conn failed\n");
		} else if (ret == 1) {
			printf("conn succeeded\n");
		}
		DELAY(1000);
	}
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

    // init awdl
    awdl_init();
    DELAY(100);

    /*
	printf("adding dns\n");
	char *addrbuf = "fe80::1234:5678";
	static ip_addr_t ipaddr;
	ipaddr_aton(addrbuf, &ipaddr);
	dns_local_addhost(HOSTNAME, &ipaddr);
	*/

    xTaskCreate(https_task, "https_task", 8192, NULL, 5, NULL);

    // init bt
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
    // ESP_ERROR_CHECK(esp_ble_gap_start_advertising(&adv_params));

    for (;;) {
    	printf("idle...\n");
    	xSemaphoreTake(pcap_mutex, portMAX_DELAY);
    	if (pcap_done) {
    		printf("pcap is done, stopping wifi\n");
    		// ESP_ERROR_CHECK(esp_wifi_stop());
    		DELAY(1000);
    		printf("printing pcap hex\n");
    		for (int i = 0; i < pcap_buf_idx; i++) {
    			printf("%02x", pcap_buf[i]);
    			if (i % 1024 == 0) {
    				vTaskDelay(0); // so the watchdog is happy?
    			}
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
}
