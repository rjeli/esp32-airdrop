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

    ESP_ERROR_CHECK(nvs_flash_init());
    awdl_init();

    // xTaskCreate(https_task, "https_task", 8192, NULL, 5, NULL);

    for (;;) {
    	printf("idle...\n");
    	DELAY(1000);
    }
}
