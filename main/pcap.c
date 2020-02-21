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
