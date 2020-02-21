ESP_EVENT_DECLARE_BASE(AWDL_EVENT);
enum {
	AWDL_FOUND_AIRDROP,
};

typedef struct {
	char hostname[256];
	uint16_t port;
} awdl_airdrop_addr_t;

esp_event_loop_handle_t awdl_init();
