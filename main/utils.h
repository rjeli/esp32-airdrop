typedef struct {
	uint8_t addr[6];
} mac_t;

#define MAC(a,b,c,d,e,f) ((mac_t) { .addr = { a, b, c, d, e, f } })
#define NULL_MAC ((mac_t) { .addr = { 0, 0, 0, 0, 0, 0 } })

mac_t mac_from_bytes(uint8_t *src);

int64_t wrap_mac(mac_t mac);
mac_t unwrap_mac(int64_t x);
void print_mac(mac_t mac);

ip_addr_t mac_to_ip(mac_t mac, int zone);
void ip6_to_mac(const ip6_addr_t *ip6addr, mac_t *mac);

typedef struct {
	int64_t *vals;
	int pos, cap;
	SemaphoreHandle_t mtx;

	int64_t recent_awc_seqnum;
} running_stats_t;

void running_stats_init(running_stats_t *rs, int n);
void running_stats_update(running_stats_t *rs, int64_t val);
void running_stats_calc(running_stats_t *rs, float *mean, float *stdev);

