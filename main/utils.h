void print_mac(uint8_t *addr);

typedef struct {
	int32_t *vals;
	int pos, cap;
	SemaphoreHandle_t mtx;
} running_stats_t ;

void running_stats_init(running_stats_t *rs, int n);
void running_stats_update(running_stats_t *rs, int32_t val);
void running_stats_calc(running_stats_t *rs, float *mean, float *stdev);

