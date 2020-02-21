#include <stdio.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "utils.h"

void 
print_mac(uint8_t *addr)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}


void
running_stats_init(running_stats_t *rs, int n)
{
	rs->vals = malloc(n*sizeof(int32_t));
	rs->pos = 0;
	rs->cap = n;
	rs->mtx = xSemaphoreCreateMutex();
	for (int i = 0; i < n; i++) {
		rs->vals[i] = 0;
	}
}

void
running_stats_update(running_stats_t *rs, int32_t val)
{
	xSemaphoreTake(rs->mtx, portMAX_DELAY);
	rs->vals[rs->pos] = val;
	rs->pos = (rs->pos+1) % rs->cap;
	xSemaphoreGive(rs->mtx);
}

void
running_stats_calc(running_stats_t *rs, float *mean, float *stdev)
{
	xSemaphoreTake(rs->mtx, portMAX_DELAY);
	float sum = 0;
	for (int i = 0; i < rs->cap; i++) {
		sum += rs->vals[i];
	}
	*mean = sum / rs->cap;
	float sumsqerr = 0;
	for (int i = 0; i < rs->cap; i++) {
		float err = rs->vals[i] - *mean;
		sumsqerr += err*err;
	}
	*stdev = sqrt(sumsqerr/rs->cap);
	xSemaphoreGive(rs->mtx);
}


