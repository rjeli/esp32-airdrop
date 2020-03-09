#include <stdio.h>
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/ip_addr.h"

#include "utils.h"

mac_t 
mac_from_bytes(uint8_t *src)
{
	mac_t mac;
	memcpy(mac.addr, src, 6);
	return mac;
}

void 
print_mac(mac_t mac)
{
	uint8_t *addr = mac.addr;
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

int64_t
wrap_mac(mac_t mac)
{
	int64_t x = 0;
	memcpy(&x, mac.addr, 6);
	return x;
}

mac_t
unwrap_mac(int64_t x)
{
	mac_t mac;
	memcpy(mac.addr, &x, 6);
	return mac;
}

ip_addr_t 
mac_to_ip(mac_t mac, int zone)
{
	uint8_t *hwaddr = mac.addr;
	char addrbuf[128];
	sprintf(addrbuf, "fe80::%02x%02x:%02xff:fe%02x:%02x%02x",
		hwaddr[0]^0x2, hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	printf("converted to %s\n", addrbuf);
	ip_addr_t ipaddr;
	ipaddr_aton(addrbuf, &ipaddr);
	ip6_addr_set_zone(ip_2_ip6(&ipaddr), zone);
	return ipaddr;
}

void
ip6_to_mac(const ip6_addr_t *ip6addr, mac_t *mac)
{
	uint8_t *hwaddr = mac->addr;
	hwaddr[0] = (IP6_ADDR_BLOCK5(ip6addr) >> 8) ^ 0x2;
	hwaddr[1] = IP6_ADDR_BLOCK5(ip6addr) & 0xff;
	hwaddr[2] = IP6_ADDR_BLOCK6(ip6addr) >> 8;
	hwaddr[3] = IP6_ADDR_BLOCK7(ip6addr) & 0xff;
	hwaddr[4] = IP6_ADDR_BLOCK8(ip6addr) >> 8;
	hwaddr[5] = IP6_ADDR_BLOCK8(ip6addr) & 0xff;
}

void
running_stats_init(running_stats_t *rs, int n)
{
	rs->vals = malloc(n*sizeof(rs->vals[0]));
	rs->pos = 0;
	rs->cap = n;
	rs->mtx = xSemaphoreCreateMutex();
	for (int i = 0; i < n; i++) {
		rs->vals[i] = 0;
	}
}

void
running_stats_update(running_stats_t *rs, int64_t val)
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


