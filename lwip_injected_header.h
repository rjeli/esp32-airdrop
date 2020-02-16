#include "lwip/netif.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"

extern err_t awdl_dns_lookup(const char *name, ip_addr_t *addr, u8_t dns_addrtype);
#define DNS_LOOKUP_LOCAL_EXTERN(n,a,t) awdl_dns_lookup(n,a,t)
