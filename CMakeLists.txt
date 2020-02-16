cmake_minimum_required(VERSION 3.5)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32airdrop)

target_compile_options(__idf_lwip PRIVATE
-include ${CMAKE_SOURCE_DIR}/lwip_injected_header.h
)

target_compile_definitions(__idf_lwip PUBLIC
# DNS_LOCAL_HOSTLIST=1 
# DNS_LOCAL_HOSTLIST_IS_DYNAMIC=1
# "DNS_LOCAL_HOSTLIST_INIT=\{\}"
# "DNS_LOOKUP_LOCAL_EXTERN(n,a,t)=awdl_dns_lookup(n,a,t)"
)