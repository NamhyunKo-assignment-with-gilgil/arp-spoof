#pragma once
#include <stdio.h>
#include <stdint.h>

typedef struct my_ipv4_hdr {	/* ipv4_hdr */
    uint8_t ip_v_n_hl;	/* version & IHL(header length) */
    uint8_t ip_tos;	/* TOS(type of service) */
    uint16_t ip_len;	/* total length */
    uint16_t ip_id;	/* identification */
    uint16_t ip_off;	/* flags & fragment offset */
    uint8_t ip_ttl;	/* TTL(time to live) */
    uint8_t ip_p;	/* protocol */
    uint16_t ip_sum;	/* header checksum */
    uint32_t ip_src, ip_dst;	/* source & dest address */
} IPV4_HDR;

void stringip_to_byteip(const char* str_ip, uint32_t* byte_ip);
void byteip_to_stringip(uint32_t* byte_ip, char* str_ip);
void print_ipv4(IPV4_HDR* ip);