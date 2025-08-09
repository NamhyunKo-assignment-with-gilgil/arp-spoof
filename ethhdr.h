#pragma once
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

typedef struct MY_ETHERNET_HEADER{	/* ethernet_hdr total 14bytes */
    uint8_t  ether_dhost[6];	/* destination ethernet address */
    uint8_t  ether_shost[6];	/* source ethernet address */
    uint16_t ether_type;	/* protocol */
} ETHERNET_HDR;

void stringmac_to_bytemac(const char* str_mac, uint8_t* byte_mac);
void bytemac_to_stringmac(uint8_t* byte_mac, char* str_mac);
void print_ethernet(ETHERNET_HDR* ethernet);