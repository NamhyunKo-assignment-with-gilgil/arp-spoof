#pragma once
#include <iostream>
#include <string>
#include <stdint.h>
#include <netinet/in.h>

typedef struct MY_ARP_HEADER{
	uint16_t hardware_type;			/* hardware type 16bit */
	uint16_t protocol_type;			/* protocol type 16bit */
	uint8_t hardware_length;		/* hardware length 8bit */
	uint8_t protocol_length;		/* protocol length 8bit */
	uint16_t operation;				/* operation 16bit */
	uint8_t sender_mac_address[6];	/* sender mac address 48bit */
	uint32_t sender_ip_address;		/* sender ip address 32bit */
	uint8_t target_mac_address[6];	/* target mac address 48bit */
	uint32_t target_ip_address;		/* target ip address 32bit */
} __attribute__((packed)) ARP_HDR; 	/* wireshark로 확인 후 구조체패딩 해제 */

void stringip_to_byteip(const char* str_ip, uint32_t* byte_ip);
void byteip_to_stringip(uint32_t* byte_ip, char* str_ip);