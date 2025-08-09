#include "ethhdr.h"

void stringmac_to_bytemac(const char* str_mac, uint8_t* byte_mac){
    sscanf(str_mac,
        "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
        &byte_mac[0], &byte_mac[1], &byte_mac[2], &byte_mac[3], &byte_mac[4], &byte_mac[5]
    );
}

void bytemac_to_stringmac(uint8_t* byte_mac, char* str_mac){
    sprintf(str_mac,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        byte_mac[0], byte_mac[1], byte_mac[2], byte_mac[3], byte_mac[4], byte_mac[5]
    );
}

void print_ethernet(ETHERNET_HDR* ethernet){
    char dst_mac[18], src_mac[18];
    bytemac_to_stringmac(ethernet->ether_dhost, dst_mac);
    bytemac_to_stringmac(ethernet->ether_shost, src_mac);

    printf("[Ethernet]\n");
    printf("DST MAC : %s \n", dst_mac);
    printf("SRC MAC : %s \n", src_mac);
    printf("Protocol : %04x\n", ntohs(ethernet->ether_type));
}