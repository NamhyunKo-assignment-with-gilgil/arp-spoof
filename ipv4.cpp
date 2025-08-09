#include "ipv4.h"

void stringip_to_byteip(const char* str_ip, uint32_t* byte_ip){
    uint32_t b_ip[4];
	sscanf(str_ip,
        "%u.%u.%u.%u",
        &b_ip[3], &b_ip[2], &b_ip[1], &b_ip[0]
    );
    b_ip[0] = b_ip[0] << 24;
    b_ip[1] = b_ip[1] << 16;
    b_ip[2] = b_ip[2] << 8;
    b_ip[3] = b_ip[3];
    *byte_ip = b_ip[0] | b_ip[1] | b_ip[2] | b_ip[3];
}

void byteip_to_stringip(uint32_t* byte_ip, char* str_ip){
    sprintf(str_ip,
        "%u.%u.%u.%u",
        *byte_ip & 0xFF,
        (*byte_ip >> 8) & 0xFF,
        (*byte_ip >> 16) & 0xFF,
        (*byte_ip >> 24) & 0xFF
    );
}

void print_ipv4(IPV4_HDR* ip){
    printf("[Ipv4]\n");

    printf("DST IP : ");
    char dst_ip[16];
    byteip_to_stringip(&(ip->ip_dst), dst_ip);
    printf("%s\n", dst_ip);

    printf("SRC IP : ");
    char src_ip[16];
    byteip_to_stringip(&(ip->ip_src), src_ip);
    printf("%s\n", src_ip);

    printf("Protocol : %02x\n", ip->ip_p);
}