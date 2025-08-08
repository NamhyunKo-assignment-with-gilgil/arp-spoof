#include <stdint.h>

typedef struct my_tcp_hdr{	/* tcp_hdr */
    uint16_t th_sport;	/* source port */
    uint16_t th_dport;	/* destination port */
    uint32_t th_seq;	/* sequence number */
    uint32_t th_ack;	/* acknowledgement number */
	uint8_t th_off;	/* data offset & reserved */
    uint8_t th_flags;	/* control flags */
    uint16_t th_win;	/* window */
    uint16_t th_sum;	/* checksum */
    uint16_t th_urp;	/* urgent pointer */
} Tcp_HDR;