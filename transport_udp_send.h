
#include "Header_Include.h"
#include <process.h>

struct address
{
	u_int8_t ip[4];
	u_int16_t port;
};

struct udp_header
{
	u_int8_t sour_ip[4];
	u_int8_t dst_ip[4];
	u_int8_t zero;
	u_int8_t type;  // 0: 表示TCP= SOCK_STREAM;  1: 表示udp= SOCK_DGRAM;
	u_int16_t udp_len1;
	u_int16_t sour_port;
	u_int16_t dst_port;
	u_int16_t udp_len2;
	u_int16_t check_sum;
};

int Socket(int af, int type, int protocol);

int init(address dest);

void load_udp_header(udp_header * hdr, int buflen);

void load_udp_data(u_int8_t* udp_buf, u_int8_t * buf, int buflen);

u_int16_t udp_check_sum(u_int8_t *udp_hdr, int len);

int network_udp_send(int sockid, u_int8_t * buf, int buflen, int flags, address destadd, int addrlen);






