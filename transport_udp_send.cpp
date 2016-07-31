#include"transport_udp_send.h"
#include"Network_IPV4.h"
#include "Resource.h"

int AF;
int TYPE;
int Protocol;
address server;

int Socket(int af, int type, int protocol)
{
	AF = af;
	TYPE = type;
	Protocol = protocol;
	return getpid(); //返回当前进程号
}

int init(address dest)
{

	int i = 0;
	for (i = 0; i<4; ++i)
	{
		server.ip[i] = dest.ip[i];
	}
	server.port = dest.port;
	return 1;
}

void load_udp_header(udp_header * hdr, int buflen)
{
	extern u_int8_t local_ip[4];
	extern u_int16_t source_port;
	int i = 0;
	for (i = 0; i<4; ++i)
	{
		hdr->sour_ip[i] = local_ip[i];
	}
	for (i = 0; i<4; ++i)
	{
		hdr->dst_ip[i] = server.ip[i];
	}
	hdr->zero = 0;
	hdr->type = 17;
	hdr->udp_len1 = htons(buflen + 8);//只包括数据和首部长度
	hdr->sour_port = source_port;
	hdr->dst_port = server.port;
	hdr->udp_len2 = hdr->udp_len1;
	hdr->check_sum = 0;
}

void load_udp_data(u_int8_t* udp_buf, u_int8_t * buf, int buflen)
{
	int i = 0;
	for (i = 0; i<buflen; ++i)
	{
		*(udp_buf + sizeof(udp_header) + i) = buf[i];    
	}
}

u_int16_t udp_check_sum(u_int8_t *udp_hdr, int len)
{
	int sum = 0, tmp = len;
	u_int16_t *p = (u_int16_t*)udp_hdr;
	while (len > 1)
	{
		sum += *p;
		len -= 2;
		p++;
	}

	//len=1 last one byte
	if (len)
	{
		sum += *((u_int8_t*)udp_hdr + tmp - 1);
	}

	//fold 32 bits to 16 bits
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}



int network_udp_send(int sockid, u_int8_t * buf, int buflen, int flags, address destadd, int addrlen)
{
	int total_len;
	init(destadd);
	u_int8_t udp_buf[65535] = { 0 };
	udp_header* hdr = (udp_header *)udp_buf;
	load_udp_header(hdr, buflen);
	load_udp_data(udp_buf, buf, buflen);
	total_len = buflen + sizeof(udp_header);
	hdr->check_sum = udp_check_sum(udp_buf, total_len);
	network_ipv4_send(udp_buf + 12, total_len - 12, IPPROTO_UDP);
	return 1;
}





