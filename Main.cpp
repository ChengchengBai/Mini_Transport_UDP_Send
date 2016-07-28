#include "ARP_Cache_Table.h"
#include "Network_ARP.h "
#include "Resource.h"
#include "Header_Include.h"
#include "Network_ICMP.h"
#include "Transport_TCP.h"

//u_int8_t ip_buffer[MAX_SIZE];
//u_int8_t icmp_buffer[MAX_SIZE];
pcap_t *handle;


int main()
{
	struct tcp_socket *sockid;
	extern int TCP_RECV_TYPE;

	init_arp_table();
//	output_arp_table();

	open_device();
	u_int8_t test[1200] = { 0 };
	sockid = tcp_sock(1, 1, IPPROTO_IP);
	tcp_adr dest;
	extern u_int8_t sever_ip[4];
	extern u_int16_t sever_port;
	int i = 0;
	for (i = 0; i<4; ++i)
	{
		dest.ip[i] = sever_ip[i];
	}
	dest.port = sever_port;

	srand(time(0));
	sockid->c_seq = rand();

	//建立TCP连接
	while (tcp_connect(sockid, &dest, sizeof(tcp_adr)) == -1);
	sockid->c_seq++;
	while (tcp_send_ack_wait(sockid) == -1);

	printf("************************************************************************************");
	FILE *fp;
	int len;
	fp = fopen("test.txt", "rb+");
	if (fp == NULL)
	{
		printf("open file fail\n");
		return 0;
	}
	while (1)
	{
		if ((len = fread(test, 1, 1200, fp))<1200)
		{
			tcp_send_buffer((char*)test, len, sockid);
			break;
		}
		else
		{
			tcp_send_buffer((char*)test, len, sockid);
		}
	}
	printf("************************************************************************************");
	//断开连接
	tcp_send_fin_wait(sockid);
	sockid->c_seq++;
	while (true)
	{
		Get_Tcp_recv();
		if (TCP_RECV_TYPE == 2)
			break;
	}
	while (tcp_send_ack_wait(sockid) == -1);
	close_device();
	printf("%d", sockid->c_seq);
	printf("**************************************************************************************");
	return 0;
}