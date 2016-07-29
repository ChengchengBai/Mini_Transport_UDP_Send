#include "Network_IPV4.h"
#include "Network_ICMP.h"
#include "Resource.h"
#include "Transport_UDP.h"


#define MAX_DATA_SIZE 1000000
u_int16_t ip_id = 0;
u_int16_t i = 0;

u_int8_t data_buffer[MAX_DATA_SIZE];

int previous = 0, current = 0;

extern u_int8_t local_ip[4];



/*
if allow fragment, store to buffer until not allow, then
store to file.
*/

int is_accept_ip_packet(struct ip_header *ip_hdr)
{
	int i;
	int flag = 0;
	for (i = 0; i < 4; i++)
	{
		if (ip_hdr->destination_ip[i] != local_ip[i])break;
	}

	if (i == 4)
	{
		flag = 1;
	//	printf("It's sended to my IP.\n");
	}

	for (i = 0; i < 4; i++)
	{
		if (ip_hdr->destination_ip[i] != 0xff)break;
	}
	if (i == 4)
	{
		//flag = 1;			//这里设置为不接收广播，调试用
	//	printf("It's broadcast IP.\n");
	}

	if (!flag)
		return 0;

	u_int16_t check_sum = calculate_check_sum(ip_hdr, 60);
	if (check_sum == 0xffff || check_sum == 0x0000)
	{
//		printf("No error in ip_header.\n");
	}
	else
	{
		//printf("Error in ip_header\n");
		return 0;
	}

}

void load_data_to_buffer(u_int8_t *buffer, u_int8_t *ip_data, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(ip_data + i);
	}
}

int load_data_to_file(u_int8_t *buffer, int len, FILE *fp)
{
	int res = fwrite(buffer, sizeof(u_int8_t), len, fp);
	if (res != len)
	{
		printf("Write file error!\n");
		return 0;
	}
	fflush(fp);
	return 1;
}


int network_ipv4_recv(u_int8_t *ip_buffer)
{
	struct ip_header *ip_hdr = (struct ip_header *)ip_buffer;
	int len = ntohs(ip_hdr->total_length) - sizeof(ip_header);

	unsigned char length_ip_hdr = ip_hdr->version_hdrlen << 4;
	length_ip_hdr = (length_ip_hdr >> 4) * 4;

	//check the valid
	if (!is_accept_ip_packet(ip_hdr))
	{
		return 0;
	}

	u_int16_t fragment;
	fragment = ntohs(ip_hdr->fragment_offset);

	int dural = 0;
	if (previous == 0)
	{
		previous = time(NULL);
	}
	else
	{
		//get current time
		current = time(NULL);
		dural = current - previous;
		printf("%d %d\n", current, previous);
		//current time became previous
		previous = current;
	}

	//interval can not larger than 30s
	if (dural >= 30)
	{
		printf("Time Elapsed.\n");
		return 0;
	}

	if ((fragment & 0x2000) && (ip_id == ip_hdr->id))//true means more fragment
	{
		load_data_to_buffer(data_buffer + i, ip_buffer + sizeof(ip_header), len);
		i += len;
		return 1;
	}
	else if (ip_id == ip_hdr->id)
	{
		load_data_to_buffer(data_buffer + i, ip_buffer + sizeof(ip_header), len);
		i += len;
		FILE *fp = fopen("data.txt", "w");
		if (load_data_to_file(data_buffer, i, fp))
		{
			printf("Load to file Succeed.\n");
		}
		fclose(fp);
		//restore the value
		i = 0;
		ip_id++;
	}
	else
	{
		printf("Lost packets.\n");
		//pass the last fragment make move
		i = 0;
		ip_id++;
		return 0;
	}

	printf("--------------IP Protocol-------------------\n");
	printf("IP version: %d\n", (ip_hdr->version_hdrlen & 0xf0));
	printf("Type of service: %02x\n", ip_hdr->type_of_service);
	printf("IP packet length: %d\n", len + sizeof(ip_header));
	printf("IP identification: %d\n", ip_hdr->id);
	printf("IP fragment & offset: %04x\n", ntohs(ip_hdr->fragment_offset));
	printf("IP time to live: %d\n", ip_hdr->time_to_live);
	printf("Upper protocol type: %02x\n", ip_hdr->upper_protocol_type);
	printf("Check sum: %04x\n", ip_hdr->check_sum);
	printf("Source IP: ");
	int i;
	for (i = 0; i < 4; i++)
	{
		if (i)printf(".");
		printf("%d", ip_hdr->source_ip[i]);
	}
	printf("\nDestination IP: ");
	for (i = 0; i < 4; i++)
	{
		if (i)printf(".");
		printf("%d", ip_hdr->destination_ip[i]);
	}
	printf("\n");



	u_int8_t upper_protocol_type = ip_hdr->upper_protocol_type;
	switch (upper_protocol_type)
	{
	case IPPROTO_ICMP:
		network_icmp_recv(data_buffer);
	case IPPROTO_TCP:
		transport_tcp_recv(data_buffer + 60, htons(ip_hdr->total_length) - 60);
		break;
	case IPPROTO_UDP:
		printf("Put into UDP!\n");
		struct sock_addr Servaddr;
		binds(Servaddr);
		network_udp_recv(Servaddr,(data_buffer+length_ip_hdr),ip_hdr->total_length-length_ip_hdr,1,ip_hdr->source_ip,4);
		break;
	}

	printf("-----------------End of IP Protocol---------------\n");
	return 1;
}