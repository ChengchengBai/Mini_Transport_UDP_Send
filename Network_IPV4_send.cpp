#include "Network_IPV4.h"
#include "Resource.h"
#include "Ethernet.h"
#include "ARP_Cache_Table.h"
#include "Network_ARP.h"

//u_int8_t buffer[MAX_SIZE];

u_int16_t ip_packet_id = 0;//as flag in ip_header->id
u_int32_t ip_size_of_packet = 0;

extern int ethernet_upper_len;
extern u_int8_t broadcast_mac[6];
extern u_int8_t target_mac[6];
extern u_int8_t local_ip[4];
extern u_int8_t target_ip[4];
extern u_int8_t netmask[4];
extern u_int8_t gateway_ip[4];
extern pcap_t *handle;
extern u_int8_t local_mac[6];
extern u_int8_t *destination_ip;
extern u_int8_t * dest_mac;


u_int16_t calculate_check_sum(ip_header *ip_hdr, int len)
{
	int sum = 0, tmp = len;
	u_int16_t *p = (u_int16_t*)ip_hdr;
	while (len > 1)
	{
		sum += *p;
		len -= 2;
		p++;
	}

	//len=1 last one byte
	if (len)
	{
		sum += *((u_int8_t*)ip_hdr + tmp - 1);
	}

	//fold 32 bits to 16 bits
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

void load_ip_header(u_int8_t *ip_buffer)
{
	struct ip_header *ip_hdr = (struct ip_header*)ip_buffer;
	ip_size_of_packet = 0;
	//initial the ip header
	ip_hdr->version_hdrlen = 0x4f;//0100 1111 means ip version4 and header length: 60 bytes
	ip_hdr->type_of_service = 0xfe;/*111 1 1110: first 3 bits: priority level,
								   then 1 bit: delay, 1 bit: throughput, 1 bit: reliability
								   1 bit: routing cost, 1 bit: unused
								   */
	ip_hdr->total_length = 0;// wait for data length, 0 for now
	ip_hdr->id = ip_packet_id;//identification
	ip_hdr->fragment_offset = 0x0000;/*0 0 0 0 00...00: first 3 bits is flag: 1 bit: 0 the last fragment,
									 1 more fragmet. 1 bit: 0 allow fragment, 1 don't fragment. 1 bit: unused
									 the last 12 bits is offset
									 */
	ip_hdr->time_to_live = 64;//default 1000ms
	ip_hdr->upper_protocol_type = IPPROTO_ICMP;
	//ip_hdr->upper_protocol_type =  IPPROTO_IP;//default upper protocol is tcp
	ip_hdr->check_sum = 0;//initial zero

	int i;
	for (i = 0; i < 4; i++)
	{
		ip_hdr->source_ip[i] = local_ip[i];
		ip_hdr->destination_ip[i] = target_ip[i];
	}

	//initial check_sum is associate with offset. so in the data we need to calculate check_sum
	ip_size_of_packet += sizeof(ip_header);
}

void load_ip_data(u_int8_t *ip_buffer, FILE *fp, int len)
{
	int i = 0;
	char ch;
	while (i < len && (ch = fgetc(fp)) != EOF)
	{
		*(ip_buffer + i) = ch;
		i++;
	}
	ip_size_of_packet += len;
}

void load_ip_icmp(u_int8_t *ip_buffer, u_int8_t *buffer, int len)
{
	int i = 0;
	char ch;
	for (i = 0;i<len; i++)
	{
		ch = *(buffer + i);
		*(ip_buffer+i) = ch;
	}

	ip_size_of_packet += len;
}

int is_same_lan(u_int8_t *local_ip, u_int8_t *destination_ip)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		if ((local_ip[i] & netmask[i]) != (destination_ip[i] & netmask[i]))
			return 0;
	}
	return 1;
}

int network_ipv4_send(u_int8_t *buffer, int icmp_size_of_packet)
{
	u_int8_t ip_buffer[MAX_SIZE];
	u_int16_t offset = 0;
	int ip_data_len;
	u_int16_t fragment_offset;

	load_ip_header(ip_buffer);
	struct ip_header *ip_hdr = (struct ip_header *)ip_buffer;
	fragment_offset = 0x0000;//16bits
	ip_data_len = icmp_size_of_packet;
	int number_of_fragment = (int)ceil(icmp_size_of_packet*1.0 / MAX_IP_PACKET_SIZE);

	ip_hdr->fragment_offset = htons(fragment_offset);
	ip_hdr->total_length = htons(ip_data_len + sizeof(ip_header));
	ip_hdr->check_sum = calculate_check_sum(ip_hdr, 60);

	load_ip_icmp(ip_buffer + sizeof(ip_header), buffer, icmp_size_of_packet);

	//check if the target pc mac is in arp_table

	if (is_same_lan(local_ip, ip_hdr->destination_ip))
		destination_ip = ip_hdr->destination_ip;
	else
		destination_ip = gateway_ip;

	u_int8_t *destination_mac = is_existed_ip(destination_ip);

	/*
	//get the size of file
	int file_len;
	fseek(fp, 0, SEEK_END);
	file_len = ftell(fp);
	rewind(fp);

	//get how many fragments
	int number_of_fragment = (int)ceil(file_len*1.0 / MAX_IP_PACKET_SIZE);
	u_int16_t offset = 0;
	int ip_data_len;
	u_int16_t fragment_offset;

	while (number_of_fragment)
	{
		load_ip_header(ip_buffer);
		struct ip_header *ip_hdr = (struct ip_header *)ip_buffer;
		if (number_of_fragment == 1)
		{
			fragment_offset = 0x0000;//16bits
			ip_data_len = file_len - offset;
		}
		else
		{
			fragment_offset = 0x2000;//allow the next fragment
			ip_data_len = MAX_IP_PACKET_SIZE;
		}

		fragment_offset |= ((offset / 8) & 0x0fff);
		ip_hdr->fragment_offset = htons(fragment_offset);

		//printf("%04x\n", ip_hdr->fragment_offset);
		ip_hdr->total_length = htons(ip_data_len + sizeof(ip_header));
		ip_hdr->check_sum = calculate_check_sum(ip_hdr, 60);
		//printf("%04x\n", ip_hdr->check_sum);

		//load_ip_icmp(ip_buffer + sizeof(ip_header), icmp_buffer, icmp_len);
		//load_ip_data(ip_buffer + sizeof(ip_header), fp, ip_data_len);

		//check if the target pc mac is in arp_table

		if (is_same_lan(local_ip, ip_hdr->destination_ip))
			destination_ip = ip_hdr->destination_ip;
		else
			destination_ip = gateway_ip;

		u_int8_t *destination_mac = is_existed_ip(destination_ip);

		if (destination_mac == NULL)
		{
			dest_mac = NULL;
			//check if the target pc and the local host is in the same lan
			network_arp_send(destination_ip, broadcast_mac);
			while (destination_mac == NULL)
			{
				Get_Arp_reply();
				destination_mac = dest_mac;
			}

			//wait for replying, get the destination mac


			struct pcap_pkthdr *pkt_hdr;
			u_int8_t *pkt_content;
			while (pcap_next_ex(handle, &pkt_hdr, (const u_char **)&pkt_content) != 0)
			{
				destination_mac = NULL;
				struct ethernet_header *ethernet_hdr = (struct ethernet_header *)(pkt_content);
				//check if is acceptable packet

				int i;
				for (i = 0; i < 6; i++)
				{
					//if (ethernet_hdr->destination_mac[i] != local_mac[i]) or (ethernet_hdr->destination_mac[i] != oxffffff)
					if (ethernet_hdr->destination_mac[i] != local_mac[i])
						break; // not consider broadcast frame for arp reply
				}
				if (i < 6)continue;

				//no crc

				if (ntohs(ethernet_hdr->ethernet_type) != ETHERNET_ARP)continue;
				destination_mac = network_arp_recv(pkt_content + sizeof(struct ethernet_header));
				if (destination_mac != NULL)
					break;
			}

		}
	}*/

	
		//send the data
		ethernet_upper_len = ip_size_of_packet;//ip packet size
		//ethernet_send_packet(ip_buffer, destination_mac, ETHERNET_IP);
		ethernet_send_packet(ip_buffer, target_mac, ETHERNET_IP);

		
		offset += MAX_IP_PACKET_SIZE;
		number_of_fragment--;

	//fclose(fp);
	//auto increase one
	ip_packet_id++;

	return 1;
}




