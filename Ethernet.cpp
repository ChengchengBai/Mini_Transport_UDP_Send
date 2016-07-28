#include "Ethernet.h"
#include "Resource.h"
#include "Network_IPV4.h"
#include "Network_ARP.h"

u_int32_t crc32_table[256] = { 0 };
u_int32_t size_of_packet = 0;

u_int8_t buffer[MAX_SIZE];
extern pcap_t *handle;
extern u_int8_t local_mac[6];
extern int ethernet_upper_len;
extern u_int8_t * dest_mac;

void generate_crc32_table()
{
	int i, j;
	u_int32_t crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

u_int32_t calculate_crc(u_int8_t *buffer, int len)
{
	int i;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}


void load_ethernet_header(u_int8_t *destination_mac,u_int16_t ethernet_type)
{
	struct ethernet_header *hdr = (struct ethernet_header *)buffer;
	size_of_packet = 0;
	// add destination mac address
	hdr->destination_mac[0] = destination_mac[0];
	hdr->destination_mac[1] = destination_mac[1];
	hdr->destination_mac[2] = destination_mac[2];
	hdr->destination_mac[3] = destination_mac[3];
	hdr->destination_mac[4] = destination_mac[4];
	hdr->destination_mac[5] = destination_mac[5];

	//add source mac address
	hdr->source_mac[0] = local_mac[0];
	hdr->source_mac[1] = local_mac[1];
	hdr->source_mac[2] = local_mac[2];
	hdr->source_mac[3] = local_mac[3];
	hdr->source_mac[4] = local_mac[4];
	hdr->source_mac[5] = local_mac[5];

	// add source typy
	hdr->ethernet_type = htons(ethernet_type);

	// caculate the size of packet now
	size_of_packet += sizeof(ethernet_header);
}

int load_ethernet_data(u_int8_t *buffer, u_int8_t *upper_buffer, int len)
{
	if (len > 1500)
	{
		printf("IP buffer is too large. So we stop the procedure.");
		return -1;
	}

	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(upper_buffer + i);
	}

	//add a serial 0 at the end
	while (len < 46)
	{
		*(buffer + len) = 0;
		len++;
	}
    
    //generate_crc32_table();
	u_int32_t crc = calculate_crc(buffer - sizeof( ethernet_header), len + sizeof(struct ethernet_header));

	*(u_int32_t *)(buffer + len) = crc;
	size_of_packet += len + 4;
	return 1;
}

int ethernet_send_packet(u_int8_t *upper_buffer,u_int8_t *destination_mac,u_int16_t ethernet_type)
{
	load_ethernet_header(destination_mac, ethernet_type);
	load_ethernet_data(buffer + sizeof(struct ethernet_header), upper_buffer, ethernet_upper_len);

	if (pcap_sendpacket(handle, (const u_char *)buffer, size_of_packet) != 0)
	{
		printf("Sending failed..\n");
		return -1;
	}
	else
	{
		printf("Sending Succeed..\n");
		return 1;
	}
}


void open_device()
{
	extern  char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	/*device = pcap_lookupdev(error_buffer);
	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);*/


	//pcap_t *adhandle;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	int inum;


	// get the all network adapter handle 

	if (pcap_findalldevs(&alldevs, error_buffer) == -1)
	{
		printf("%s\n", error_buffer);
		return ;
	}


	/* Print the list of all network adapter information */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return ;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);



	/* Open the adapter */
	if ((handle = pcap_open_live(d->name, // name of the device
		65536, // portion of the packet to capture.65536 grants that the whole packet will be captured on/// all the MACs.
		1, // promiscuous mode
		1000, // read timeout
		error_buffer // error buffer
		)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ;
	}


	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ;
	}

	//handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);

	generate_crc32_table();
}
void close_device()
{
	pcap_close(handle);
}



//新增  for ethernet_recv
int is_accept_ethernet_packet(u_int8_t *packet_content, int len)
{
	struct ethernet_header *ethernet_hdr = (struct ethernet_header *)packet_content;
	int i;
	int flag = 0;
	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != 0xff)break;
	}

	if (i == 6)
	{
	//	flag = 1;		//设置为不接受广播
//		printf("It's broadcast packet.\n");
		return 0;
	}

	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != local_mac[i])break;
	}

	if (i == 6)
	{
		flag = 1;
//		printf("It's sended to my pc.\n");
	}
	if (!flag)
		return 0;

	//generate_crc32_table();
	//crc match
	u_int32_t crc = calculate_crc((u_int8_t *)packet_content , len - 4 );
	if (crc != *((u_int32_t *)(packet_content + len - 4)))
	{
	//	printf("The data has changed.\n");
		//return 0;
	}
	return 1;
}

//新增   接收数据帧
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	int len = packet_header->len;
	if (!is_accept_ethernet_packet((u_int8_t *)packet_content, len))
	{
		return;
	}

	struct ethernet_header *ethernet_hdr = (struct ethernet_header *)packet_content;
	u_int16_t ethernet_type = ntohs(ethernet_hdr->ethernet_type);


	/*printf("Capture %d packet\n", packet_number++);
	printf("Capture time: %d %d\n", packet_header->ts.tv_sec, packet_header->ts.tv_usec);
	//output_time(packet_header->ts.tv_sec);
	printf("Packet length: %d\n", packet_header->len);

	printf("--------------------------Ethernet Protocol------------------------\n");
	printf("Ethernet type:  %04x\n", ethernet_type);
	printf("MAC source address: ");
	output_mac(ethernet_hdr->source_mac);
	printf("MAC destination address: ");
	output_mac(ethernet_hdr->destination_mac);*/

	u_int8_t *upper_buffer = (u_int8_t *)(packet_content + sizeof(ethernet_header));

	switch (ethernet_type)
	{
	case 0x0800:
	//	printf("Upper layer protocol: IPV4\n");
		network_ipv4_recv(upper_buffer);
		break;
	case 0x0806:
//		printf("Upper layer protocol: ARP\n");

		//int is_accept_arp_packet(struct arp_pkt *arp_packet)
		//printf("arp_reply frame accepted!\n");
		dest_mac =  network_arp_recv(upper_buffer);
	
		break;
	case 0x8035:
	//	printf("Upper layer protocol: RARP\n");
		//network_rarp_recv();
		break;
	case 0x814c:
	//	printf("Upper layer protocol: SNMP\n");
		//network_snmp_recv();
		break;
	case 0x8137:
		printf("Upper layer protocol: IPX(Internet Packet Exchange)\n");
		//network_ipx_recv();
		break;
	case 0x86DD:
		printf("Upper layer protocol: IPV6\n");
		//network_ipv6_recv();
		break;
	case 0x880B:
		printf("Upper layer protocol: PPP\n");
		//network_ppp_recv();
		break;
	default:break;
	}
	//printf("-------------------End of Ethernet Protocol----------------\n");
}

