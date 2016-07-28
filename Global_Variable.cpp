#include "Header_Include.h"

u_int8_t local_mac[6] = { 0xa0, 0x48, 0x1c, 0x0f, 0xf8, 0xa4 };
u_int8_t local_ip[4] = { 10, 20, 4, 39 };
u_int8_t gateway_ip[4] = { 10, 21, 4, 1 };
//u_int8_t local_mac[6] = { 0x44, 0x37, 0xE6, 0x8D, 0x32, 0x6B };
//u_int8_t local_ip[4] = { 10, 13, 83, 42 };
//u_int8_t gateway_ip[4] = { 10, 13, 83, 1 };
u_int8_t netmask[4] = { 255, 255, 255, 0 };
u_int8_t dns_server_ip[4] = { 61, 134, 1, 4 };
u_int8_t dhcp_server_ip[4] = { 222, 24, 192, 2 };
u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

//pcap_t *handle; 
int ethernet_upper_len;
u_int8_t target_ip[4] = { 10, 20, 4, 39 };
//u_int8_t target_ip[4] = { 10, 13, 83, 42 };
u_int8_t target_mac[6] = { 0xa0, 0x48, 0x1c, 0x0f, 0xf8, 0xa4 };

u_int8_t *destination_ip;

//ÐÂÔö
u_int8_t * dest_mac;
char *device;

//tcp
//u_int16_t source_port = htons(6000);
u_int16_t sever_port = htons(6000);
u_int8_t sever_ip[4] = { 10, 20, 4, 39 };
u_int16_t local_port;

int TCP_ACK;
int C_SEQ;
int S_SEQ;
int WINDOW;
int TCP_RECV_TYPE;
int ACK_NUM;
int MSS = 200;
