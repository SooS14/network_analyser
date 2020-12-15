#ifndef BOOTP_H
#define BOOTP_H

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "header_def.h"



struct bootp_head {
	unsigned char op;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	unsigned int xid;
	unsigned short secs;
	unsigned short flags;
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	unsigned char chaddr[16];
	unsigned char sname[64];
	unsigned char file[128];
	unsigned char vend[64];
};


// BOOTP opcode
#define BOOTP_REQUEST	0x01
#define BOOTP_REPLY		0x02


// DHCP Options
#define SUBNET_MASK     0x01
#define TIME_OFFSET     0x02
#define ROUTER          0x03
#define DNS             0x06
#define HOST_NAME       0x12
#define DOMAIN_NAME     0x15
#define BROADCAST_ADDR  0x28
#define NONS            0x44
#define NOS             0x47
#define REQ_IP_ADDR     0x50
#define LEASE_TIME      0x51
#define DHCP_MESS_TYPE  0x53
#define SERV_ID         0x54
#define PARAM_REQ_LST   0x55
#define CLIENT_ID       0x61


// DHCP Message types (values for TAG_DHCP_MESSAGE option)
#define	DHCP_DISCOVER	0x01
#define DHCP_OFFER	    0x02
#define	DHCP_REQUEST	0x03
#define	DHCP_DECLINE	0x04
#define	DHCP_ACK		0x05
#define	DHCP_NAK		0x06
#define	DHCP_RELEASE    0x07


#endif