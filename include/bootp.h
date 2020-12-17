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
#define BOOTP_REQUEST	1
#define BOOTP_REPLY		2


// DHCP Options
#define DHCP_SUBNET_MASK     1
#define DHCP_TIME_OFFSET     2
#define DHCP_ROUTER          3
#define DHCP_DNS             6
#define DHCP_HOST_NAME       12
#define DHCP_DOMAIN_NAME     15
#define DHCP_BROADCAST_ADDR  28
#define DHCP_NONS            44
#define DHCP_NOS             47
#define DHCP_REQ_IP_ADDR     50
#define DHCP_LEASE_TIME      51
#define DHCP_DHCP_MESS_TYPE  53
#define DHCP_SERV_ID         54
#define DHCP_PARAM_REQ_LST   55
#define DHCP_CLIENT_ID       61
#define DHCP_END            255

// DHCP Message types (values for TAG_DHCP_MESSAGE option)
#define	DHCP_DISCOVER	1
#define DHCP_OFFER	    2
#define	DHCP_REQUEST	3
#define	DHCP_DECLINE	4
#define	DHCP_ACK		5
#define	DHCP_NAK		6
#define	DHCP_RELEASE    7

//DHCP Parameters request list
#define DHCP_REQ_SUBNET_MSK     1
#define DHCP_REQ_DOMAIN_NAME    15
#define DHCP_REQ_ROUTER         3
#define DHCP_REQ_NONS           44
#define DHCP_REQ_NNT            46
#define DHCP_REQ_NOS            47
#define DHCP_REQ_DNS            6



#endif