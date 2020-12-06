#ifndef HEADER_DEF_H
#define HEADER_DEF_H

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define ADDR_LEN_ETHER 6
#define SIZE_ETHER 14

// ethernet data type 
#define DT_IP 0x08			//TRES BIZARRE A VOIR -> il manque le dernier octet à data_type
#define DT_ARP 0x0806
#define DT_RARP 0x0835 


// macros used to set appart the IP header lenght from the IP version
#define VER(ip)			(((ip)->ver_hdlen) >> 4)
#define HDLEN(ip)		(((ip)->ver_hdlen) & 0b00001111)


// IP protocols
#define TCP 0x06
#define UDP 0x11


//macro used to separate data offset from reserved informations
#define D_OFF(tcp)	(((tcp)->d_off & 0b11110000) >> 4)

//TCP flags
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PUSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
#define FLAGS (FIN|SYN|RST|ACK|URG|ECE|CWR)



/* Struct representing an ethernet header */
struct ethernet_head {
	unsigned char dst[ADDR_LEN_ETHER];
	unsigned char src[ADDR_LEN_ETHER]; 
	unsigned short data_type; 
};



/* Struct representing an IP header */
struct ip_head {
	unsigned char ver_hdlen;		//version << 4 ; header length >> 2
	unsigned char ToS;
	unsigned short tot_len;
	unsigned short ident;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short chk_sum;
	struct in_addr src;
	struct in_addr dst;
};



/* Struct representing a TCP header */
struct tcp_head {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned char d_off;			// to get data offset use the macro D_OFF
	unsigned char tcp_flags;
	unsigned short window;
	unsigned short chk_sum;
	unsigned short ugent_ptr;
};


/* Struct representing a UDP header */
struct udp_head {
	unsigned short src_port;
	unsigned short dst_port;
    unsigned short len;
	unsigned short chk_sum;
};


void ethernet_pkt(u_char *verbose, const struct pcap_pkthdr *header, const u_char *packet);

int ip_pkt(u_char * verbose, const u_char *packet);

int tcp_pkt(u_char * verbose, const u_char *packet);

void udp_pkt(u_char * verbose, const u_char *packet);



#endif 