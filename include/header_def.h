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
#define DT_IP 0x0800			
#define DT_ARP 0x0806
#define DT_RARP 0x0835 


// macros used to set appart the IP header lenght from the IP version
#define VER(ip)			(((ip)->ver_hdlen) >> 4)
#define HDLEN(ip)		(((ip)->ver_hdlen) & 0b00001111)
#define FRAG_OFF(ip)    (ntohs((ip)->flags_frag_off) & 0b0000111111111111)        
#define IP_FLAGS(ip)    ((ntohs((ip)->flags_frag_off) & 0b1111000000000000))


// IP protocols
#define PROT_TCP 0x06
#define PROT_UDP 0x11


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


//ARP protocol type
#define TYPE_IPv4 	0x0800
#define TYPE_IPv6 	0x86dd

//Application protocol's designated port
//tcp
#define PORT_DNS	    53
#define PORT_FTP	    21
#define PORT_HTTP 	    80
#define PORT_POP	    110
#define PORT_IMAP	    143
#define PORT_SMTP	    25

//udp
#define PORT_BOOTP_C	67
#define PORT_BOOTP_S	68





// Struct representing an ethernet header
struct ethernet_head {
	unsigned char dst[ADDR_LEN_ETHER];
	unsigned char src[ADDR_LEN_ETHER]; 
	unsigned short data_type;
};



// Struct representing an IP header
struct ip_head {
	unsigned char ver_hdlen;
	unsigned char ToS;
	unsigned short tot_len;
	unsigned short ident;
	unsigned short flags_frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short chk_sum;
	struct in_addr src;
	struct in_addr dst;
};



// Struct representing a TCP header
struct tcp_head {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned char d_off;
	unsigned char tcp_flags;
	unsigned short window;
	unsigned short chk_sum;
	unsigned short ugent_ptr;
};


// Struct representing a UDP header
struct udp_head {
	unsigned short src_port;
	unsigned short dst_port;
    unsigned short len;
	unsigned short chk_sum;
};


// Struct representing a DNS header
struct dns_head {
    unsigned short id;        
    unsigned short flags;     
    unsigned short que;   
    unsigned short ans;   
    unsigned short aut;   
    unsigned short add;   
    unsigned char payload[];  
 } ;


void ethernet_pkt(u_char *verbose, const struct pcap_pkthdr *header, const u_char *packet);

void ip_pkt(u_char * verbose, const u_char *packet);

void tcp_pkt(u_char * verbose, const u_char *packet, int len_ip);

void udp_pkt(u_char * verbose, const u_char *packet, int len_ip);

void arp_pkt(u_char * verbose, const u_char * packet);

void ftp_pkt(u_char * verbose, const u_char *packet, int app_len);

void http_pkt(u_char * verbose, const u_char *packet, int app_len);

void dns_pkt(u_char * verbose, const u_char *packet, int app_len);

void pop_pkt(u_char * verbose, const u_char *packet, int app_len);

void imap_pkt(u_char * verbose, const u_char *packet, int app_len);

void smtp_pkt(u_char * verbose, const u_char *packet, int app_len);

void bootp_pkt(u_char * verbose, const u_char *packet, int len_ip);


#endif 