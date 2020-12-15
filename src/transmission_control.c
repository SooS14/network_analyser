#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>


/**
 * @brief prints TCP flags
 * 
 * @param tcp is a struct representing the TCP header
 */
void flag_tcp(unsigned char flags)
{
	if (flags & FIN)
		printf("FIN ");
	if (flags & SYN)
		printf("SYN ");
	if (flags & RST)
		printf("RST ");
	if (flags & PUSH)
		printf("PUSH ");
	if (flags & ACK)
		printf("ACK ");
	if (flags & URG)
		printf("URG ");
	if (flags & ECE)
		printf("ECE ");
	if (flags & CWR)
		printf("CWR ");
	printf("\n");
}



/**
 * @brief prints some information contained in the TCP header
 * 
 * @param tcp is a struct representing the TCP header
 */
void tcp_v2(const struct tcp_head *tcp)
{
    printf("\n-> tcp header \n");
    printf("src port : %i ", ntohs(tcp->src_port));
    printf("dst port : %i ", ntohs(tcp->dst_port));
    printf("flags : ");
	flag_tcp(tcp->tcp_flags);
}


/**
 * @brief prints all the information contained in the TCP header
 * 
 * @param tcp is a struct representing the TCP header
 */
void tcp_v3(const struct tcp_head *tcp)
{
    printf("\n");
    printf("\n########## tcp header ##########\n");
    printf("Source port ntohs: 0x%.2x -> %i \n", ntohs(tcp->src_port), ntohs(tcp->src_port));
    printf("Destination port ntohs: 0x%.2x -> %i \n", ntohs(tcp->dst_port), ntohs(tcp->dst_port));
    printf("Sequence Number : 0x%.4x\n", ntohs(tcp->seq_num));
    printf("Acknoledgment Number : 0x%.4x\n", ntohs(tcp->ack_num));
    printf("Data offset : %i\n", D_OFF(tcp));
    printf("Window : 0x%.2x\n", ntohs(tcp->window));
    printf("flags : ");
	flag_tcp(tcp->tcp_flags);
    printf("Checksum : 0x%.2x\n", ntohs(tcp->chk_sum));
	printf("Urgent Pointer : 0x%.2x\n", ntohs(tcp->ugent_ptr));

}



/**
 * @brief process the TCP header
 * 
 * the segment is then passed to functions that are specialised in processing
 * application data based on destination and source port in the TCP header.
 * 
 * @param verbose 
 * @param segment is the data received from ip_pkt
 */
void tcp_pkt(u_char * verbose, const u_char *segment, int len_ip)
{
    const struct tcp_head *tcp;
    tcp = (const struct tcp_head*) segment;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("TCP ;");
        break;

    case 2:
        tcp_v2(tcp);
        break;

    case 3:
        tcp_v3(tcp);
        break;
    
    default:
        fprintf(stderr, "error switch tcp_pkt function");
        break;
    }

    

	if (ntohs(tcp->src_port) == PORT_DNS || ntohs(tcp->dst_port) == PORT_DNS)
	{
		dns_pkt(verbose, segment, len_ip - D_OFF(tcp) * 4);
	}
	if (ntohs(tcp->src_port) == PORT_FTP || ntohs(tcp->dst_port) == PORT_FTP)
	{
		ftp_pkt(verbose, segment + D_OFF(tcp) * 4, len_ip - D_OFF(tcp) * 4);
	}
	else if (ntohs(tcp->src_port) == PORT_HTTP || ntohs(tcp->dst_port) == PORT_HTTP)
	{
		http_pkt(verbose, segment + D_OFF(tcp) * 4, len_ip - D_OFF(tcp) * 4);
	}
	if (ntohs(tcp->src_port) == PORT_POP || ntohs(tcp->dst_port) == PORT_POP)
	{
		pop_pkt(verbose, segment, len_ip - D_OFF(tcp) * 4);
	}
	if (ntohs(tcp->src_port) == PORT_IMAP || ntohs(tcp->dst_port) == PORT_IMAP)
	{
		imap_pkt(verbose, segment, len_ip - D_OFF(tcp) * 4);
	}
	if (ntohs(tcp->src_port) == PORT_SMTP || ntohs(tcp->dst_port) == PORT_SMTP)
	{
		smtp_pkt(verbose, segment, len_ip - D_OFF(tcp) * 4);
	}
	if (ntohs(tcp->src_port) == PORT_BOOTP_C || 
        ntohs(tcp->src_port) == PORT_BOOTP_S || 
        ntohs(tcp->dst_port) == PORT_BOOTP_C || 
        ntohs(tcp->dst_port) == PORT_BOOTP_S)
	{
		bootp_pkt(verbose, segment, len_ip - 8);
	}
	if (ntohs(tcp->src_port) == PORT_DNS || ntohs(tcp->dst_port) == PORT_DNS)
	{
		dns_pkt(verbose, segment, len_ip - 8);
	}
}