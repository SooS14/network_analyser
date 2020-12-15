#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"





/**
 * @brief process the UDP header
 * 
 * the packet is then passed to functions that are specialised in processing
 * application data based on port number.
 * 
 * @param verbose 
 * @param packet is the data received from eth_pkt
 */
void udp_pkt(u_char * verbose, const u_char *segment, int len_ip)
{
    const struct udp_head *udp;
    udp = (const struct udp_head*) segment;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("UDP ; ");
        break;

    case 2:
        printf("\n-> udp header \n");
        printf("src port : %i ", ntohs(udp->src_port));
        printf("dst port : %i ", ntohs(udp->dst_port));
        printf("len : %i ", ntohs(udp->len));
        break;

    case 3:
        printf("\n");
        printf("\n############# udp header ############\n");
        printf("Source port : %i \n", ntohs(udp->src_port));
        printf("Destination port : %i \n", ntohs(udp->dst_port));
        printf("Length : %i \n", ntohs(udp->len));
        printf("Checksum : 0x%.2x \n", ntohs(udp->chk_sum));
        break;
    
    default:
        fprintf(stderr, "error switch udp_pkt function");
        break;
    }

	if (ntohs(udp->src_port) == PORT_DNS || ntohs(udp->dst_port) == PORT_DNS)
	{
		dns_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if (ntohs(udp->src_port) == PORT_FTP || ntohs(udp->dst_port) == PORT_FTP)
	{
		ftp_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if (ntohs(udp->src_port) == PORT_HTTP || ntohs(udp->dst_port) == PORT_HTTP)
	{
		http_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if (ntohs(udp->src_port) == PORT_POP || ntohs(udp->dst_port) == PORT_POP)
	{
		pop_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if (ntohs(udp->src_port) == PORT_IMAP || ntohs(udp->dst_port) == PORT_IMAP)
	{
		imap_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if (ntohs(udp->src_port) == PORT_SMTP || ntohs(udp->dst_port) == PORT_SMTP)
	{
		smtp_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if ((ntohs(udp->src_port) == PORT_BOOTP_C) || 
             (ntohs(udp->src_port) == PORT_BOOTP_S) || 
             (ntohs(udp->dst_port) == PORT_BOOTP_C) || 
             (ntohs(udp->dst_port) == PORT_BOOTP_S))
	{
		bootp_pkt(verbose, segment + 8, len_ip - 8);
	}
	else if (ntohs(udp->src_port) == PORT_DNS || ntohs(udp->dst_port) == PORT_DNS)
	{
		dns_pkt(verbose, segment + 8, len_ip - 8);
	}
}