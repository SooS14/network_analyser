#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>



void flag_tcp(uint8_t flags)
{
	if (flags & FIN)
		printf("FIN ");
	if (flags & 0x0F)
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


void tcp_v2(const struct tcp_head *tcp)
{
    printf("\n-> tcp header \n");
    printf("src port : %i ", ntohs(tcp->src_port));
    printf("dst port : %i ", ntohs(tcp->dst_port));
	printf("flags : ");
	flag_tcp(tcp->tcp_flags);
}

void tcp_v3(const struct tcp_head *tcp)
{
    printf("\n");
    printf("\n-> tcp header \n");
    printf("Source port ntohs: 0x%.2x -> %i \n", ntohs(tcp->src_port), ntohs(tcp->src_port));
    printf("Destination port ntohs: 0x%.2x -> %i \n", ntohs(tcp->dst_port), ntohs(tcp->dst_port));
    printf("Sequence Number : %i\n", ntohs(tcp->seq_num));
    printf("Acknoledgment Number : %i\n", ntohs(tcp->ack_num));
    printf("Data offset macro: %i \n", D_OFF(tcp));
    printf("Window : 0x%.2x\n", ntohs(tcp->window));
    printf("Checksum : 0x%.2x\n", ntohs(tcp->chk_sum));
	printf("Urgent Pointer : 0x%.2x\n", ntohs(tcp->ugent_ptr));
    printf("flags : ");
	flag_tcp(tcp->tcp_flags);

}



int tcp_pkt(u_char * verbose, const u_char *packet)
{
    const struct tcp_head *tcp;
    tcp = (const struct tcp_head*) packet;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        break;

    case 2:
        tcp_v2(tcp);
        break;

    case 3:
        tcp_v3(tcp);
        break;
    
    default:
        fprintf(stderr, "error switch ethernet_pkt function");
        break;
    }

    return D_OFF(tcp) * 4;


/*
    switch (tcp->protocol)
    {
    case UDP:
        printf("UDP");
        udp_pkt(verbose, packet + (ip->ver_hdlen >> 4) * 20);
        break;

    case TCP:
        printf("TCP");
        tcp_pkt(verbose, packet + (ip->ver_hdlen >> 4) * 20);
        break;
    
    default:
        printf("....\n");
        fprintf(stderr, "Transport protocol not supported\n");
        break;
    }
    */
}