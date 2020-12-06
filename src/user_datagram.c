#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"



void udp_v2(const struct udp_head *udp)
{
    printf("\n-> udp header \n");
    printf("src port : %i ", ntohs(udp->src_port));
    printf("dst port : %i ", ntohs(udp->dst_port));
    printf("len : %i ", ntohs(udp->len));

}

void udp_v3(const struct udp_head *udp)
{
    printf("\n");
    printf("\n-> udp header \n");
    printf("Source port : %i ", ntohs(udp->src_port));
    printf("Destination port : %i ", ntohs(udp->dst_port));
    printf("Length : %i ", ntohs(udp->len));
    printf("Checksum : 0x%.2x ", ntohs(udp->len));
}


void udp_pkt(u_char * verbose, const u_char *packet)
{
    const struct udp_head *udp;
    udp = (const struct udp_head*) packet;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        break;

    case 2:
        udp_v2(udp);
        break;

    case 3:
        udp_v3(udp);
        break;
    
    default:
        fprintf(stderr, "error switch udp_pkt function");
        break;
    }
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