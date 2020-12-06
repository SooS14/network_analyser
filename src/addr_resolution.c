#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"



void ip_v2(const struct ip_head *ip)
{
    printf("\n-> ip header \n");
    printf("ver : %i", ip->ver_hdlen >> 4);
    printf("src @ : %s",inet_ntoa(ip->src));
    printf("dst @ : %s",inet_ntoa(ip->dst));
    printf("prot : ");
}

void ip_v3(const struct ip_head *ip)
{   

    printf("\n");
    printf("\n-> ip header \n");
    printf("Version : %i\n", VER(ip));
    printf("Header Length : %i\n", HDLEN(ip));
    printf("Type of Service : 0x%.2x\n", ip->ToS);
    printf("Total Length : %i\n", ntohs(ip->tot_len));
    printf("Identification : 0x%.2x\n", ntohs(ip->ident));
    printf("Fragment Offset : 0x%.2x\n", ntohs(ip->frag_off));
    printf("Time to Live : %i\n", ip->ttl);
    printf("Header Checksum : 0x%.2x\n", ntohs(ip->chk_sum));
    printf("Source Addresse : %s\n", inet_ntoa(ip->src));
    printf("Destination Addresse : %s\n", inet_ntoa(ip->dst));
    printf("Protocol : ");
}



int ip_pkt(u_char * verbose, const u_char * packet)
{
    int trnsprt_len = 0;
    const struct ip_head *ip;
    ip = (const struct ip_head*) packet;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        break;

    case 2:
        ip_v2(ip);
        break;

    case 3:
        ip_v3(ip);
        break;
    
    default:
        fprintf(stderr, "error switch ethernet_pkt function");
        break;
    }

    switch (ip->protocol)
    {
    case UDP:
        printf("UDP");
        udp_pkt(verbose, packet + HDLEN(ip) * 4);
        trnsprt_len = 8;
        break;

    case TCP:
        printf("TCP");
        trnsprt_len = tcp_pkt(verbose, packet + HDLEN(ip) * 4);
        break;
    
    default:
        printf("....\n");
        fprintf(stderr, "Transport protocol not supported\n");
        break;
    }


    int totlen = ntohs(ip->tot_len);
    return totlen - HDLEN(ip) - trnsprt_len;
}