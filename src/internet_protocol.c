#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"






/**
 * @brief prints main information contained in the IP header
 * 
 * @param ip is a struct representing the IP header
 */
void ip_v2(const struct ip_head *ip)
{
    printf("-> ip header \n");
    printf("ver : %i ; ", ip->ver_hdlen >> 4);

    printf("protocol : ");
    switch (ip->protocol)
    {
    case PROT_UDP:
        printf("UDP ; ");
        break;
    case PROT_TCP:
        printf("TCP ; ");
        break;    
    default:
        printf("... ; ");
        break;
    }

    printf("src @ : %s ; ",inet_ntoa(ip->src));
    printf("dst @ : %s",inet_ntoa(ip->dst));
}



/**
 * @brief prints all the information contained in the IP header
 * 
 * @param ip is a struct representing the IP header
 */
void ip_v3(const struct ip_head *ip)
{   

    printf("\n");
    printf("\n############ ip header ###########\n");
    printf("Version : %i\n", VER(ip));
    printf("Header Length : %i\n", HDLEN(ip));
    printf("Type of Service : 0x%.2x\n", ip->ToS);
    printf("Total Length : %i\n", ntohs(ip->tot_len));
    printf("Identification : 0x%.2x\n", ntohs(ip->ident));
    printf("IP flags : 0x%.2x\n", IP_FLAGS(ip));    
    printf("Fragment Offset : %i\n", FRAG_OFF(ip));
    printf("Time to Live : %i\n", ip->ttl);

    printf("Protocol : ");
    switch (ip->protocol)
    {
    case PROT_UDP:
        printf("UDP\n");
        break;
    case PROT_TCP:
        printf("TCP\n");
        break;    
    default:
        printf("...\n");
        break;
    }

    printf("Header Checksum : 0x%.2x\n", ntohs(ip->chk_sum));
    printf("Source Adresse : %s\n", inet_ntoa(ip->src));
    printf("Destination Adresse : %s\n", inet_ntoa(ip->dst));
}



/**
 * @brief process the IP header
 * 
 * the packet is then passed to functions that are specialised in processing
 * transport layer headers.
 * 
 * @param verbose 
 * @param packet is the data received from eth_pkt
 */
void ip_pkt(u_char * verbose, const u_char * packet)
{

    const struct ip_head *ip;
    ip = (const struct ip_head*) packet;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("IP ; ");
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
    case PROT_UDP:
        udp_pkt(verbose, packet + HDLEN(ip) * 4, ntohs(ip->tot_len));
        break;

    case PROT_TCP:
        tcp_pkt(verbose, packet + HDLEN(ip) * 4, ntohs(ip->tot_len));
        break;
    
    default:
        fprintf(stderr, "Transport protocol not supported\n");
        break;
    }

}