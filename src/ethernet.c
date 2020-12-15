#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"



int frame_num = 1;

/**
 * @brief prints main information in the ethernet header
 * 
 * @param eth is a struct representing the ethernet header
 */
void ethernet_v2(const struct ethernet_head *eth)
{   
    
    printf("\n-> eth header \n");
    printf("@mac dst : %.2x:...:%.2x ; ",eth->dst[0], eth->dst[5]);
    printf("@mac src : %.2x:...:%.2x ; ",eth->src[0], eth->src[5]);
    printf("data type : ");
    switch (ntohs(eth->data_type))
    {
    case DT_IP:
        printf("IP\n");
        break;

    case DT_ARP:
        printf("ARP\n");
        break;

    case DT_RARP:
        printf("RARP\n");
        break;
    
    default:
        printf("...\n");
        break;
    }
}



/**
 * @brief prints all the information in the ethernet header
 * 
 * @param eth is a struct representing the ethernet header
 */
void ethernet_v3(const struct ethernet_head *eth)
{
    printf("\n########### ethernet header ##########\n");
    printf("@mac dst : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",
        eth->dst[0], eth->dst[1], eth->dst[2],
        eth->dst[3], eth->dst[4], eth->dst[5]);
    printf("@mac src : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",
        eth->src[0], eth->src[1], eth->src[2],
        eth->src[3], eth->src[4], eth->src[5]);

    printf("data type : ");
    switch (ntohs(eth->data_type))
    {
    case DT_IP:
        printf("IP\n");
        break;

    case DT_ARP:
        printf("ARP\n");
        break;

    case DT_RARP:
        printf("RARP\n");
        break;
    
    default:
        printf("...\n");
        break;
    }
    
}



/**
 * @brief process the ethernet header
 * 
 * Since we only look for ethernet frames, the function processing 
 * the ethernet header is the loopback function of pcap_loop in main
 * function. The packet received is casted into an suitable struct representing
 * the header. The frame is then passed to a specific function able to process 
 * network layer packets.
 * 
 * @param verbose
 * @param header
 * @param packet
 */
void ethernet_pkt(u_char *verbose, const struct pcap_pkthdr *header, const u_char *frame)
{
    int full_frame = 0;
    int verb;
    const struct ethernet_head *ethernet;

    ethernet = (struct ethernet_head*) (frame);

    printf("\n\n***************** frame number : %i\n", frame_num);
    printf("packet lenght : %d \n", header->len);
    frame_num++;
    
    verb = atoi((const char *)verbose);
    
    if (verb == 4)
    {
        verbose = (u_char *) "3";
        verb = 3;
        full_frame = 1;
    }

    switch (verb)
    {
    case 1:
        printf("ethernet ; ");
        break;

    case 2:
        ethernet_v2(ethernet);
        break;

    case 3:
        ethernet_v3(ethernet);
        break;
    
    default:
        fprintf(stderr, "error switch ethernet_pkt function");
        break;
    }

    
    switch (ntohs(ethernet->data_type))
    {
    case DT_IP:
        ip_pkt(verbose, frame + SIZE_ETHER);
        break;

    case DT_ARP:
        arp_pkt(verbose, frame + SIZE_ETHER);
        break;

    case DT_RARP:
        fprintf(stderr, "RARP packet not supported\n");
        break;

    default:
        fprintf(stderr, "ethernet frame type not supported\n");
        break;
    }

    printf("\n\n");

    if (full_frame)
    {
        unsigned char *payload;
	    payload = (unsigned char *)(frame);
        print_hex(payload, header->len); 
    }
}

