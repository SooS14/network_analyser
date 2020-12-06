#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"



int frame_num = 0;



void ethernet_v1()
{
    printf("ethernet ;");
}

void ethernet_v2(const struct ethernet_head *eth)
{   
    
    printf("\n-> eth header \n");
    printf("@mac dst : %.2x:...:%.2x ; ",eth->dst[0], eth->dst[5]);
    printf("@mac src : %.2x:...:%.2x ; ",eth->src[0], eth->src[5]);
    printf("data type : ");
}

void ethernet_v3(const struct ethernet_head *eth)
{
    printf("\n-> ethernet header \n");
    printf("@mac dst : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",
        eth->dst[0], eth->dst[1], eth->dst[2],
        eth->dst[3], eth->dst[4], eth->dst[5]);
    printf("@mac src : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",
        eth->src[0], eth->src[1], eth->src[2],
        eth->src[3], eth->src[4], eth->src[5]);
    printf("data type : ");
}


void ethernet_pkt(u_char *verbose, const struct pcap_pkthdr *header, const u_char *packet)
{
    //int iplen = 0;

    printf("\n\n############### frame number : %i\n", frame_num);
    frame_num++;

    const struct ethernet_head *ethernet;
    ethernet = (struct ethernet_head*) (packet);

    int verb = atoi((const char *)verbose);
    switch (verb)
    {
    case 1:
        ethernet_v1();
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


    switch (ethernet->data_type)
    {
    case DT_IP:
        printf("IP");
        //iplen = ip_pkt(verbose, packet + SIZE_ETHER);
        ip_pkt(verbose, packet + SIZE_ETHER);
        break;

    case DT_ARP:
        printf("ARP");
        fprintf(stderr, "ARP packet not supported\n");
        break;

    case DT_RARP:
        printf("RARP");
        fprintf(stderr, "RARP packet not supported\n");
        break;

    default:
        printf("....\n");
        fprintf(stderr, "ethernet frame type not supported\n");
        break;
    }

    printf("\n\n");


	unsigned char *payload;
	payload = (unsigned char *)(packet);

    printf("packet lenght : %d \n", header->len);
    print_hex(payload, header->len);    

}

