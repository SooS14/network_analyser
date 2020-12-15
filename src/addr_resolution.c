#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include "utils_fun.h"




/**
 * @brief prints some informations in the ARP header
 * 
 * @param arp is a struct representing the ARP header
 */
void arp_v2(const struct ether_arp *arp)
{
    printf("\n-> ARP \n");
    printf("Operation : %i ", ntohs(arp->arp_op));
    if(ntohs(arp->arp_op) == ARPOP_REQUEST)
		printf("request (%.2x)", ntohs(arp->arp_op));
    if(ntohs(arp->arp_op) == ARPOP_REPLY)
		printf("reply (%.2x)", ntohs(arp->arp_op));
    printf(" ; ");

	printf("Sender : %.2x:...:%.2x",arp->arp_sha[0],arp->arp_sha[5]);
    printf(" ; Target : %.2x:...:%.2x", arp->arp_tha[0], arp->arp_tha[5]);

}


/**
 * @brief prints all the informations in the ARP header
 * 
 * @param arp is a struct representing the ARP header
 */
void arp_v3(const struct ether_arp *arp)
{   

    printf("\n");
    printf("\n######### ARP #########\n");

	printf("Hardware type : ethernet (%.2x)\n", ntohs(arp->arp_hrd));

    printf("Protocol type : ");
	if(ntohs(arp->arp_pro) == TYPE_IPv4)
    {
        printf(" IPv4");
    }
    else if(ntohs(arp->arp_pro) == TYPE_IPv6)
    {
        printf(" IPv6");
    }
    else
    {
        printf("Unknown");
    }
    
	printf("\nHardware Address Length : %i\n", arp->arp_hln);
	printf("Protocol Address Length : %i\n", arp->arp_pln);

    printf("Operation : ");
    if(ntohs(arp->arp_op) == ARPOP_REQUEST)
    {
		printf("Request (%.2x)", ntohs(arp->arp_op));
    }
    else if(ntohs(arp->arp_op) == ARPOP_REPLY)
    {
		printf("Reply (%.2x)", ntohs(arp->arp_op));
    }
    else
    {
        printf("Unknown");
    }

    printf("\nSender Hardware Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", 
            arp->arp_sha[0],arp->arp_sha[1],arp->arp_sha[2],
            arp->arp_sha[3],arp->arp_sha[4],arp->arp_sha[5]);

    printf("Sender Protocol Address : %i.%i.%i.%i \n", 
            arp->arp_spa[0],arp->arp_spa[1],arp->arp_spa[2],arp->arp_spa[3]);

    printf("Target Hardware Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", 
            arp->arp_tha[0],arp->arp_tha[1],arp->arp_tha[2],
            arp->arp_tha[3],arp->arp_tha[4],arp->arp_tha[5]);

    printf("Target Protocol Address : %i.%i.%i.%i \n", 
            arp->arp_tpa[0],arp->arp_tpa[1],arp->arp_tpa[2],arp->arp_tpa[3]);
}




/**
 * @brief process the ARP header
 * 
 * @param verbose
 * @param packet
 */
void arp_pkt(u_char * verbose, const u_char * packet)
{

    const struct ether_arp * arp;
    arp = (const struct ether_arp *) packet;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("RARP");
        break;

    case 2:
        arp_v2(arp);
        break;

    case 3:
        arp_v3(arp);
        break;
    
    default:
        fprintf(stderr, "error switch ethernet_pkt function");
        break;
    }
}