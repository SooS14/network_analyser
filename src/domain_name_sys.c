#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"



/**
 * @brief process the DNS header
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void dns_pkt(u_char * verbose, const u_char *packet, int app_len)
{
    const struct dns_head * dns;
    dns = (const struct dns_head *) packet;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf(" DNS");
        break;

    case 2:
        printf("\n-> dns header \n");
        printf("ID : 0x%.2x ; ", ntohs(dns->id));
        printf("Question : %i ; ", ntohs(dns->que));
        printf("Answers : %i", ntohs(dns->ans));
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## dns header ##########\n");

        printf("Transaction ID : 0x%.2x\n", ntohs(dns->id));
        printf("Flags : 0x%.2x\n", ntohs(dns->flags));
        printf("Questions : %i\n", ntohs(dns->que));
        printf("Answers : %i\n", ntohs(dns->ans));
        printf("Authority RRs : %i\n", ntohs(dns->aut));
        printf("Additional RRs : %i\n", ntohs(dns->add));
        printf("\n");
        print_hex(dns->payload, app_len);
        break;
    
    default:
        fprintf(stderr, "error switch dns_pkt function");
        break;
    }
}