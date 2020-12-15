#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include "header_def.h"
#include "utils_fun.h"
#include "bootp.h"




/**
 * @brief prints vendor specific option
 * 
 * @param vend vendor specific parts of bootp header
 */
void vendor_spe(const unsigned char * vend)
{
    /*
    for (int i = 0; i < 64; i++)
    {
        printf("sooooooos : %.2x\n", vend[i]);
    }
    */
    
	if (vend[0] != 0x63 ||
        vend[1] != 0x82 ||
	    vend[2] != 0x53 ||
        vend[3] != 0x63)
	{
		return;
	}

    printf("vendor specific : ");
    int count = 4;

    while (count < 64)
    {
        switch (vend[count])
        {
        case SUBNET_MASK:
            printf("subnet mask : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            
            break;

        case TIME_OFFSET:
            printf("time offset : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case ROUTER:
            printf("router : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case DNS:
            printf("dns : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");            
            break;

        case HOST_NAME:
            printf("host name : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case DOMAIN_NAME:
            printf("domain name : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case BROADCAST_ADDR:
            printf("broadcast addr : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case NONS:
            printf("netbios over TCP/IP name server : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case NOS:
            printf("netbios over TCP/IP scope : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");        
            break;

        case REQ_IP_ADDR:
            printf("Requested IP address : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");  
            break;

        case LEASE_TIME:
            printf("leas time : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case DHCP_MESS_TYPE:
            printf("DHCP message type : 0x");

            switch (vend[count+2])
            {
            case DHCP_DISCOVER:
                printf("DISCOVER");
                break;
            
            case DHCP_OFFER:
                printf("OFFER");
                break;

            case DHCP_REQUEST:
                printf("REQUEST");
                break;

            case DHCP_DECLINE:
                printf("DECLINE");
                break;

            case DHCP_ACK:
                printf("ACK");
                break;

            case DHCP_NAK:
                printf("NAK");
                break;

            case DHCP_RELEASE:
                printf("RELEASE");
                break;

            default:
                break;
            }

            count = count + 3;
            printf("\n");
            break;

        case SERV_ID:
            printf("netbios over TCP/IP name server : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");          
            break;

        case PARAM_REQ_LST:
            printf("netbios over TCP/IP name server : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        case CLIENT_ID:
            printf("netbios over TCP/IP name server : 0x");
            for (int i = count+2; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[i]);
            }
            count = vend[count+1] + 1 + count;
            printf("\n");
            break;

        default:
            break;
        }

    }

}


/**
 * @brief prints some informations in the BOOTP header
 * 
 * @param bootp is a struct representing the BOOTP header
 */
void bootp_v2(const struct bootp_head *bootp)
{
    printf("\n-> bootp header \n");
	printf("ciaddr : %s", inet_ntoa(bootp->ciaddr));
	printf("yiaddr : %s", inet_ntoa(bootp->yiaddr));
	printf("siaddr : %s", inet_ntoa(bootp->siaddr));
}


/**
 * @brief prints all informations in the BOOTP header
 * 
 * @param bootp is a struct representing the BOOTP header
 */
void bootp_v3(const struct bootp_head *bootp)
{
    printf("\n");
    printf("\n############# bootp header ############\n");

    printf("Opcode : ");
    if (bootp->op == BOOTP_REPLY)
    {
        printf("reply");
    }
    else if (bootp->op == BOOTP_REQUEST)
    {
        printf("request");
    }
	printf("\nHardware address type : %i\n", bootp->htype);
	printf("Hardware address lenght : %i\n", bootp->hlen);
	printf("Gateway hops : %u\n", bootp->hops);
	printf("Transaction ID : 0x%x\n", ntohl(bootp->xid));
	printf("Seconds since beginning : %i \n", ntohs(bootp->secs));
	printf("Flags : 0x%.2x\n", ntohs(bootp->flags));
	printf("Client address : %s\n", inet_ntoa(bootp->ciaddr));
	printf("Your address : %s\n", inet_ntoa(bootp->yiaddr));
	printf("Server address : %s\n", inet_ntoa(bootp->siaddr));
	printf("Gateway address : %s\n", inet_ntoa(bootp->giaddr));
	printf("Client hardware address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            bootp->chaddr[0],bootp->chaddr[1],bootp->chaddr[2],
            bootp->chaddr[3],bootp->chaddr[4],bootp->chaddr[5]);
    printf("Server Name : %s\n", bootp->sname);
    printf("File name : %s\n", bootp->file);
    //vendor_spe(bootp->vend); NE MARCHE PAS WHILE INF À VOIR
}


/**
 * @brief process the bootp header
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void bootp_pkt(u_char * verbose, const u_char *data, int len_ip)
{
    const struct bootp_head *bootp;
    bootp = (const struct bootp_head*) data;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf(" BOOTP");
        break;

    case 2:
        bootp_v2(bootp);
        break;

    case 3:
        bootp_v3(bootp);
        break;
    
    default:
        fprintf(stderr, "error switch bootp_pkt function");
        break;
    }

}
