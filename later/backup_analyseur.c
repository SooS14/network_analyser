/* compile with : gcc -o analyseur analyseur.c -lpcap */
/* use valgrind with : 

valgrind --tool=memcheck --leak-check=full ./bin/analyseur 

--track-origins=yes to see where uninitialised values come from
For lists of detected and suppressed errors, rerun with: -s
*/



#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "args-parser.h"
#include "header_def.h"
#include "pcap_fun.h"


#define SIZE 1024






unsigned int analyse_tcp(const u_char *packet, const struct tcp_head *tcp)
{
    unsigned int size_tcp = 0;
    if ((size_tcp = D_OFF(tcp)*4) < 20)
    {
        return -1;
    }

    return size_tcp;
}



unsigned int analyse_ip(const u_char *packet, const struct ip_head *ip)
{
    unsigned int size_ip;
    if ((size_ip = HDLEN(ip)*4) < 20)
    {
        return -1;
    } 

    unsigned int size_tcp = 0;
    const struct tcp_head *tcp;

    switch (ip->protocol)
    {
    case TCP:
        tcp = (const struct tcp_head *) (packet + SIZE_ETHER + size_ip);
        if ((size_tcp = analyse_tcp(packet, tcp)) == -1)
        {
            return -1;
        }
        return size_ip + size_tcp;

    case UDP:
        printf("analyse_ip, UDP header, not supported\n");
        return -1;    

    default:
        printf("analyse_ip, don't know what it is\n");
        return -1;
    }
}


unsigned int analyse_ethernet(const u_char *packet, const struct ethernet_head *ethernet)
{
    unsigned int size_ip_tcp = 0;
    const struct ip_head *ip;

    
    switch (ethernet->data_type)
    {
    case DT_IP:
        ip = (const struct ip_head *) (packet + SIZE_ETHER);
        if ((size_ip_tcp = analyse_ip(packet, ip)) == -1)
        {
            return -1;
        }

        return (SIZE_ETHER + size_ip_tcp);
    
    case DT_ARP:
        printf("analyse_ethernet, ARP header, not supported\n");
        return -1;
    
    case DT_RARP:
        printf("analyse_ethernet, RARP header, not supported\n");
        return -1;
    
    default:
        printf("analyse_ethernet, don't know what it is\n");
        return -1;
    }
}



/**
 * @brief callback function
 *
 */
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    // we assume that all packet received are ethernet
    const struct ethernet_head *ethernet;

    ethernet = (struct ethernet_head*) (packet);
    unsigned int size_head_tot;

    if ((size_head_tot = analyse_ethernet(packet, ethernet)) == -1)
    {
        return;
    }
    
	unsigned char *payload;
	payload = (unsigned char *)(packet + size_head_tot);


    printf("packet lenght : %d \n", header->len);
    //print_hex(payload, ip->tot_len - size_head_tot);

}







/**
 * @brief main function
 *
 * 
 * 
 */
int main(int argc, char *argv[])
{
    //fill the struct args with the arguments from the command line
    args_t args;
    parse_args(argc, argv, &args);    


    //list of var needed to open a device
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *p;	


    //struct that is needed to use filters :
    struct bpf_program fp;


    //var used to get the ip address and mask of a device
	bpf_u_int32 mask;		
	bpf_u_int32 ip_addr;	


    //var used by pcap_loop 
    struct pcap_pkthdr header;
    const u_char * packet;
    int pcap_loop_ret;
    int count_loop = 10000;



    if (!(args.flags & OFFLINE_ANALYSE))
    {

        findalldevs(&alldevsp,errbuf);

        if (!(args.flags & LIVE_ANALYSE))
        {
            printf("no file/device given. Using first device found by findalldevs :\n");
            printf("device : %s, desc : %s\n", alldevsp->name, alldevsp->description);
            device = alldevsp->name;
    
        }


        else 
        
        
        {
            int check_device = 0;
            for (pcap_if_t * i = alldevsp; i != NULL; i->next)
            {
                if (strncmp(alldevsp->name, args.interface, SIZE) == 0)
                {
                    printf("your device has been found within findalldevs's list, launching live analyse\n");
                    check_device = 1;
                    device = args.interface;
                    break;
                }
            
            }

            if (check_device == 0)
            {
                printf("your device hasn't been found, exiting\n");
                exit(0);
            }

        }

        open_live(device, errbuf, &p);

        //checks if the device is being used with ethernet
        datalink(&p, device);

        if (args.flags & FILTER)
        {

            //get the ip addr and mask of the device
            lookupnet(device,&mask,&ip_addr,errbuf);

            set_filters(&p, &fp, args.filter, mask);

        }	
    }


    else
    
    
    {
        printf("using offline analyse if both -i and -o flags are present\n");
        printf("opening file for an offline analyse\n");
        if ((p = pcap_open_offline(args.file_path ,errbuf)) == NULL)
        {
            fprintf(stderr, "open_offline err, errbuf :%s\n", errbuf);
            exit(0);
        }
    }




    pcap_loop_ret = pcap_loop(p, count_loop, loop_callback, NULL);

    if (pcap_loop_ret == 0)
    {
        printf("count is exhausted or no more packets are available\n");
    }
    else if (pcap_loop_ret == PCAP_ERROR)
    {
        printf("err pcap_loop, loop terminated with PCAP_ERR\n");
    }
        


    pcap_close(p);


    return 0;
}

