#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "args_parser.h"
#include "header_def.h"
#include "pcap_fun.h"
#include "utils_fun.h"






/**
 * @brief calls pcap_findalldevs and checks for errors
 *
 * @param alldevsp a list of network devices (opened with pcap_open_live)
 * @param errbuf a buffer to print possible errors
 * 
 */
void findalldevs(pcap_if_t **alldevsp,char *errbuf)
{
   if (pcap_findalldevs(alldevsp, errbuf) == PCAP_ERROR)
    {
        fprintf(stderr, "findalldevs err : %s\n", errbuf);
        exit(0);
    }
    else if (alldevsp == NULL)
    {
        fprintf(stderr,"findalldevsp : no devices were found\n");
        exit(0);
    }
}





/**
 * @brief calls pcap_open_live and checks for errors
 *
 * The snapshot length is set to BUFSIZ.
 * Promiscuous mode is deactivated.
 * the packet buffer timeout is set to 1 seconde.
 * 
 * @param name the name of the interface
 * @param errbuf a buffer to print possible errors
 * @param p capture handle
 * 
 */
void open_live(char *name, char *errbuf, pcap_t **p)
{
    if ((*p = pcap_open_live(name, BUFSIZ, 0, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "Couldn't open the interface %s, errbuf : %s\n", name, errbuf);
        exit(0);
    }
}



/**
 * @brief calls pcap_compile and pcap_setfilter, checks for errors
 *
 * No optimization is performed in pcap_compile
 * 
 * @param p is the capture handle
 * @param fp bpf_program struct filed by pcap_compile
 * @param filter_exp the string being compiled into a filter program
 * @param netmask IPv4 netmask of the network on which packets are being captured
 * 
 */
void set_filters(pcap_t **p, struct bpf_program *fp, const char *filter_exp, bpf_u_int32 netmask) {
    
    if (pcap_compile(*p, fp, filter_exp, 0, netmask) == -1) {
	    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(*p));
	    exit(0);
    }
    if (pcap_setfilter(*p, fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(*p));
        exit(0);
    }
}





/**
 * @brief calls pcap_datalink and checks for errors
 * 
 * The purpose is to check if we are capturing on an ethernet device
 *
 * @param p capture handle
 * @param device the name of the device
 * 
 */
void datalink(pcap_t **p, char *device) {
	
	if (pcap_datalink(*p) != DLT_EN10MB) {
		fprintf(stderr, "not an ethernet device : %s\n", device);
		exit(0);
	}
}






/**
 * @brief calls pcap_lookupnet and checks for errors
 *
 * The purpose is to give the ip addresse of the device before capturing packets
 * 
 * @param device the name of the device
 * @param mask netmask of the device 
 * @param ip_addr addresse of the device
 * @param errbuf to print possible errors
 * 
 */
void lookupnet(char *device, bpf_u_int32 *mask, bpf_u_int32 *ip_addr, char *errbuf)
{
    printf("\n");
	if (pcap_lookupnet(device, ip_addr, mask, errbuf) == PCAP_ERROR) {
        printf("Cant find ip addr and mask for device : %s\n", device);
        printf("!NOT EXITING!, ip and mask set to 0, check stderr\n");
	    fprintf(stderr, "err pcap_lookupnet : device %s ; errbuf : %s\n", device, errbuf);
	    ip_addr = 0;
	    mask = 0;
    }
    else
    {
        printf("ip : ");
        print_ip_addr(*ip_addr);
        printf("mask : ");
        print_ip_addr(*mask);
        printf("for device : %s\n", device);
    }
    printf("\n");
}


