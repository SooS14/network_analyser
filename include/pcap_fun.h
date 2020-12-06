#ifndef PCAP_FUN_H
#define PCAP_FUN_H



#include <pcap/pcap.h>
#include "header_def.h"
#include "utils_fun.h"



void print_ip_addr(bpf_u_int32 ip);

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void findalldevs(pcap_if_t **alldevsp,char *errbuf);

void open_live(char *name, char *errbuf, pcap_t **p);

void set_filters(pcap_t **p, struct bpf_program *fp, const char *filter_exp, bpf_u_int32 mask);

void datalink(pcap_t **p, char *device);

void lookupnet(char *device, bpf_u_int32 *mask, bpf_u_int32 *ip_addr, char *errbuf);


#endif