#ifndef UTILS_FUN_H
#define UTILS_FUN_H


#include <pcap/pcap.h>




struct ip_addr {
        unsigned char one;
        unsigned char two;
        unsigned char three;
        unsigned char four;
};



void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_payload(const u_char *payload, int len);

int print_ip_addr(bpf_u_int32 ip);

void print_hex(const unsigned char *payload, int payload_size);


#endif