/**
 * @brief callback function
 *
 */
/*
void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    const struct ethernet_head *ethernet;
    const struct ip_head *ip;
    const struct tcp_head *tcp;
    ethernet = (struct ethernet_head*) (packet);

    unsigned int size_ip = 0;
    unsigned int size_tcp = 0;
    unsigned int size_tot = 0;


    switch (ethernet->data_type)
    {
    case DT_IP:
        ip = (const struct ip_head *) (packet + SIZE_ETHER);
        if ((size_ip = HDLEN(ip)*4) < 20)
        {
            return;
        } 
        break;


        switch (ip->protocol)
        {
        case TCP:
            tcp = (const struct tcp_head *) (packet + SIZE_ETHER + size_ip);
            if ((size_tcp = D_OFF(tcp)*4) < 20)
            {
                return;
            }
            break;

        case UDP:
            printf("analyse_ip, UDP header, not supported\n");
            return;    

        default:
            printf("analyse_ip, don't know what it is\n");
            return;
        }
        

    case DT_ARP:
        printf("analyse_ethernet, ARP header, not supported\n");
        return;
    
    case DT_RARP:
        printf("analyse_ethernet, RARP header, not supported\n");
        return;
    
    default:
        printf("analyse_ethernet, don't know what it is\n");
        return;
    }

    
	unsigned char *payload;
	payload = (unsigned char *)(packet + SIZE_ETHER + size_ip + size_tcp);


    printf("packet lenght : %d \n", header->len);
    print_hex(payload, ip->tot_len - (size_ip + size_tcp));

}
*/


#ifndef HEADER_DEF_H
#define HEADER_DEF_H

#include <pcap/pcap.h>


#define ADDR_LEN_ETHER 6
#define SIZE_ETHER 14

// ethernet data type 
#define DT_IP 0x08			//TRES BIZARRE A VOIR -> il manque le dernier octet à data_type
#define DT_ARP 0x0806
#define DT_RARP 0x0835 



// macros used to set appart the IP header lenght from the IP version
#define VER(ip)			(((ip)->ver_dhlen) >> 4)
#define HDLEN(ip)		(((ip)->ver_hdlen) & 0b00001111)

//IP flags
#define RF 0x8000            /* reserved fragment flag */
#define DF 0x4000            /* don't fragment flag */
#define MF 0x2000            /* more fragments flag */
#define OFFMASK 0x1fff       /* mask for fragmenting bits */

// IP protocols
#define TCP 0x06
#define UDP 0x11


//macro used to separate data offset from reserved informations
#define D_OFF(tcp)	(((tcp)->d_off & 0b11110000) >> 4)

//TCP flags
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PUSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
#define FLAGS (FIN|SYN|RST|ACK|URG|ECE|CWR)



/* Struct representing an ethernet header */
struct ethernet_head {
	unsigned char dst[ADDR_LEN_ETHER];
	unsigned char src[ADDR_LEN_ETHER]; 
	unsigned short data_type; 
};



/* Struct representing an IP header */
struct ip_head {
	unsigned char ver_hdlen;		//version << 4 ; header length >> 2
	unsigned char ToS;
	unsigned short tot_len;
	unsigned short ident;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short chk_sum;
	struct in_addr src;
	struct in_addr dst;
};



/* Struct representing a TCP header */
struct tcp_head {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned char d_off;			// to get data offset use the macro D_OFF
	unsigned char tcp_flags;
	unsigned short window;
	unsigned short chk_sum;
	unsigned short ugent_ptr;
};


#endif 



/**
 * @brief convert an hexadecimal expression to an int  
 * 
 * @param hex_array an array of char representing the input expression
 * @param length specify the length of the expression 
 * @return the result as an int
 */
int hex2dec(const unsigned char * hex_array, int length) {

    unsigned int res = 0; 

    for (int i = 1; i <= length; i++)
    {
        /*
        if ((hex_array[length - i] >= 48) && (hex_array[length - i] <= 57)) 
        {
            res += pow(16,i-1) * (hex_array[length - i] - 48);
        }
        else if ((hex_array[length - i] >= 65) && (hex_array[length - i] <= 90))
        {
            res += pow(16,i-1) * (hex_array[length - i] - 65);
        }
        else if ((hex_array[length - i] >= 97) && (hex_array[length - i] <= 122))
        {
            res += pow(16,i-1) * (hex_array[length - i] - 97);
        }
        else
        {
            fprintf(stderr, "wrong character hex2dec\n");
        }
        */

       res += pow(16,i-1) * (hex_array[length - i]);
    }

    return res;
}
