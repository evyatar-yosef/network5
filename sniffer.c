#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>


/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};
// ip header

struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};
/* app header*/
struct appheader
{
    uint32_t timestamp;
    uint16_t total_length;
    union
    {
        uint16_t reserved : 3, cache_flag : 1, steps_flag : 1, type_flag : 1, status_code : 10;
        uint16_t flags;
    };

    uint16_t cache_control;
    uint16_t padding;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    // Extract the necessary information from the packet
    FILE *fp ;
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + ip->iph_ihl*4);

    if (tcp->psh != 1)
    {
        return;
    }
    
    struct appheader *app = (struct appheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp->doff * 4);
   
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->iph_sourceip, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->iph_destip, dest_ip, INET_ADDRSTRLEN);
    
    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t timestamp = ntohl( app->timestamp);
    uint16_t total_length = ntohs(app->total_length);
    app->flags= ntohs(app->flags);
    uint16_t cache_flag = (((app->flags >> 12) & 1));
    uint16_t steps_flag = (((app->flags >> 11) & 1));
    uint16_t type_flag = (((app->flags >> 10) & 1));
    uint16_t status_code = app->status_code;
    uint16_t cache_control = ntohs(app->cache_control);
    uint8_t data[total_length];
    memcpy(data, (packet + sizeof(struct ethheader) + ip->iph_ihl*4 + tcp->doff*4 + 12), total_length);

    // Open a text file for writing
    fp = fopen("207467820,206616690.txt", "a");
    if (fp == NULL)
    {
        perror("can't open file");
    }



    // Write the packet information to the file in the desired format
    fprintf(fp, "source_ip: %s, dest_ip: %s, source_port: %hu, dest_port: %hu, timestamp: %u, total_length: %hu, cache_flag: %hu, steps_flag: %hu, type_flag: %hu, status_code: %hu, cache_control: %hu, data\n",
            source_ip, dest_ip, source_port, dest_port, timestamp, total_length, cache_flag, steps_flag, type_flag, status_code, cache_control);
    printf( "source_ip: %s, dest_ip: %s, source_port: %hu, dest_port: %hu, timestamp: %u, total_length: %hu, cache_flag: %hu, steps_flag: %hu, type_flag: %hu, status_code: %hu, cache_control: %hu, data\n",
            source_ip, dest_ip, source_port, dest_port, timestamp, total_length, cache_flag, steps_flag, type_flag, status_code, cache_control);

        for (int i = 0; i < total_length; i++)
    {
        if (!(i & 15))
            fprintf(fp, "\n%04X: ", i);

        fprintf(fp, "%02X ", ((unsigned char *)data)[i]);
   
    }
    
    // Close the file
    fclose(fp);
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) < 0)
    {
        perror("pcap");

        exit(1);
    }
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}

