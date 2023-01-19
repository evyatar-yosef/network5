#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <string.h>



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
    struct in_addr iph_swap;
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
/* ICMP Header  */
struct icmpheader
{
    unsigned char icmp_type;         // ICMP message type
    unsigned char icmp_code;         // Error code
    unsigned short int icmp_checksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id_1;     // Used for identifying request
    unsigned short int icmp_seq_1;    // Sequence number
};

unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    if (sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) <= 0)
    {
        perror("sendto() failed");
    }
     printf("source_ip: %s\n",inet_ntoa(ip->iph_sourceip));
     printf("dest_ip: %s\n",inet_ntoa(ip->iph_destip));

    close(sock);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    char newPacket[1500];
    memset(newPacket,0,1500);

    // Extract the necessary information from the packet
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + 14);
    struct icmpheader *icmp_hdr = (struct icmpheader *)(packet + 14 +(4 * ip->iph_ihl));

    struct ethheader *ethNew = (struct ethheader *)newPacket;
    struct ipheader *ipNew = (struct ipheader *)(newPacket + 14);
    struct icmpheader *icmp_hdrNew = (struct icmpheader *)(newPacket+ 14+ (4 * ip->iph_ihl));
 
    if (icmp_hdr->icmp_type == 8)
    {
    ipNew->iph_sourceip.s_addr = ip->iph_destip.s_addr;
    ipNew->iph_destip.s_addr = ip->iph_sourceip.s_addr;

    icmp_hdrNew->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity-
    icmp_hdrNew->icmp_checksum = 0;
    icmp_hdrNew->icmp_checksum = in_cksum((unsigned short *)icmp_hdrNew , sizeof(struct icmpheader));

    ipNew->iph_ver = 4;
    ipNew->iph_ihl = 5;
    ipNew->iph_ttl = 20;
    ipNew->iph_protocol = IPPROTO_ICMP;
    ipNew->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));

    
    send_raw_ip_packet(ipNew);  
    }
    
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("br-806f049de9ed", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    //    int pcap = pcap_compile(handle, &fp, filter_exp, 0, net);
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
