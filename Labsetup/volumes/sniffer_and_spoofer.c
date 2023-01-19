#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <errno.h>
#include <stdbool.h>
//#include <netinet/ip_icmp.h>

struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};



unsigned short in_cksum(unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *) (&temp) = *(u_char *) w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short) (~sum);
}

int create_raw_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        printf("ERROR: socket() failed with error: %d\n", errno);
        printf("WARNNING: To create a raw socket, the process needs to be run by Admin/root user.\n");
    }

    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    return sock;
}

bool is_icmp_echo(const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;
    if (ntohs(eth->ether_type) != 0x0800) {
        return false;
    }

    struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
    if (ip->iph_protocol != IPPROTO_ICMP) {
        return false;
    }

    struct icmpheader *icmp = (struct icmpheader *) ((u_char *) ip + sizeof(struct ipheader));
    return icmp->icmp_type == 8;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len <= 0) {
        return;
    }

    if (!is_icmp_echo(packet)) {
        return;
    }

    struct ethheader *eth = (struct ethheader *) packet;
    struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
    struct icmpheader *icmp = (struct icmpheader *) ((u_char *) ip + sizeof(struct ipheader));

    printf("ICMP: %s", inet_ntoa(ip->iph_sourceip));
    printf(" -> %s\n", inet_ntoa(ip->iph_destip));

    // sendping back
    icmp->icmp_type = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *) icmp, ip->iph_len - sizeof(struct ipheader));

    ip->iph_ident = 0;
    ip->iph_flag = 0;
    ip->iph_ttl = 115;

    int temp = ip->iph_sourceip.s_addr;
    ip->iph_sourceip.s_addr = ip->iph_destip.s_addr;
    ip->iph_destip.s_addr = temp;

    // Create raw socket for IP-RAW
    int sock = create_raw_socket();

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr = ip->iph_destip;

    // Send the packet using sendto() for sending datagrams.
    int bytes_sent = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *) &dest_in, sizeof(dest_in));
    if (bytes_sent == -1) {
        printf("WARNNING: sendto() failed with error: %d\n", errno);
    }

    printf("Ping sented %s", inet_ntoa(ip->iph_sourceip));
    printf(" -> %s\n", inet_ntoa(ip->iph_destip));

    // Close the raw socket descriptor.
    close(sock);
}
//Main GPT
int main(int argc, char **argv)
{
    char *dev = argv[1];

    char filter[] = "icmp";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle;        /* Session handle */
    struct bpf_program fp; /* The compiled filter expression */
    bpf_u_int32 mask;      /* Our netmask */
    bpf_u_int32 net;       /* The IP of our sniffing device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("Internet Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        printf("Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return 1;
    }

    printf("Start Runing\n");

    pcap_loop(handle, -1, process_packet, NULL);
}


// //Main Robot
// int main(int argc, char **argv)
// {
//     char *dev = argv[1];

//     char filter[] = "icmp";

//     char errbuf[PCAP_ERRBUF_SIZE];

//     pcap_t *handle;        /* Session handle */
//     struct bpf_program fp; /* The compiled filter expression */
//     bpf_u_int32 mask;      /* Our netmask */
//     bpf_u_int32 net;       /* The IP of our sniffing device */

//     if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
//     {
//         fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
//         net = 0;
//         mask = 0;
//     }

//     printf("Internet Device: %s\n", dev);

//     handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

//     if (handle == NULL)
//     {
//         printf("Couldn't open device %s: %s\n", dev, errbuf);
//         return 1;
//     }
//     if (pcap_compile(handle, &fp, filter, 0, net) == -1)
//     {
//         printf("Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
//         return 1;
//     }
//     if (pcap_setfilter(handle, &fp) == -1)
//     {
//         printf("Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
//         return 1;
//     }

//     printf("Start Runing\n");

//     pcap_loop(handle, -1, process_packet, NULL);
// }
