/* Inspired by the courese presentations
and thanks to *tj7723* GitHub repository in https://github.com/tj7723/CIS644-sniffandspoff/blob/master/SniffAndSpoofPacket.c
Should be run by command:   $gcc Sniffing.c -lpcap -o "sniffing.out
                            Then, running by    $sudo ./sniffing.out
*/


#include <sys/socket.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

struct Ethernet_header
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

struct IPheader
{
  unsigned char iph_ihl : 4,       //IP header length
      iph_ver : 4;                 //IP version
  unsigned char iph_tos;           //Type of service
  unsigned short int iph_len;      //IP Packet length (data + header)
  unsigned short int iph_ident;    //Identification
  unsigned short int iph_flag : 3, //Fragmentation flags
      iph_offset : 13;             //Flags offset
  unsigned char iph_ttl;           //Time to Live
  unsigned char iph_protocol;      //Protocol type
  unsigned short int iph_chksum;   //IP datagram checksum
  struct in_addr iph_sourceip;     //Source IP address
  struct in_addr iph_destip;       //Destination IP address
};

struct ICMPheader
{
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct Ethernet_header *eth = (struct Ethernet_header *)packet;

  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type
    struct IPheader *ip = (struct IPheader *)(packet + sizeof(struct Ethernet_header));

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));

    //getting the pointer to the ICMP part of the packet
    int ip_header_len = ip->iph_ihl * 4;
    struct ICMPheader *icmp = (struct ICMPheader *)(packet + sizeof(struct Ethernet_header) + ip_header_len);

    printf("       Type: %d\n", icmp->icmp_type);
    printf("       Code: %d\n\n", icmp->icmp_code);
  }
}

int main()
{
  pcap_t *handle;
  char errorbuffer[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3.

  // instead of "eth0", one should put his own machine name by using ifconfig order
  handle = pcap_open_live("eth1", BUFSIZ, 1, 1000, errorbuffer);

  if (handle != 0) {
    fprintf(stderr, "Can't open eth1: %s\n", errorbuffer);
    exit(1);
}
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0)
  {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }
  
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle); //Close the handle
  return 0;
}
