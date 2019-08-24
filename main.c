#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <ctype.h>

#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];
  u_char  ether_shost[ETHER_ADDR_LEN];
  u_short ether_type;
};

struct sniff_ip {
  u_char  ip_vhl;
  u_char  ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
#define   IP_RF 0x8000
#define   IP_DF 0x4000
#define   IP_MF 0x2000
#define   IP_OFFMASK 0x1fff
  u_char  ip_ttl;
  u_char  ip_p;
  u_short  ip_sum;
  struct  in_addr ip_src, ip_dst; 
};

#define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
  u_short   th_sport;	/* source port */
  u_short   th_dport;	/* destination port */
  tcp_seq   th_seq;		/* sequence number */
  tcp_seq   th_ack;		/* acknowledgement number */
  u_char    th_offx2;	/* data offset, rsvd */
#define     TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char    th_flags;
#define     TH_FIN 0x01
#define     TH_SYN 0x02
#define     TH_RST 0x04
#define     TH_PUSH 0x08
#define     TH_ACK 0x10
#define     TH_URG 0x20
#define     TH_ECE 0x40
#define     TH_CWR 0x80
#define     TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short   th_win;		/* window */
  u_short   th_sum;		/* checksum */
  u_short   th_urp;		/* urgent pointer */
};

#define SIZE_ETHERNET 14

void print_hex_ascii_line(const u_char *payload, int len, int offset){
  int i;
  int gap;
  const u_char *ch;

  printf("%05d  ", offset);
  ch = payload;
  for(i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    if (i==7){
      printf(" ");
    }
  }

  if (len < 8) {
    printf(" ");
  }

  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("  ");
    }
  }

  printf("  ");

  ch = payload;
  for(i = 0; i < len; i++) {
    if (isprint(*ch)) {
      printf("%c", *ch);
    } else {
      printf(".");
    }
    ch++;
  }
  printf("\n");
}

void print_payload(const u_char *payload, int len){
  int len_rem = len;
  int line_width = 16;
  int line_len;
  int offset = 0;
  const u_char *ch = payload;

  if (len <= 0) {
    return;
  }

  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  for (;;) {
    line_len = line_width % len_rem;
    print_hex_ascii_line(ch, line_len, offset);
    len_rem = len_rem - line_len;
    ch = ch + line_len;
    offset = offset + line_width;
    if(len_rem <= line_width) {
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const u_char *payload;
  u_int size_ip;
  u_int size_tcp;
  u_int size_payload;

  printf("Jacked a packet with length of [%d]\n", header->len);
  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); 
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf(" * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
  print_payload(payload, size_payload);
}

int main(int argc, char *argv[])
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "port 443";
  pcap_t *handle;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  const u_char *packet;

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(2);
  }

  printf("Device %s\n", dev);

  if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Cant't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
    return(2);
  }



  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter: %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  return(0);
}
