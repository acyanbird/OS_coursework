#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include <signal.h>
#include "analysis.h"

#define THREADNUM 20

// the analyse return
extern int syn;
extern unsigned int *data;
extern int dataSize;
extern int arp;
extern int blackURL;

jobQueue *q;

int uniqueIP(unsigned int *data, int tol){
    int unique = 0;
    int judge[tol];
    unsigned int curr;
    // set judge all to non seen before
    memset(judge, 0, sizeof(judge));
    // traverse all the element
    for(int i = 0;i < tol;i++){
        // if final element not appear before
        if(i == (tol - 1) && !judge[i]){
            unique++;
        }
        // if this element is not seen before
        else if(!judge[i]){
            curr = *(data + i);
            // mark all same value judge to 1
            for(int j = i + 1;j < tol;j++){
                if(curr == *(data + j)){
                    judge[j] = 1;
                }
            }
            unique++;
        }
    }   // finish travers
    return unique;
}

// Application main sniffing loop
void sigHandle(){
    printf("Intrusion Detection Report:\n");
    printf("%d SYN packets detected from %d different IPs (syn attack)\n", syn, uniqueIP(data, syn));
    printf("%d ARP responses (cache poisoning)\n", arp);
    printf("%d URL Blacklist violations\n", blackURL);
    exit(1);
}

// convert int ip to char ip
void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void sniff(char *interface, int verbose) {

    q = (jobQueue *) malloc(sizeof (struct jobQueue));
    createQueue(q);

    // init the array for syn ip
    data = (unsigned int *) calloc(dataSize, sizeof (unsigned int ));
    char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
    pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
    } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
    }

    pthread_t tid[THREADNUM];

    for (int i = 0; i < THREADNUM; ++i) {
    // pthread create tid? it pass what store in tid i to
    pthread_create(&tid[i], NULL, analyse, NULL);
    }


    signal(SIGINT,sigHandle);   // to handle when user press ctrl + c
    pcap_loop(pcap_handle, -1, dispatch, verbose);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ethhdr * eth_header = (struct ethhdr *) data;

  //struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");

  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->h_source[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->h_dest[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->h_proto);
  // try tcp and ip
  // data is unsigned char, so directly use add number, eth -> ip -> tcp, +14 +20

    struct iphdr *ip_head = (struct iphdr *)(data + sizeof(struct ethhdr));
    struct tcphdr *tcp_head = (struct tcphdr *) (data + sizeof (struct ethhdr) + sizeof (struct iphdr));

    printf("send ip addr is ");
    print_ip(ntohl(ip_head->saddr));
    printf("\n");
    printf("Dest ip addr is ");  // using ntohs convert it to short
    print_ip(ntohl(ip_head->daddr));
    printf("\n");

    printf("Source port is %d\n", ntohs(tcp_head->source));
    printf("Dest port is %d\n", ntohs(tcp_head->dest));
    printf("eth proto is %d", htons(eth_header->h_proto));



    printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;   // ETH_HLEN 14,
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
