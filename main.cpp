#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#define LIBNET_LIL_ENDIAN 1
#include <libnet/libnet-headers.h>
#include <packet_header.h>

using namespace std;

void usage() {
  printf("syntax: airodump-ng_test <interface>\n");
  printf("sample: airodump-ng_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct radiotap_header* radiotapH = (struct radiotap_header *) packet;
//  packet += radiotapH->it_len;
    if(packet[radiotapH->it_len] == 0x80){
        printf("\n%u bytes captured\n", header->caplen);
        
        for(int i=radiotapH->it_len; i<(radiotapH->it_len)+16; i++) printf("%02x ", packet[i]);
        printf("\n");
    }
  }
  pcap_close(handle);
  return 0;
}
