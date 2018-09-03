#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <map>
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

    map<string, struct print_value> list;
    map<string, struct print_value>::iterator iter;
    struct print_value b;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct radiotap_header* radiotapH = (struct radiotap_header *) packet;
        packet += radiotapH->it_len;

        if(packet[0] == 0x80){
            struct IEEE80211_beacon* beaconf = (struct IEEE80211_beacon *) packet;
            packet += sizeof(struct IEEE80211_beacon);
            struct IEEE80211_framebody_NIE* fb_nie = (struct IEEE80211_framebody_NIE *) packet;
            packet += sizeof(struct IEEE80211_framebody_NIE);

            char bss[18];
            string bssid;
            snprintf(bss, sizeof(bss), "%02X:%02X:%02X:%02X:%02X:%02X", beaconf->bssid[0], beaconf->bssid[1], beaconf->bssid[2], beaconf->bssid[3], beaconf->bssid[4], beaconf->bssid[5]);
            bssid = bss;

            b.pwr = (int)radiotapH->antenna_signal1 - 256;                  /* PWR */

            iter = list.find(bssid);                                        /* Beacons */
            if(iter != list.end()) {
                (iter->second).beacon_count += 1;
                b.beacon_count = (iter->second).beacon_count;
            }
            else b.beacon_count = 1;

            int tag_len = 0;                               /* ESSID */
            if(packet[0] == 0x00){
                tag_len = (int) packet[1];
                char* buffer;
                buffer = (char*) calloc(1, tag_len);
                memcpy(buffer, packet+2, tag_len);
                b.essid = buffer;
                free(buffer);
                packet += tag_len + 2;
            }
            while(1){                                       /* Channel */
                tag_len = (int) packet[1];
                if(packet[0] == 0x03){
                    b.ch = (int) packet[2];
                    break;
                }
                packet += tag_len + 2;
            }

            list[bssid] = b;
            iter = list.find(bssid);
            if(iter != list.end())
            {
                printf( "%c[J", 27 );
                cout.setf(ios::left);
                cout << setw(20) << iter->first << setw(5) <<(iter->second).pwr << setw(10) << (iter->second).beacon_count << setw(5) << (iter->second).ch << setw(20) <<(iter->second).essid << endl;
            }
        }
    }
    pcap_close(handle);
    return 0;
}
