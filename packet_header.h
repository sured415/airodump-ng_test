#ifndef PACKET_HEAER_H
#define PACKET_HEAER_H
#endif // PACKET_HEAER_H

#include <string>
using namespace std;

struct radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present1;
    uint32_t it_present2;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t ch_freq;
    uint16_t ch_flag;
    uint8_t antenna_signal1;
    uint16_t rx_flag;
    uint8_t antenna_signal2;
    uint8_t antenna;
};

struct IEEE80211_beacon {
    uint16_t fc;                /* Frame Control */
    uint16_t duration;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];           /* BSSID */
    uint16_t seq_control;
};

#pragma pack(push, 1)
struct IEEE80211_framebody_NIE {
    uint64_t timestamp;
    uint16_t bi;                /* Beacon Interval */
    uint16_t ci;                /* Capability Information */
};
#pragma pack(pop)

struct print_value {
    int pwr;
    uint32_t beacon_count;
    int ch;
    string essid;
};
