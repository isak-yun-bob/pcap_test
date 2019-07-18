#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <stdint.h>
#include <string>


void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

#define ETHERNET_HEADER_SIZE 14
#define SRC_IP_LOCATION 14
#define DEST_IP_LOCATION 18
#define SRC_PORT_LOCATION 22
#define DEST_PORT_LOCATION 24
#define SRC_MAC_LOCATION 6
#define TCP_OFFSET_LOCATION 12

// Print MAC address
void print_mac(uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Print IP address
void print_ip(uint8_t *ip) {
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}


// Print Port number
void print_port(uint8_t *port) {
    uint16_t *port_output = reinterpret_cast<uint16_t *>(port);
    uint16_t temp = (((*port_output)&0xFF00)>>8) | (((*port_output)&0x00FF)<<8);
    printf("%d\n", temp);
}

// Packet struct
typedef struct packet_struct {

    u_char src_mac[6];
    uint8_t src_ip[4];
    uint8_t src_port[2];
    u_char dest_mac[6];
    uint8_t dest_ip[4];
    uint8_t dest_port[2];
    uint8_t ip_type[2];
    uint8_t ip_header_size;
    uint8_t tcp_header_size;
    uint8_t protocol;
    uint8_t *tcp_data;
    int tcp_data_size;

} Packet;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    // Declare network packet structure
    Packet packet_saved;

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    uint8_t ipv4[] = {0x08, 0x00};


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        for(int i=0; i<int(header->caplen); i++) {

            // Saving Destination MAC
            if(i==0) {
                for(int j=0; j<6; j++) {
                    packet_saved.dest_mac[j] = packet[i+j];
                }
            }


            // Saving Source MAC
            if(i==6) {
                for(int j=0; j<6; j++) {
                    packet_saved.src_mac[j] = packet[i+j];
                }
            }

            // Check if IP is exists. (IPv4 or IPv6)
            if(i==12) {
                for(int j=0; j<2; j++) {
                    packet_saved.ip_type[j] = packet[i+j];
                }
            }

            // Get IP header size
            if(i==14) {
                packet_saved.ip_header_size = packet[i];
                packet_saved.ip_header_size %= 16;
                packet_saved.ip_header_size *= 4;
            }

            // Check Protocol
            // Protocol is in IP header 10byte point
            if(i==ETHERNET_HEADER_SIZE + 9) {
                packet_saved.protocol = packet[i];
            }

            // Saving Source IP
            if(i==ETHERNET_HEADER_SIZE + packet_saved.ip_header_size - 8) {
                for(int j=0; j<4; j++) {
                    packet_saved.src_ip[j] = packet[i+j];
                }
            }

            // Saving Destination IP
            if(i==ETHERNET_HEADER_SIZE + packet_saved.ip_header_size - 4) {
                for(int j=0; j<4; j++) {
                    packet_saved.dest_ip[j] = packet[i+j];
                }
            }

            // Saving Source Port
            if(i==ETHERNET_HEADER_SIZE + packet_saved.ip_header_size) {
                for(int j=0; j<2; j++) {
                    packet_saved.src_port[j] = packet[i+j];
                }
            }

            // Saving Destination Port
            if(i==ETHERNET_HEADER_SIZE + packet_saved.ip_header_size + 2) {
                for(int j=0; j<2; j++) {
                    packet_saved.dest_port[j] = packet[i+j];
                }
            }

            // Get TCP header size
            if(i==ETHERNET_HEADER_SIZE + packet_saved.ip_header_size + 12) {
                packet_saved.tcp_header_size = packet[i];
                packet_saved.tcp_header_size /= 16;
                packet_saved.tcp_header_size *= 4;
            }

            // Saving TCP data
            packet_saved.tcp_data_size = 0;
            packet_saved.tcp_data = (uint8_t *)malloc(sizeof(uint8_t) * packet_saved.tcp_data_size);
            if(i==ETHERNET_HEADER_SIZE + packet_saved.ip_header_size + packet_saved.tcp_header_size - 2) {
                for(int j=0; packet[j] == 0x00 && packet[j+1] == 0x00; j++) {
                    packet_saved.tcp_data_size++;
                    packet_saved.tcp_data[j] = packet[i+j];
                }
            }
        }

        printf("Destination MAC : ");
        print_mac(packet_saved.dest_mac);

        printf("Source MAC : ");
        print_mac(packet_saved.src_mac);

        if(*packet_saved.ip_type == *ipv4)
            printf("Type : IPv4\n");
        else {
            printf("Type : IPv6. Just continue.\n");
            continue;
        }

        printf("IP header size : %d\n", packet_saved.ip_header_size);
        printf("TCP Header size : %d\n", packet_saved.tcp_header_size);

        if(packet_saved.protocol == 0x6)
            printf("Protocol : TCP\n");
        else if (packet_saved.protocol == 0x11) {
            printf("Protocol : UDP. Just continue.\n");
            continue;
        }

        printf("Source IP : ");
        print_ip(packet_saved.src_ip);

        printf("Destination IP : ");
        print_ip(packet_saved.dest_ip);

        printf("Source Port : ");
        print_port(packet_saved.src_port);

        printf("Destination Port : ");
        print_port(packet_saved.dest_port);

        // Print TCP Data (maximum : 10bytes)
        printf("TCP Data : \n");
        for(int i=0; i<packet_saved.tcp_data_size; i++) {
            printf("%02X ",packet_saved.tcp_data[i]);
        }
        printf("\n");
        printf("---------------------------\n");

    }
    pcap_close(handle);
    return 0;
}
