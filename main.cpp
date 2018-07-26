/*----------------------------------------------------------------------*/
/* Program Description */
/* 
 * Parses packet contents and retrieves following data
 * eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data(max. of 16 bytes)
 * 
 * Any 'non-TCP/IP' packet is omitted
 */
/*----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

char *div = "*******************************************************************";

void usage(void);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    printf("Receiving packets...\n\n");

    while (true)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
       
        uint8_t  ETH_HL          = 14;
        uint16_t ETHERTYPE_PCKT  = (packet[12] << 8) | packet[13];
        
        uint16_t IPPROTO_PCKT    = packet[ETH_HL + 9];
        uint8_t  IP_IHL;
        
        uint16_t TCP_SRC_PORT;
        uint16_t TCP_DST_PORT;
        uint8_t  TCP_HL;
        
        uint8_t  DATA_OFFSET     = 0;
        uint8_t  DATA_PRINT_BASE = 0;
        
        if (ETHERTYPE_PCKT != ETHERTYPE_IP)
        {
            //printf("Ethertype not IP: dropped packet info... :(");
            //printf("\n\n");
            continue;
        }

        IP_IHL = (packet[ETH_HL + 0] & 0x0F) << 2;

        if (IPPROTO_PCKT != IPPROTO_TCP)
        {
            //printf("IP proto not TCP: dropped packet info... :(");
            //printf("\n\n");
            continue;
        }
        
        printf("%s\n", div);
        // non-TCP/IP packets omitted from print
        printf("<%u bytes captured>\n\n", header->caplen);

        TCP_HL = ((packet[ETH_HL + IP_IHL + 12] & 0xF0) >> 4) << 2;

        DATA_OFFSET     = ETH_HL + IP_IHL + TCP_HL; 
        DATA_PRINT_BASE = (DATA_OFFSET >> 4) << 4; 

        printf("[Source      MAC Address] %02x:%02x:%02x:%02x:%02x:%02x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
        printf("[Destination MAC Address] %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
        printf("\n");

        printf("[Source      IP  Address] %3d.%3d.%3d.%3d\n", packet[26], packet[27], packet[28], packet[29]);
        printf("[Destination IP  Address] %3d.%3d.%3d.%3d\n", packet[30], packet[31], packet[32], packet[33]);
        printf("\n");

        TCP_SRC_PORT = (packet[34] << 8) | packet[35];
        TCP_DST_PORT = (packet[36] << 8) | packet[37];

        printf("[Source      TCP  Port #] %5d\n", TCP_SRC_PORT);
        printf("[Destination TCP  PORT #] %5d\n", TCP_DST_PORT);
        printf("\n");

        printf("[DATA]\n");
        for (int i = DATA_PRINT_BASE; i < header->caplen; i++)
        {
            if      (i < DATA_OFFSET) printf("-- ");
            else    printf("%02x ", packet[i]);
            
            if (i % 16 == 7)    printf(" ");
            if (i % 16 == 15)   printf("\n");
        }
        
/* print packet contents------------------------------------------------
        for (int i = 0; i < header->caplen; i++)
        {
            printf("%02x ", packet[i]);
            if (i % 16 == 7)    printf(" ");
            if (i % 16 == 15)   printf("\n");
        }
----------------------------------------------------------------------*/     
        
        printf("\n");
        printf("%s", div);
        printf("\n");
    }

    pcap_close(handle);

    return 0;
}

void usage(void)
{
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

