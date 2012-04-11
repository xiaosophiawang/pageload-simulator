/**
 * Convert each frame from a raw pcap file to the following format.
 * We focus on the TCP behaviors.
 *   - timestamp | direction | ip | port | size | optional (url/mime/etc.)
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <memory.h>
#include "pcap_header.h"

extern char *optarg; // Used for parsing command line arguments

//------------------------------------------------------------------- 
int main(int argc, char **argv) { 
	pcap_t *handle; //a handle to the entire trace
  	char errbuf[PCAP_ERRBUF_SIZE]; //we dont really use this, but this is an input to the pcap_open_offline function
	
	struct return_data *metadata = (struct return_data *)malloc(sizeof(struct return_data));
  	struct pcap_pkthdr header; // The header that pcap gives us 
  	const u_char *packet; // A pointer to a packet in the trace
	char arg, *filename = NULL, *ip_address = NULL;
	
	int timestamp;
	int sizeEthernetHeader = sizeof(struct ethernet_header);
	int sizeIPHeader = sizeof(struct ip_header);
	int sizeTCPHeader = sizeof(struct tcp_header);
	int ch = 0;
	
  	// Check command line arguments 
  	if (argc < 5) {
		fprintf(stderr, "Usage: %s [-t pcap file] [-i ip address]\n", argv[0]);
		exit(1); 
  	}
	
	// Parse command line arguments
	while ((arg = getopt(argc, argv, "t:i:")) != -1) {
		switch (arg) {
			case 't':
				filename = optarg;
				break;
			case 'i':
				ip_address = optarg;
				break;
			default:
				break;
		}
	}

  	//open the pcap file
  	if ((handle = pcap_open_offline(filename, errbuf)) == NULL) { //call pcap library to read the file
  		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
		exit(1); 
   	}

	// The pcap_next function gives the pointer to the next packet
	while (packet = pcap_next(handle, &header)) {
		//fprintf(stdout, "Size of the packet captured by pcap is %d\n", header.len);
		//timestamp = (float)header.ts.tv_sec + (float)header.ts.tv_usec / 1000000.0;
		timestamp = (header.ts.tv_sec % 100) * 1000000 + header.ts.tv_usec;
		fprintf(stdout, "%d\t", timestamp);
		
		// Get another copy of the packet pointer, so you can modify it
		u_char *pktPtr = (u_char *)packet;
		
		// Get the IP header
		// We only consider TCP packets
		struct ip_header *ipHeader = (struct ip_header*)(pktPtr + sizeEthernetHeader);
		if (ipHeader->ip_p != IPPROTO_TCP) {
			fprintf(stdout, "\n");
			continue;
		}
		
		// Only consider traffic through our current machine
		// TODO also consider 80/443
		ch = 0;
		char *tmpAddr = inet_ntoa(ipHeader->ip_src);
		char srcAddr[20];
		sprintf(srcAddr, "%s", tmpAddr);
		char *dstAddr = inet_ntoa(ipHeader->ip_dst);
		if (strcmp(srcAddr, ip_address) == 0) {
			ch = OUTGOING;
			fprintf(stdout, "out\t%s\t", dstAddr);
		}
		if (strcmp(dstAddr, ip_address) == 0) {
			ch = INCOMING;
			fprintf(stdout, "in\t%s\t", srcAddr);
		}
		if (ch == 0) {
			fprintf(stdout, "\n");
			continue;
		}
		
		// Get the tcp header
		struct tcp_header *tcpHeader = (struct tcp_header*)(pktPtr + sizeEthernetHeader + sizeIPHeader);
		if (ch == OUTGOING)
			fprintf(stdout, "%d\t", ntohs(tcpHeader->th_sport));
		else
			fprintf(stdout, "%d\t", ntohs(tcpHeader->th_dport));

		// TODO figure out when to add 12
		int data_len = header.len - (sizeEthernetHeader + sizeIPHeader + (tcpHeader->header_length >> 2));
		fprintf(stdout, "%d\t", data_len);
		
		// Print flags
		if (tcpHeader->th_flags & 0x10)
			fprintf(stdout, "ACK ");
		if (tcpHeader->th_flags & 0x01)
			fprintf(stdout, "FIN ");
		if (tcpHeader->th_flags & 0x02)
			fprintf(stdout, "SYN ");
		
		// Print HTTP GET and Res
		if (data_len > 0 && ch == OUTGOING) {
			if (ntohs(tcpHeader->th_dport) == APP_SECURE_WEB) { // HTTPS
				fprintf(stdout, "\t%d", APP_SECURE_WEB);
			} else {
			char *pHTTP = pktPtr + sizeEthernetHeader + sizeIPHeader + (tcpHeader->header_length >> 2);
			int len = 0;
			while (len < data_len && *(pHTTP + len) != '\r') {
				len++;
			}
			char http[TCP_PAYLOAD_SIZE];
			memcpy(http, pHTTP, len);
			fprintf(stdout, "\t%s\n", http);
			}
		}
		
		fprintf(stdout, "\n");
	} // End internal loop for reading packets 
	
	pcap_close(handle);
	
  	return 0; // Done
} // End of main() function
