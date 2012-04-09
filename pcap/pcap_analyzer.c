/**
 * CSE461 au11 homework 4 DNS
 *
 * Print out all dns delays
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

  	struct pcap_pkthdr header; // The header that pcap gives us 
  	const u_char *packet; // A pointer to a packet in the trace
	
	struct return_data *metadata = (struct return_data *)malloc(sizeof(struct return_data));
	char arg, *filename = NULL, *mac_address = NULL;
  
	int totalPackets; //keeps track of the number of packets
	double beginTime, endTime;
	
	// For profiling traffic
	int dnsdelays_s[MAX_SITES], dnsdelays_e[MAX_SITES];
	char sites[MAX_SITES][PAYLOAD_LEN];
	int counter_s = 0, i; // counter of sites
	
	memset(sites, '0', sizeof(sites));
	memset(dnsdelays_s, 0, sizeof(dnsdelays_s));
	memset(dnsdelays_e, 0, sizeof(dnsdelays_e));
	
  	// Check command line arguments 
  	if (argc < 3) {
#if DEBUGGING
		fprintf(stderr, "Usage: %s [-t pcap file]\n", argv[0]);
#endif
		exit(1); 
  	}
	
	// Parse command line arguments
	while ((arg = getopt(argc, argv, "t:")) != -1) {
		switch (arg) {
			case 't':
				filename = optarg;
				break;
			default:
				break;
		}
	}
  
  	//----------------- 
  	//open the pcap file
  	if ((handle = pcap_open_offline(filename, errbuf)) == NULL) { //call pcap library to read the file
#if DEBUGGING
  		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
#endif
		exit(1); 
   	}
     
	totalPackets = 0; // Initialize the number of packets read to 0
	beginTime = -1;

	// The pcap_next function gives the pointer to the next packet
	while (packet = pcap_next(handle, &header)) {
		// Increment the number of packets seen
		totalPackets++;
		
#if DEBUGGING
		fprintf(stdout, "Packet number: %d\n", totalPackets);
		fprintf(stdout, "Size of the packet captured by pcap is %d\n", header.len);
#endif
		if (beginTime < 0){
			beginTime = header.ts.tv_sec+(header.ts.tv_usec/1000000.0);
		}
		
		// Get another copy of the packet pointer, so you can modify it
		u_char *pktPtr = (u_char *)packet; 

		// Get the dns header
		// 42 = sizeEthernetHeader + sizeIPHeader + sizeUDPHeader
		struct dns_header *dheader = (struct dns_header*)(pktPtr + 42);
		
		// Get whether this is a request or a response
		// The leftmost bit indicates whether this is a request or response
		int is_response = ntohs(dheader->flags) >> 15;
		
		// Get the dns payload
		// 54 = sizeEthernetHeader + sizeIPHeader + sizeUDPHeader + sizeDNSHeader
		char *payload = (char *)(pktPtr + 54);
		
		for (i = 0; i < counter_s; i++) {
			if (strcmp(payload, sites[i]) == 0) {
				// We've got this before
				break;
			}
		}
		
		// The first time we got this domain name
		if (i == counter_s) {
			memcpy(sites[i], payload, PAYLOAD_LEN);
			counter_s++;
		}
		
		// This is the first request of this domain
		if (!is_response && dnsdelays_s[i] == 0) {
			// We don't have to worry about overflow here because the response should be overflowed as well
			dnsdelays_s[i] = 1000000 * header.ts.tv_sec + header.ts.tv_usec;
		}
		
		// This is the first response of this domain
		if (is_response && dnsdelays_e[i] == 0) {
			dnsdelays_e[i] = 1000000 * header.ts.tv_sec + header.ts.tv_usec;
		}

		
#if DEBUGGING
		printf("body: %d\n", is_response);
		printf("payload: %s\n", payload);
		printf("time: %d\n", header.ts.tv_sec);
		fprintf(stdout, "\n\n");
#endif
 
	} // End internal loop for reading packets 
	
	pcap_close(handle);  // Close the pcap file 
 
	//---------- Done with Main Packet Processing Loop --------------  
 
	endTime = header.ts.tv_sec+(header.ts.tv_usec/1000000.0);
	
	// Total time in the trace
	double traceDuration = endTime - beginTime;
	
	
#if !DEBUGGING
	//printf("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<report>\n<description></description>\n");
#endif
	
	for (i = 0; i < counter_s; i++) {
		if (dnsdelays_s[i] == 0 || dnsdelays_e[i] == 0) {
			continue;
		}
#if DEBUGGING
		printf("domain: %s\n", sites[i]);
		printf("delay: %d\n", dnsdelays_e[i] - dnsdelays_s[i]);
		printf("start time: %d\n", dnsdelays_s[i]);
		printf("end time: %d\n\n", dnsdelays_e[i]);
#else
		printf("%d\n", (dnsdelays_e[i] - dnsdelays_s[i])/1000, sites[i]); // in milliseconds
#endif
	}
	
#if DEBUGGING
	printf("duration: %f\n", traceDuration);
#else
	//printf("</report>\n");
#endif

  	return 0; // Done
} // End of main() function
