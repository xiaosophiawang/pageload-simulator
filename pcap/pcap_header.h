// Define all header files here
#define	ETHER_ADDR_LEN		6
#define PAYLOAD_LEN			100
#define	MAC_ADDR_LEN		18
#define MAX_SITES			1000

// Other define
#define DEBUGGING			0 // Switch to print debugging info, should be 0 if printing the report

// Structure of an Ethernet header
struct	ethernet_header {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
} ;

// Structure of an IP header
struct ip_header {
	u_char  ip_vhl;			/* version << 4 | header length >> 2 */
	u_char  ip_tos;			/* type of service */
	u_short ip_len;			/* total length */
	u_short ip_id;			/* identification */
	u_short ip_off;			/* fragment offset field */
	u_char  ip_ttl;			/* time to live */
	u_char  ip_p;			/* protocol */
	u_short ip_sum;			/* checksum */
	struct in_addr ip_src;  /* source and dest address */
	struct in_addr ip_dst;
};

#define IP_VHL_HL(vhl)          ((vhl) & 0x0f)
#define IP_VHL_V(vhl)           ((vhl) >> 4)

// Structure of a UDP header
struct udp_header {
	u_short uh_sport;			/* source port */
	u_short uh_dport;			/* destination port */
	u_short uh_ulen;			/* udp length */
	u_short uh_sum;				/* udp checksum */
};

// Structure of a DNS header
struct dns_header {
	u_short transaction_id;
	u_short flags;
	u_short questions;
	u_short answer_rrs;
	u_short authority_rrs;
	u_short additional_rrs;
};

// Structure of metadata that is calculated from each packet
struct return_data {
	u_short direction;			/* incoming or outgoing */
	u_short kind;				/* UDP, TCP, etc */
	int  bytes_length;
	u_char	s_mac_address[MAC_ADDR_LEN];		/* Mac address of the sender device */
	u_char	d_mac_address[MAC_ADDR_LEN];		/* Mac address of the receiver device */
};
