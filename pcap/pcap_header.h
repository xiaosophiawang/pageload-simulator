// Define all header files here
#define	ETHER_ADDR_LEN		6
#define PAYLOAD_LEN			100
#define	MAC_ADDR_LEN		18
#define MAX_SITES			1000

// Network layer protocols
#define	ETHERTYPE_IP		0x0800
#define	ETHERTYPE_ARP		0x0806
#define	ETHERTYPE_REVARP	0x8035
#define	ETHERTYPE_IPv6		0x86dd

// Transport layer protocols
#define IPPROTO_TCP			6
#define IPPROTO_UDP			17
#define IPPROTO_ICMP		1
#define IPPROTO_VRRP		112

// Application ports
#define APP_WEB				80
#define APP_SECURE_WEB		443
#define APP_DNS				53

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

// Structure of a TCP header
struct tcp_header {
	unsigned short  th_sport;	/* source port */
	unsigned short  th_dport;	/* destination port */
	uint32_t th_seq;			/* sequence number */
	uint32_t th_ack;			/* acknowledgement number */
	u_char header_length;		/* data offset, rsvd */
#define TH_OFF(th)	(((th)->header_length & 0xf0) >> 4)
	unsigned char   th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short  th_win;		/* window */
	unsigned short  th_sum;		/* checksum */
	unsigned short  th_urp;		/* urgent pointer */
};

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
