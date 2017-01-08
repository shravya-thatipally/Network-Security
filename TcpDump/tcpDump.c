#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include<netinet/ether.h>


#define SIZE_ETHERNET 14
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)


typedef enum { false, true } boolean;

/* Ethernet*/
struct ethernet
{
	u_char  ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;					 /* IP? ARP? RARP? etc */
};
/* IP header */
struct s_ip
{
	u_char  ip_vhl;				 /* version << 4 | header length >> 2 */
	u_char  ip_tos;				 /* type of service */
	u_short ip_len;				 /* total length */
	u_short ip_id;				  /* identification */
	u_short ip_off;				 /* fragment offset field */
#define IP_RF 0x8000			/* reserved fragment flag */
#define IP_DF 0x4000			/* dont fragment flag */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff	   /* mask for fragmenting bits */
	u_char  ip_ttl;				 /* time to live */
	u_char  ip_p;				   /* protocol */
	u_short ip_sum;				 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
/* UDP header */
struct s_udp {
	u_short sport;	/* source port */
	u_short dport;	/* destination port */
	u_short udp_length;
	u_short udp_sum;	/* checksum */
};
/* TCP header */
typedef u_int tcp_seq;
struct s_tcp
{
	u_short th_sport;			   /* source port */
	u_short th_dport;			   /* destination port */
	tcp_seq th_seq;				 /* sequence number */
	tcp_seq th_ack;				 /* acknowledgement number */
	u_char  th_offx2;			   /* data offset, rsvd */
#define TH_OFF(th)	  (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS		(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;				 /* window */
	u_short th_sum;				 /* checksum */
	u_short th_urp;				 /* urgent pointer */
};

void print_hex(const u_char *payload, int l) {
	int i=0;
	int g;
	const u_char *c;
	c = payload;
	while(i < l) {
		printf("%02x ", *c);
                    
		c++;
                  i++;
		
	}
	
	if (l< 8)
		printf(" ");
	if (l < 16) {
		g = 16 - l;
		for(i=0; i < g;i++) {
			printf("   ");
                          
		}
	}
	printf("   ");

	
	c = payload;
	for(i = 0;i < l; i++) {
		if (isprint(*c))
			printf("%c", *c);
		else
			printf(".");
		c++;
	}

	printf("\n");

	return;
}

void get_payload(const u_char *payload, int length) {
	const u_char *c = payload;
       int r_length = length,line_width = 16,line_length;
	
	if (length <= 0)
		return;

	if (length <= line_width) {
		print_hex(c, length);
		return;
	}

	//for many lines
	while(1) {
		
		line_length = line_width % r_length;

		print_hex(c, line_length);

		r_length= r_length - line_length;
		c = c + line_length;
		if (r_length<= line_width) {
			
			print_hex(c, r_length);
			break;
		}
	}

	return;
}

// packet info display
void packet_info(boolean http, char *string, const struct pcap_pkthdr *header,
	const u_char *packet) {
	
	const struct ethernet *e;
	const struct s_ip *ip;
	const struct s_tcp *tcp;
	const struct s_udp *udp;
	const char *payload;
	int size_ip,size_tcp,size_udp = 8,size_icmp = 8,size_payload,a;

	time_t t = (time_t)header->ts.tv_sec;
	char *ptr = ctime(&t);
	char buf[200];
	strcpy(buf, ptr);
	buf[strlen(buf)-1] = 0;
	printf("%s ", buf);
	
	e = (struct ethernet*)(packet);
	a=ntohs(e->ether_type);
	if (a == ETHERTYPE_IPV4) {

                 printf("%s -> ", ether_ntoa((struct ether_addr *)&e->ether_shost));
                        printf("%s ",ether_ntoa((struct ether_addr *)&e->ether_dhost));

		ip = (struct s_ip*)(packet + SIZE_ETHERNET);
		size_ip = (((ip)->ip_vhl) & 0x0f)*4;
                    printf(" IPv4 ");
		if (size_ip < 20) {
			printf("IP header length: %u bytes\n", size_ip);
			return;
		}
		
	
		if (ip->ip_p == IPPROTO_TCP) {
			tcp = (struct s_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
                        printf("TCP ");
			if (size_tcp < 20) {
				printf("TCP header length: %u bytes\n", size_tcp);
				return;
			}
			printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
                        printf("%s.%d",inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

			printf(" len %d ", ntohs(ip->ip_len));
                        if (tcp->th_flags & TH_ECE){
        		printf("   Flag: TH_ECE");
    					}
    			if (tcp->th_flags & TH_RST){
       			 printf("   Flag: TH_RST");
    		                        }
                        if (tcp->th_flags & TH_SYN){
                        printf("   Flag: TH_SYN");
                                        }
			if (tcp->th_flags & TH_FIN){
        		printf("   Flag: TH_FIN");
   				        }
			if (tcp->th_flags & TH_PUSH){
        		printf("   Flag: TH_PUSH");
    					}
			if (tcp->th_flags & TH_ACK){
        		printf("   Flag: TH_ACK");
    					}
			if (tcp->th_flags & TH_URG){
        		printf("   Flag: TH_URG");
    					}
			if (tcp->th_flags & TH_CWR){
        		printf("   Flag: TH_CWR");
    				        }
			
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			
			// print payload
			if (size_payload > 0) {
				printf("	Payload (%d bytes):\n", size_payload);
				
				if (string != NULL) {
					if (strstr(payload, string) == NULL)
						return;
				}
				
				if (http) {
					char tmp[strlen(payload)];
					strcpy(tmp, payload);
					char *ptr = strtok(tmp, " ");
					ptr = strtok(NULL, " ");
					printf("%s\n", ptr);
				} else {
					get_payload(payload, size_payload);
				}
			}
			printf("\n");
		} else if (ip->ip_p == IPPROTO_UDP) {
			printf("UDP ");
			udp = (struct s_udp*)(packet + SIZE_ETHERNET + size_ip);
			
			printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
                                 printf("%s.%d" , inet_ntoa(ip->ip_dst), ntohs(udp->dport));
			printf(" len %d ", ntohs(ip->ip_len));
			
		
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
			
			
			if (size_payload > 0)
			{
				printf("Payload (%d bytes):\n", size_payload);
				get_payload(payload, size_payload);
			}
			printf("\n");
		} else if (ip->ip_p == IPPROTO_ICMP) {
			printf("ICMP ");
			
			printf("%s -> ", inet_ntoa(ip->ip_src));
                        printf("%s",inet_ntoa(ip->ip_dst));
			printf(" len %d ", ntohs(ip->ip_len));
			
			
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
			
			
			if (size_payload > 0)
			{
				printf("Payload (%d bytes):\n", size_payload);
				get_payload(payload, size_payload);
			}
			printf("\n");
		} 

         else {
			printf("OTHER ");
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
			size_payload = ntohs(ip->ip_len) - (size_ip);
		
			if (size_payload > 0)
			{
				printf("Payload (%d bytes):\n", size_payload);
				get_payload(payload, size_payload);
			}
			printf("\n");
		}
	} else if (a == ETHERTYPE_ARP) {
		printf("ARP\n");
	} else {
		printf("OTHER\n");
	}
	
	return;
}

// callback function for pcap_loop
void my_callback(u_char *string, const struct pcap_pkthdr *header, const u_char *packet) {

	boolean http = false;
	char *s = NULL;
	if (string != NULL) {
		char g = *string;
		if (g == 'g') {
			http = true;
			if (strlen(string+1) > 0) {
				s = string + 1;
	
			}
			
		} else {
			s = string;
		
		}
	}
	
	if (s == NULL)
		packet_info(http, s, header, packet);
	else {
	
		const struct ethernet *ethernet;
		const struct s_ip *ip;
		const struct s_tcp *tcp;
		const struct s_udp *udp;
		const char *payload;
		
		int size_ip,size_tcp,size_udp = 8,size_icmp = 8,a; 
		int size_payload;
		

		ethernet = (struct ethernet*)(packet);
		a=ntohs(ethernet->ether_type);
		if (a == ETHERTYPE_IPV4) {

			ip = (struct s_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				return;
			}
		
			if (ip->ip_p == IPPROTO_TCP) {
				tcp = (struct s_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
                                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
				if (size_tcp < 20) {
					return;
				}
				
				if (size_payload > 0) {
					char s_payload[size_payload];
					strncpy(s_payload, payload, size_payload);
					
					if (strstr(s_payload, s) == NULL)
						return;
					else
						packet_info(http, s, header, packet);
				} else {
					return;
				}
			} else if (ip->ip_p == IPPROTO_UDP) {
				udp = (struct s_udp*)(packet + SIZE_ETHERNET + size_ip);
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
				if (size_payload > 0) {
					char s_payload[size_payload];
					strncpy(s_payload, payload, size_payload);
					
					if (strstr(s_payload, s) == NULL)
						return;
					else
						packet_info(http, s, header, packet);
				} else {
					return;
				}
			} else if (ip->ip_p == IPPROTO_ICMP) {
				
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
				
				// print payload
				if (size_payload > 0) {
					char s_payload[size_payload];
					strncpy(s_payload, payload, size_payload);
					
					if (strstr(s_payload, s) == NULL)
						return;
					else
						packet_info(http, s, header, packet);
				} else {
					return;
				}
			} else {
		
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
				size_payload = ntohs(ip->ip_len) - (size_ip);
				
				
				if (size_payload > 0)
				{
					char s_payload[size_payload];
					strncpy(s_payload, payload, size_payload);
					
					if (strstr(s_payload, s) == NULL)
						return;
					else
						packet_info(http, s, header, packet);
				} else {
					return;
				}
			}
		}
	}
}

int main(int argc, char *argv[]) {
	int p= 0,count = -1;
	char *i = NULL, *f = NULL,*s = NULL,*expression = NULL;
	boolean http = false;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program filter;
        bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;
	// filter for http get and post
	char http_string[] = "(tcp port http) && ((tcp[32:4] = 0x47455420) || \
		(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354))";



	while ((p = getopt(argc, argv, "i:r:s:g")) != -1) {
		switch(p) {
			case 'i':
				i = optarg;
				
				break;
			case 'r':
				f = optarg;
				
				break;
			case 's':
				s = optarg;
				
				break;
			case 'g':
			       
				http = true;
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'i') {
					printf("Please specify interface!\n");
					return 0;
				} else if (optopt == 'r') {
					printf("Please specify file name!\n");
					return 0;
				} else if (optopt == 's') {
					printf("Please specify match string!\n");
					return 0;
				} else {
					printf("Unknown argument!\n");
					return 0;
				}
			default:
				printf("Default case?!\n");
				return 0;
		}
		
	}
	
	// get expression
	if (optind == argc - 1)
		expression = argv[optind];
else if (optind < argc -1) {
		printf("Too many arguments. Exiting...\n");
		return 0;
	}
	
	if (i!= NULL && f != NULL) {
		printf("You cannot use interface and file!\n");
		return 0;
	}
	
	if (i == NULL && f == NULL) {
		i = pcap_lookupdev(errbuf);
		if (i == NULL) {
			printf("Error message: %s\n\
			Exiting...\n", errbuf);
			return 0;
		}
	}
	
	printf("\nMydump parameters:\ninterface: %s\tfile: %s\tstring: %s\thttp sniffer mode: %s\texpression: %s\n\n\n", i, f, s,\
		http ? "true" : "false", expression);
	
	//if interface is given
	if (i != NULL && f == NULL) {
		
		if (pcap_lookupnet(i, &net, &mask, errbuf) == -1) {
			printf("Error: %s\n", errbuf);
			net = 0;
			mask = 0;
		}
		// Start pcap session
		handle = pcap_open_live(i, BUFSIZ, 1, 1000, errbuf);

		if (handle == NULL) {
			printf("Error message: %s\n\
			Existing...\n", errbuf);
			return 0;

		}
	} else if (i == NULL && f != NULL) {
		handle = pcap_open_offline(f, errbuf);
		if (handle == NULL) {
			printf("Error message: %s\n\
			Existing...\n", errbuf);
			return 0;
		}
	} else {
		printf("This shouldn't be printed out! Existing...\n");
		return 0;
	}
	
	// check if link-layer header is ethernet
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Interface %s doesn't  ethernet header! Existing\n", i);
		return 0;
	}
	
	
	if (http) {
		
		if (pcap_compile(handle, &filter, http_string, 0, net) == -1) {
			printf("Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
		
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
	}
	
	// compile and apply expression
	if (expression != NULL) {
		
		if (pcap_compile(handle, &filter, expression, 0, net) == -1) {
			printf("Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
		
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
	}
	
	
	if (http) {
		int len = 0;
		if (s != NULL)
			len = strlen(s);
		char *t = (char *)malloc(len+2);
		strcpy(t, "g");
		if (s != NULL)
			strcat(t, s);
		pcap_loop(handle, count, my_callback, t);
	} else {
		pcap_loop(handle, count, my_callback, s);
	}
	
	
	pcap_close(handle);
	
	return 0;
}
