#include <ctype.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    
    u_char  ether_shost[6];    
    u_short ether_type;        
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, iph_ver:4;
  unsigned char      iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  unsigned short int iph_flag:3, iph_offset:13;
  unsigned char      iph_ttl;
  unsigned char      iph_protocol;
  unsigned short int iph_chksum;
  struct  in_addr    iph_sourceip;
  struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;  
    u_short tcp_dport;  
    u_int   tcp_seq;    
    u_int   tcp_ack;    
    u_char  tcp_reserved:4;
    u_char  tcp_hlen:4;  
    u_char  tcp_flags;
    u_short tcp_win;    
    u_short tcp_sum;    
    u_short tcp_urp;    
};

/* Message */
struct message{
	u_char payload[16];
};


void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    //struct ipheader *ip = (struct ipheader*)(packet + sizeof(struct ethheader));
    //    printf((char*)packet);

/*   struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
    
    // Ethernet 정보 출력
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // IP 정보 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP 포트 정보 출력
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    printf("\n");
*/    
    // MAC 주소 변환
    struct ether_addr src_mac, dst_mac;
    memcpy(&src_mac, eth->ether_shost, 6);
    memcpy(&dst_mac, eth->ether_dhost, 6);
    // MAC주소 출력
    printf("Source MAC: %s\n", ether_ntoa(&src_mac));
    printf("Destination MAC: %s\n", ether_ntoa(&dst_mac));

    if (ntohs(eth->ether_type) != 0x0800) return; // IPv4만 처리

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    // IP 헤더 길이 검사
    int ip_header_length = ip->iph_ihl * 4;
    if (ip_header_length < 20 || ip_header_length > 60) {
        printf("Invalid IP header length: %d\n", ip_header_length);
        return;
    }
    // Ip 주소 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol != IPPROTO_TCP) return; // TCP만 처리

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length); // 
    // TCP port 출력
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
    printf("\n");

//TCP 페이로드 시작위치
int tcp_header_length = tcp->tcp_hlen * 4;
const u_char *payload = packet + sizeof(struct ethheader) + (ip_header_length) + tcp_header_length;
int payload_size = ntohs(ip->iph_len) - (ip_header_length) - tcp_header_length;
	if (payload_size > 0) {
                printf("Payload (%d bytes):\n", payload_size);
                for (int i = 0; i < payload_size; i++) {
                    if (isprint(payload[i])) // 출력 가능한 문자만 표시
                        printf("%c", payload[i]);
                    else
                        printf(".");
                }
                printf("\n");
            } else {
                printf("No Payload\n");
            }
            printf("=========================================\n");

//    for (int i=0; i< header->len; i++){
//	printf("%02x", packet[i]);
//    }
/* 
    int tcp_header_length = tcp->tcp_hlen * 4;
    struct message *msg = (struct message *)(packet + sizeof(struct ethheader) + ip_header_length + tcp_header_length);
    
    //char datalen = packet - sizeof(struct ethheader) + ip_header_length + tcp_header_length;
    if(header->len != 0){
	    printf("message: ");
    for(int i = 0; i < header->len; i++){
	    if(i == 16) break;
    printf("%02x\n", msg->payload[16]);
     }
    }*/
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 사용 가능한 네트워크 인터페이스 확인 후 변경 필요
    char *dev = "enp0s3";  // 변경 필요할 수도 있음

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}

