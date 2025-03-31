#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethheader {
  u_char  ether_dhost[6]; // 목적지 MAC
  u_char  ether_shost[6]; // 출발지 MAC
  u_short ether_type;     // 프로토콜 타입
};

struct ipheader {
  unsigned char iph_ihl:4, iph_ver:4; // 헤더 길이, IP 버전
  unsigned char iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  unsigned short int iph_flag:3, iph_offset:13;
  unsigned char iph_ttl;
  unsigned char iph_protocol; // TCP 여부 확인용
  unsigned short int iph_chksum;
  struct  in_addr iph_sourceip; // 출발지 IP
  struct  in_addr iph_destip;   // 목적지 IP
};

struct tcpheader {
    u_short tcp_sport;   // 출발지 포트
    u_short tcp_dport;   // 목적지 포트
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;   // 데이터 오프셋 추출에 사용
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷이면
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol == IPPROTO_TCP) { // TCP일 경우만
      int ip_header_len = ip->iph_ihl * 4;
      struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
      int tcp_header_len = ((tcp->tcp_offx2 & 0xf0) >> 4) * 4;

      const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
      int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

      //  출력
      printf("=======================================\n");

      // MAC
      printf("Src MAC: ");
      for (int i = 0; i < 6; i++) printf("%02x:", eth->ether_shost[i]);
      printf("\nDst MAC: ");
      for (int i = 0; i < 6; i++) printf("%02x:", eth->ether_dhost[i]);
      printf("\n");

      // IP
      printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
      printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

      // 포트
      printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
      printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));

      // 메시지 (Payload)
      printf("Message (payload): ");
      for (int i = 0; i < payload_len && i < 16; i++) {
        if (payload[i] >= 32 && payload[i] <= 126)
          printf("%c", payload[i]);
        else
          printf(".");
      }
      printf("\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // TCP만 필터링
  bpf_u_int32 net;

  // NIC 열기 (인터페이스가 enp0s5로 설정 되어 있어 이름을 변경)
  handle = pcap_open_live("enp0s5", BUFSIZ, 1, 1000, errbuf);

  // 필터 설정
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // 패킷 수집 시작
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;
  } 