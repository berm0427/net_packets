#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> // pcap 라이브러리를 사용하기 위한 헤더 파일, 네트워크 패킷 캡처 및 분석 기능 제공
#include <arpa/inet.h> // 네트워크 바이트 순서 변환 함수와 인터넷 주소 변환 함수를 사용하기 위한헤더 파일
#include "Sniffing_Spoofing/C_spoof/myheader.h" // 사용자 정의 헤더 파일 포함, 프로토콜 헤더 구조체 정의 포함

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
    printf("---------- 패킷 시작 ----------\n"); // 패킷 처리 시작

    struct ethheader *eth = (struct ethheader *)packet;

    // MAC 주소 출력
    printf("Ethernet Header:\n");
    printf("\tSrc MAC: ");
    for(int i = 0; i < 6; i++) 
    {
        printf("%02x", eth->ether_shost[i]);
        if(i < 5) printf(":");
    }
    printf("\n");

    printf("\tDst MAC: ");
    for(int i = 0; i < 6; i++) 
    {
        printf("%02x", eth->ether_dhost[i]);
        if(i < 5) printf(":");
    }
    printf("\n");

    // IP 정보 출력
    if (ntohs(eth->ether_type) == 0x0800) // IP 패킷인지 확인 
    { 
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // 이더넷 헤더 다음 IP가 있기 때문에 이더넷 크기 만큼 건너뛰고 IP 헤더 위치를 가리키게 함 
        printf("IP Header:\n");
	//IP주소 가져옴
        printf("\tFrom: %s\n", inet_ntoa(ip->iph_sourceip)); 
        printf("\tTo: %s\n", inet_ntoa(ip->iph_destip));

        if (ip->iph_protocol == IPPROTO_TCP) 
        {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl*4);

            printf("TCP Header:\n");
            printf("\tSrc Port: %d\n", ntohs(tcp->tcp_sport));
            printf("\tDst Port: %d\n", ntohs(tcp->tcp_dport));

            // TCP Payload 출력(IP 헤더 계산 후 더하고, TCP 헤더 계산 후 더해서 메세지 오프셋을 	       가리키도록 함)
            int header_size = sizeof(struct ethheader) + ip->iph_ihl*4 + TH_OFF(tcp)*4;

            int payload_size = ntohs(ip->iph_len) - header_size;

            printf("\tPayload (%d bytes):\n", payload_size);
            const u_char *payload = packet + header_size;

            // 메세지 길이 제한하여 출력
            if(payload_size > 0) 
            {
                int print_len = payload_size > 20 ? 20 : payload_size; // 20바이트로 출력 길이			제한
                for(int i = 0; i < print_len; i++) 
                {
                    printf("%02x ", payload[i]); // 16진수 2자리씩 출력
                }
                printf("...\n"); // 생략 되었음을 나타내고 개행
            }
        }
    }
    printf("----------- 패킷 끝 -----------\n\n"); // 패킷 처리 끝
}


int main() 
{
    pcap_t *handle; // pcap 핸들 선언 
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메세지 버퍼 선언
    struct bpf_program fp; // 필터 표현식
    char filter_exp[] = "tcp"; // TCP 프로토콜 패킷만 캡처하도록 설정
    bpf_u_int32 net; //
    // NIC에서의 실시간 pcap session을 "enp0s3"이란 이름으로 열기
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // 무작위 모드로 패킷 캡처를 작동하게 하는 구문
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device enp0s3: %s\n", errbuf);
        return 2;
    }
    // tcp를 내부 형식으로 컴파일하여 저장
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    // 필터 작동
    if (pcap_setfilter(handle, &fp) == -1) 
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    // 필터를 바탕으로 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); // 핸들 종료
    return 0;
}

