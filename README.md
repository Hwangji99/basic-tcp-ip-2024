# basic-tcp-ip-2024
IoT 개발자 과정 TCP/IP 리포지토리


## 1일차(2024-06-11)
- IPv4
    - 내 컴퓨터의 인터넷 주소
    - 8bit(1byte)가 4개 모여서 주소를 이룸(총 32bit)
    - 2011년 2월 4일부터 모든 IPv4의 주소가 소진되면서 IPv4의 할당이 중지되었다
- IPv6
    - IPv4의 제한된 주소 공간으로 주소가 거의 소진되자 대안으로 나온 프로토콜
    - 128비트의 주소 공간을 제공
    - 일반적으로 4자리의 16진수 숫자 8개로 표기하며 쌍점(:)으로 구분

- TCP (Transmission Control Protocol) 설명
    - OSI 네트워크 계층 모델 중 전송 계층에서 사용하는 프로토콜로 가상회선 방식으로 패킷을 교환함
    - 장치들 사이에 연결과 데이터의 전송/제어 기능을 통해서, 데이터 전송의 신뢰성을 보장
    - point to point 연결 방식으로 전이중/양방향에서 데이터 전송이 가능

    - TCP

    <img src="https://github.com/Hwangji99/basic-tcp-ip-2024/blob/main/images/ni001.png" width=600>


- 소말리아
    - 소 -> 소켓(socket) : 휴대폰 기기
        - 프로그램이 네트워크에서 데이터를 주고받을 수 있도록 네트워크 환경에 연결할 수 있게 만들어진 연결부
        - 입력 3개를 가진 함수
        - int 타입의 출력과 입력
        - 성공 시 파일 디스크립터, 실패 시 -1 반환
    - 말 -> 바인더(bind) : 개통을 위한 전화번호
        - 입력 3개를 가진 함수
        - int 타입의 출력과 입력
        - 성공 시 0, 실패 시 -1 반환
    - 리 -> 리슨(listen) : 개통이 완료된 상태
        - 입력 2개를 가진 함수
        - int 타입의 출력과 입력
        - 성공 시 0, 실패 시 -1 반환
    - 아 -> 엑셉트(accept) : 개통이 완료된 후 다른 상대방과 통화하는 것
        - 입력 3개를 가진 함수
        - 성공 시 파일 디스크립터, 실패 시 -1 반환


- 서버 프로그램 구현, 소켓 구현, 리눅스 실행

- 리눅스 기반 파일 조작하기
    - 파일 열기(open)
        - 2개의 입력값을 받고 int로 출력한다
        - 성공시 파일 디스크립터, 실패 시 -1 반환
        - path : 파일 이름을 나타내는 문자열의 주소 값 전달
        - flag : 파일의 오픈 모드 정보 전달

    - 파일 닫기(close)
        - 파일은 사용 후 반드시 닫아줘야 한다
        - 성공 시 0, 실패 시 -1 반환

    - 파일에 데이터 쓰기(write)
        - 성공 시 전달한 바이트 수, 실패 시 -1 반환
        - fd : 데이터 전송 대상을 나타내는 파일 디스크립터 전달
        - buf : 전송할 데이터가 저장된 버퍼의 주소 값 전달
        - nbytes : 전송할 데이터의 바이트 수 전달

    - 파일에 저장된 데이터 읽기(read)
        - 성공 시 수신한 바이트 수(단 파일의 끝을 만나면 0), 실패 시 -1 반환
        - fd : 데이터 수신 대상을 나타내는 파일 디스크립터 전달
        - buf : 수신한 데이터를 저장할 버퍼의 주소 값 전달
        - nbytes : 수신할 최대 바이트 수 전달

- 프로토콜(Protocol)
    - 대화에 필요한 통신규약
    - 쉽게 말해 서로 데이터를 주고받기 위해서 정의해 놓은 약속을 뜻함
    - 소켓의 생성
    - int socket(int domain, int type, int protocol):
        - 성공 시 파일 디스크립터, 실패 시 -1 반환
        - domain : 소켓이 사용할 프로토콜 체계(Protocol Family) 정보 전달
        - type : 소켓의 데이터 전송방식에 대한 정보 전달
        - protocol : 두 컴퓨터 간 통신에 사용되는 프로토콜 정보 전달
    - 프로토콜 체계
        - PF_INET : IPv4 인터넷 프로토콜 체계
        - PF_INET6 : IPv6 인터넷 프로토콜 체계
        - PF_LOCAL : 로컬 통신을 위한 UNIX 프로토콜 체계
        - PF_PACKET : Low Level 소켓을 위한 프로토콜 체계
        - PF_IPX : IPX 노벨 프로토콜 체계

    - 소켓의 타입
        - 연결지향형 소켓(SOCK_STREAM) -> TCP
            - 중간에 데이터가 소멸되지 않고 목적지로 전송된다
            - 전송 순서대로 데이터가 수신된다
            - 전송되는 데이터의 경계(Boundary)가 존재하지 않는다
        - 비연결지향형 소켓(SOCK_DGRAM) -> UDP
            - 전송된 순서에 상관없이 가장 빠른 전송을 지향한다
            - 전송된 데이터는 손실의 우려가 있고, 파손의 우려가 있다
            - 전송되는 데이터의 경계(Boundary)가 존재한다
            - 한번에 전송할 수 있는 데이터의 크기가 제한된다

- 주소체계와 데이터 정렬
    - 소켓에 할당되는 IP주소와 PORT번호
        - IP : 인터넷 상에서 데이터를 송수신할 목적으로 컴퓨터에게 부여하는 값
        - PORT : 컴퓨터에게 부여하는 값이 아닌, 프로그램상에서 생성되는 소켓을 구분하기 위해 소켓에 부여되는 번호

        - 클래스 별 네트워크 주소와 호스트 주소의 경계
            - 클래스 A의 첫 번째 바이트 범위 : 0 이상 127 이하
            - 클래스 B의 첫 번째 바이트 범위 : 128 이상 191 이하
            - 클래스 C의 첫 번째 바이트 범위 : 192 이상 223 이하
        - 다른 표현
            - 클래스 A의 첫 번째 비트는 항상 0으로 시작
            - 클래스 B의 첫 두 비트는 항상 10으로 시작
            - 클래스 C의 첫 세 비트는 항상 110으로 시작
        
    - IPv4 주소체계

    <img src="https://github.com/Hwangji99/basic-tcp-ip-2024/blob/main/images/ni002.png?raw=true" width=600>


    - 주소 정보의 표현
        - IPv4 기반의 주소표현을 위헌 구조체
        ```c
        struct sockaddr_in
        {
            sa_family_t     sin_family; // 주소체계(Address Family)
            uint16_t        sin_port;   // 16비트 TCP/UDP PORT번호
            struct in_addr  sin_addr    // 32비트 IP주소
            char            sin_zero[8] // 사용되지 않음
        }

        struct in_addr
        {
            in_addr_t       s_addr;     // 32비트 IPv4 인터넷 주소
        };
        ```

        - 멤버 sin_family
            - AF_INET, AF_INET6, AF_LOCAL
    
    - 네트워크 바이트 순서와 인터넷 주소 변환
        - 빅 엔디안 
            - 상위 바이트의 값을 작은 번지수(제일 왼쪽)에 저장하는 방식
            - 하위 바이트의 값을 큰 번지수(제일 오른쪽)에 저장하는 방식
        - 리틀 엔디안
            - 상위 바이트의 값을 큰 번지수(제일 오른쪽)에 저장하는 방식
            - 하위 바이트의 값을 작은 번지수(제일 왼쪽)에 저장하는 방식


        <img src="https://github.com/Hwangji99/basic-tcp-ip-2024/blob/main/images/ni003.png" width=600>


    - 인터넷 주소의 초기화와 할당

## 2일차(2024-06-12)
- 주소체계와 데이터 정렬
    - 인터넷 주소의 초기화와 할당
        - 정수형태의 IP 정보를 문자열 형태의 IP정보로 변환

    - inet_ntoa 함수
    ```C
    #include <arpa/inet.h>
    char * inet_ntoa(struct in_addr adr);
    // 성공 시 반환된 문자열의 주소값
    ```
    - 인터넷 주소의 초기화
        - memset 함수
        - 구조체 변수의 멤버들을 초기화하는 함수
        ```C
        memset(&addr, 0, sizeof(addr)); // 구조체 변수 addr의 모든 멤버 0으로 초기화
        // 0으로 초기화하는 이유 : 구조체 멤버 sin_zero를 0으로 초기화 하기 위함
        ```
    - INADDR_ANY

        - 소켓이 동작하는 컴퓨터의 IP주소가 자동으로 할당되어 IP주소를 직접 입력하는 수고를 절감
        ```C
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port=htons(atoi(serv_port));
        ```

    - 소켓에 인터넷 주소 할당하기

        - bind 함수
        ```C
        #include <sys/socket.h>
        int bind(int sockfd, struct sockaddr *myaddr, socklen_t addrlen)
        // sockfd : 소켓의 파일 디스크립터, myaddr : 할당당하고자 하는 주소정보를 지니는 구조체 변수의 주소값, addrlen : 구조체 변수의 길이정보
        // 성공시 0, 실패시 -1 반환
        ```

- TCP 기반 서버/클라이언트 1
    - TCP와 UDP에 대한 이해
        - TCP/IP 프로토콜 스택


        <img src="https://github.com/Hwangji99/basic-tcp-ip-2024/blob/main/images/ni004.png?raw=true">


        - LINK 계층

        - IP 계층

            - 목적지로 데이터를 전송하기 위한 경로
            - 하나의 데이터 패킷이 전송되는 과정에만 중점
            IP 자체는 비 연결지향적이며 신뢰할 수 없는 프로토콜이기
            - 데이터 손실 또는 오류 발생 문제 가능성

        - TCP/UDP 계층
            - IP 계층에서 알려준 경로 정보를 바탕으로 실제 데이터를 송수신을 담당하는 '전송(Transport) 계층'
            - TCP
                - 데이터가 무사히 전달되었는지 확인하여 신뢰성 있는 데이터 전송을 담당
                - 분실된 데이터에 대해 재전송을 요청
- TCP기반 서버, 클라이언트 구현
    - TCP 서버에서의 기본적인 함수 호출 순서
        - socket() -> bind() -> listen() -> accept() -> read()/write() -> close()

    - 연결요청 대기 상태(listen 함수)
        - 클라이언트가 서버의 서버 ㅡ 소켓에 연결요청을 하고 연결요청 대기큐에서 대기상태로 진입
        ```C
        #include <sys/socket.h>
        int listen(int sock, int backlog);
        // sock : 연결요청 대기상태에 두고자 하는 소켓의 파일 디스크립터 -> 서버소켓
        // backlog : 연결요청 대기 큐(Queue)의 크기정보
        // 성공시 0, 실패시 -1
        ```
        
    - 클라이언트의 연결 요청 수락(accept 함수)
        - '연결요청 대기 큐'에서 대기중인 클라이언트의 연결요청 수락
        - 호출 성공 시 내부적으로 데이터 입출력에 사용할 클라이언트 소켓을 생성하고, 그 소켓의 파일 디스크립터 반환
        ```C
        #include <sys/socket.h>
        int accept(int sock, struct sockaddr * addr, socklen_t * addrlen);
        // sock : 서버 소켓의 파일 디스크립터
        // addr : 연결 요청을 한 클라이언트의 주소정보를 담을 변수의 주소값
        // addrlen : addr에 전달된 주소의 변수 크기(바이트 단위)
        // 성공 시 생성된 소켓의 파일 디스크립터, 실패 시 -1
        ```

    - TCP 클라이언트의 기본적인 함수 호출 순서
        - socket() -> connect() -> read()/write() -> close()
        - connect 함수
        ```C
        #include <sys/socket.h>
        int connect(int sock, struct sockaddr * servaddr, socklen_t addrlen);
        // sock : 클라이언트 소켓의 파일 디스크립터
        // servaddr : 연결 요청 할 서버의 주소정보를 담은 변수의 주소값
        // addrlen : servaddr에 전달된 주소의 변수 크기(바이트 단위)
        // 성공 시 0, 실패 시 -1
        ```

    - TCP 기반 서버, 클라이언트의 함수호출 관계


    <img src="https://github.com/Hwangji99/basic-tcp-ip-2024/blob/main/images/ni005.png?raw=true">


    - TCP 기반 서버/클라이언트 2
        - TCP
            - 입출력 버퍼
                - write 함수가 호출되는 순간 데이터는 출력 버퍼로 이동
                - read 함수가 호출되는 순간 입력버퍼에 저장된 데이터를 읽어들임
                - 입력 버퍼으 ㅣ크기를 초과하는 분량의 데이터 전송은 발생하지 않음

            - TCP 내부의 동작원리
                - 상대 소켓과의 연결(Three-way handshaking)
                - 상대 소켓과의 데이터 송수신
                - 상대 소켓과의 연결 종료

    - UDP 기반 서버/클라이언트
        - UDP에 대한 이해
            - TCP와 달리 흐름제어를 하지 않는 데이터 전송 방식
        - UDP 기반 서버/클라이언트의 구현
            - UDP에서는 서버와 클라이언트의 연결설정 과정이 필요없음
            - 서버건 클라이언트 건 하나의 소켓만 있으면 됨
            - 데이터를 전송할 때 마다 반드시 목적지의 주소정보를 별도로 추가해야함
            - sendto 함수
            ```C
            #include <sys/socket.h>
            ssize_t sendto(int sock, void *buff, size_t nbytes, int flags, struct sockaddr *to, socklen_t addr len);
            // 성공 시 전송된 바이트 수, 실패 시 -1 반환
            // sock : 데이터 전송에 사용될 UDP 소켓의 파일 디스크립터
            // buff : 전송할 데이터가 저장된 버퍼의 주소값
            ```


## 3일차(2024-06-13)
