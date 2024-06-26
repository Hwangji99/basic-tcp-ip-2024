#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>


#define TRUE 1
#define BUF_SIZE 2048
#define MAX_IMG_SIZE 700000

void send_webpage(int clnt_sock);
void send_image(int clnt_sock);

int main(int argc, char *argv[]) {
    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t sin_len = sizeof(clnt_addr);
    int serv_sock, clnt_sock;
    char buf[BUF_SIZE];
    int option = TRUE;

    // 프로그램 실행 시 포트 번호를 인자로 전달받지 않으면 사용법 출력 후 종료
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    // TCP 소켓 생성
    serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        perror("socket() error");
        exit(1);
    }

    // 소켓 옵션 설정 (주소와 포트 재사용)
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));

    // 서버 주소 설정 및 소켓에 바인딩
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(atoi(argv[1]));
    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind() error");
        exit(1);
    }

    // 연결 요청 대기열 설정
    if (listen(serv_sock, 5) == -1) {
        perror("listen() error");
        exit(1);
    }

    while (1) {
        // 클라이언트로부터 연결 요청 수락
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &sin_len);
        if (clnt_sock == -1) {
            perror("accept() error");
            continue;
        }
        printf("New client connection from %s:%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));

        // 클라이언트로부터의 요청 읽기
        read(clnt_sock, buf, BUF_SIZE);
        printf("Request:\n%s\n", buf);

        // 요청이 이미지 파일인지 확인 후 처리
        if (strstr(buf, "GET /dog.jpg") != NULL) {
            send_image(clnt_sock);  // 이미지 파일 전송 함수 호출
        } else {
            send_webpage(clnt_sock);  // 웹 페이지 전송 함수 호출
        }

        close(clnt_sock);  // 클라이언트 소켓 닫기
        printf("Connection closed for %s:%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
    }

    close(serv_sock);  // 서버 소켓 닫기
    return 0;
}

// 웹 페이지를 클라이언트에게 전송하는 함수
void send_webpage(int clnt_sock) {
    // HTML 형식의 웹 페이지 응답을 문자열로 생성
    char webpage[] = "HTTP/1.1 200 OK\r\n"
                     "Server: Linux Web Server\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                     "<!DOCTYPE html>\r\n"
                     "<html><head><title>끝내버림</title>\r\n"
                     "<link rel=\"icon\" href=\"data:,\">\r\n"
                     "<style>body {background-color: #FFFF00 }</style></head>\r\n"
                     "<body><center><h1>귀엽다 그죠잉~??</h1><br>\r\n"
                     "<img src=\"dog.jpg\"></center></body></html>\r\n";

    // 클라이언트 소켓에 HTML 페이지 전송
    if (write(clnt_sock, webpage, strlen(webpage)) == -1) {
        perror("write() error");
    }
}

// 이미지 파일을 클라이언트에게 전송하는 함수
void send_image(int clnt_sock) 
{
    char img_buf[MAX_IMG_SIZE];
    ssize_t img_size;
    int fdimg;

    // 이미지 파일 열기
    fdimg = open("dog.jpg", O_RDONLY);
    if (fdimg == -1) {
        perror("open() error");
        return;
    }

    // 이미지 파일 읽기
    img_size = read(fdimg, img_buf, sizeof(img_buf));
    if (img_size == -1) {
        perror("read() error");
        close(fdimg);
        return;
    }

    // HTTP 응답 헤더 생성
    char header[BUF_SIZE];
    snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\n"
                                      "Server: Linux Web Server\r\n"
                                      "Content-Type: image/jpeg\r\n"
                                      "Content-Length: %zd\r\n\r\n", img_size);

    // 헤더 전송
    if (write(clnt_sock, header, strlen(header)) == -1) {
        perror("write() error");
        close(fdimg);
        return;
    }

    // 이미지 데이터 전송
    if (write(clnt_sock, img_buf, img_size) == -1) {
        perror("write() error");
        close(fdimg);
        return;
    }

    close(fdimg);  // 파일 디스크립터 닫기
}
