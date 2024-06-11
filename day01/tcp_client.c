#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
void error_handling(char *message);

int main(int argc, char* argv[])
{
   int sock;
   struct sockaddr_in serv_addr;
   char message[30];
   int str_len=0;
   int idx=0, read_len=0;

   if(argc!=3){
      printf("Usage : %s <IP> <port>\n", argv[0]);
      exit(1);
   }

   // TCP 소켓을 생성. 첫 번째 인자와 두 번째 인자로 각각 PF_INET, SOCK_STREAM가 전달되면 세 번째
   // 인자인 IPPROTO_TCP은 생략 가능
   sock=socket(PF_INET, SOCK_STREAM, 0);
   if(sock == -1)
      error_handling("socket() error");

   memset(&serv_addr, 0, sizeof(serv_addr));
   serv_addr.sin_family=AF_INET;
   serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
   serv_addr.sin_port=htons(atoi(argv[2]));

   if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))== -1)
      error_handling("connect() error!");

   // while문 안에서 read 함수를 반복 호출. 중요한 것은 이 함수가 호출될 때마다 1바이트씩 데이터를 읽어들인다
   // read 함수가 0을 반환하면 이는 거짓을 의미하기 때문에 while문을 빠져나간다
   while(read_len=read(sock, &message[idx++], 1))
   {
      if(read_len == -1)
         error_handling("read() error!");
   
      str_len+=read_len; // 이 문장이 실행될 때 read_len에 저장되어 있는 값은 항상 1이다. 38행에서 1바이트씩 데이터를
                         // 읽고 있기 때문이다. 결국 while문을 빠져나간 이후에 str_len에는 읽어 들인 바이트 수가 저장된다
   }

   printf("Message from server: %s \n", message);
   printf("Function read call count: %d \n", str_len);
   close(sock);
   return 0;
}

void error_handling(char *message)
{
   fputs(message, stderr);
   fputc('\n', stderr);
   exit(1);
}
