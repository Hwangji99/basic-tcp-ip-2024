#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define BUF_SIZE 1024

int main(int argc, char *argv[])
{
  int sock;
  char buf[BUF_SIZE];
  struct sockaddr_in serv_adr;
  
  FILE * readfp;
  FILE * writefp;

  sock=socket(PF_INET, SOCK_STREAM, 0);
  memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;
	serv_adr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_adr.sin_port = htons(atoi(argv[2]));

  connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr));
  readfp=fdopen(sock, "r");  
  writefp=fdopen(sock, "w");

  while(1)
  {
    if(fgets(buf, sizeof(buf), readfp)==NULL)  // EOF가 전달되면 fgets 함수는 NULL포인터를 반환
      break;                                   // 따라서 NULL이 반환되는 경우에 반복문을 빠져나감
    fputs(buf, stdout);
    fflush(stdout);
  }

  fputs("FROM CLIENT: Thank you! \n", writefp);  // 이 문장에 의해서 서버로 마지막 문자열이 전송
  fflush(writefp);                               // 위 문자열은 서버로부터 전달된 EOF 수신 후에
  fclose(writefp);                              // 전송하는 문자열
  fclose(readfp);
  return 0;
}
