#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE 30
void error_handling(char *message);

int main(int argc, char *argv[])
{
  int recv_sock, acpt_sock;
  struct sockaddr_in acpt_adr, recv_adr;
  int str_len, state;
  socklen_t recv_adr_sz;
  char buf[BUF_SIZE];
  if(argc!=2) {
    printf("Usage : %s  <port>\n", argv[0]);
    exit(1);
  }

  acpt_sock=socket(PF_INET, SOCK_STREAM, 0);
  memset(&acpt_sock, 0, sizeof(acpt_sock));
  acpt_adr.sin_family=AF_INET;
  acpt_adr.sin_addr.s_addr=htonl(INADDR_ANY);
  acpt_adr.sin_port=htons(atoi(argv[1]));

  if(bind(acpt_sock, (struct sockaddr*)&acpt_adr, sizeof(acpt_adr))==-1)
    error_handling("bind() error!");
  listen(acpt_sock, 5);

  recv_adr_sz=sizeof(recv_adr);
  recv_sock=accept(acpt_sock, (struct sockaddr*)&recv_adr, &recv_adr_sz);

  while(1)
  {
    str_len=(recv_sock, buf, sizeof(buf)-1, MSG_PEEK|MSG_DONTWAIT);  // ercv 함수를 호출하면서 MSG_PEEK을 옵션으로 전달. 옵션을 함께 전달하는 이유는
    if(str_len>0)                                                   // 데이터가 존재하지 않아도 블로킹 상태에 두지 않기 위해서
      break;
  }

  buf[str_len]=0;
  printf("Buffering %d bytes: %s \n", str_len, buf);

  str_len=recv(recv_sock, buf, sizeof(buf)-1, 0);    // recv 함수를 한번 더 호출. 아무런 옵션 설정 X. 때문에 이번에 읽어 들인 데이터는 입력버퍼에서
  buf[str_len];                                      // 지워짐
  printf("Read again: %s \n", buf);
  close(acpt_sock);
  close(recv_sock);
  return 0;
}

void error_handling(char *message)
{
  fputs(message, stderr);
  fputc('\n', stderr);
  exit(1);
}
