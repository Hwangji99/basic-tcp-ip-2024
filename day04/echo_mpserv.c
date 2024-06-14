#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 30
void error_handling(char *message);
void read_childproc(int sig);

int main(int argc, char *argv[])
{
  int serv_sock, clnt_sock;
  struct sockaddr_in serv_adr, clnt_adr;

  pid_t pid;
  struct sigaction act;
  socklen_t adr_sz;
  int str_len, state;
  char buf[BUF_SIZE];
  if(argc!=2) {
    printf("Usage : %s <port>\n", argv[0]);
    exit(1);
  }

  act.sa_handler=read_childproc;  // 29~32행 : 좀비 프로세스의 생성을 막기 위한 코드 구성
  sigemptyset(&act.sa_mask);
  act.sa_flags=0;
  state=sigaction(SIGCHLD, &act, 0);
  serv_sock=socket(PF_INET, SOCK_STREAM, 0);
  memset(&serv_adr, 0, sizeof(serv_adr);
  serv_adr.sin_family=AF_INET;
  serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
  serv_adr.sin_port=htons(atoi(argv[1]));

  if(bind(serv.sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr))==-1)
    error_handling("bind() error");
  if(listen(serv.sock, 5)==-1)
    error_handling("listen() error");

  while(1)
  {
    adr_sz=sizeof(clnt_adr);
    clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz);  // 47, 52행 : 47행에서 accept 함수를 호출한 후에
    if(clnt_sock==-1)                                                   // 52행에서 fork 함수를 호출하고 있다. 때문에 47행을
      continue;                                                         // 통해서 만들어진 소켓의 파일 디스크립터를 부모 프로세스와
    else                                                                // 자식 프로세스가 동시에 하나씩 갖게 된다
      puts("new client connected...");
    pid=fork();
    if(pid==-1)
    {
      close(clnt_sock);
      continue;
    }
    if(pid==0) /* 58~66행 : 자식 프로세스 실행 영역 */    // 에코 서비스가 제공
    {
      close(serv_sock);  // 33행에서 만든 서버 소켓을 닫음
      while(str_len=read(clnt_sock, buf, BUF_SIZE))!=0)
        write(clnt_sock, buf, str_len);

      close(clnt_sock);
      puts("client disconnected...");
      return 0;
    }
    else
      close(clnt_sock);  // 47행의 accept 함수호출을 통해서 만들어진 소켓의 파일 디스크립터가 자식 프로세스에게 복사되었으니
  }                      // 서버는 자신이 소유하고 있는 파일 디스크립터를 소멸시켜야 한다
  close(serv_sock);
  return0;
}

void read_childproc(int sig)
{
  pid_t pid;
  int status;
  pid=waitpid(-1, &status, WNOHANG);
  printf("removed proc id : %d \n", pid);
}
void error_handling(char *message)
{
  fputs(message, stderr;
  fputc('\n', stderr;
  exit(1);
}
