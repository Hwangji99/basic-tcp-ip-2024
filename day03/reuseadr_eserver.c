#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define TRUE 1
#define FALSE 0
void error_handling(char *message);

int main(int argc, char *argv[])
{
  int serv_sock, clnt_sock;
  char message[30];
  int option, str_len;
  socklen_t optlen, clnt_adr_sz;
  struct sockaddr_in serv_adr, clnt_adr;
  if(argc != 2) {
    printf("Usage: %s <port> \n", argv[0]);
    exit(1);
  }

  serv_sock=socket(PF_INET, SOCK_STREAM, 0);
  if(serv_sock == -1)
    error_handling("socket() error");

  fp=fopen("receive", "wb");
  sd=socket(PF_INET, SOCK_STREAM, 0);

  memset(&serv_adr, 0, sizeof(serv_adr));
  serv_adr.sin_family=AF_INET;
  serv_adr.sin_addr.s_addr=inet_addr(argv[1]);
  serv_adr.sin_port=htons(atoi(argv[2]));

  connect(sd, (struct sockaddr*)&serv_adr, sizeof(serv_adr));

  while((read_cnt=read(sd, buf, BUF_SIZE))!=0)
    fwrite((void*)buf, 1, read_cnt, fp);

  puts("Received file data");
  write(sd, "Thank you", 10);
  fclose(fp);
  close(sd);
  return 0;
}

void error_handling(char *message)
{
  fputs(message, stderr);
  fputc('\n', stderr);
  exit(1);
}