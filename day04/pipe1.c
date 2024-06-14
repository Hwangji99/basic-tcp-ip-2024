#include <stdio.h>
#include <unistd.h>
#define BUF_SIZE 30

int main(int argc, char *argv[])
{
  int fds[2];
  char str[]="Who are you?";
  char buf[BUF_SIZE];
  pid_t pid;

  pipe(fds);  // pipe 함수호출을 통해 파이프 생성. 이로 인해 fds에는 압출력을 위한 파일 디스크립터가 각각 저장
  pid=fork();  // 이어서 fork 함수호출 12행으로 얻은 2 개의 디스크립터를 소유
  if(pid==0)
  {
    write(fds[1], str, sizeof(str));  // 16, 20행 : 자식 프로세스는 16행의 실행을 통해서 파이프로 문자열을 전달
  }                                   // 그리고 부모 프로세스는 20행의 실행을 통해 파이프로부터 문자열 수신
  else
  {
    read(fds[0], buf, BUF_SIZE);
    puts(buf);
  }
  return 0;
}
