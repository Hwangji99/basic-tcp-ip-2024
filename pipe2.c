#include <stdio.h>
#include <unistd.h>
#define BUF_SIZE 30

int main(int argc, char *argv[])
{
  int fds[2];
  char str1[]="Who are you?";
  char str2[]="Thank you for your message";
  char buf[BUF_SIZE];
  pid_t pid;

  pipe(fds);  // pipe 함수호출을 통해 파이프 생성. 이로 인해 fds에는 압출력을 위한 파일 디스크립터가 각각 저장
  pid=fork();  // 이어서 fork 함수호출 12행으로 얻은 2 개의 디스크립터를 소유
  if(pid==0)
  {
    write(fds[1], str1, sizeof(str1));
    sleep(2);
    read(fds[0], buf, BUF_SIZE);
    printf("Child proc output: %s \n", buf);
  }                                   
  else
  {
    read(fds[0], buf, BUF_SIZE);
    printf("Parent proc output: %s \n", buf);
    write(fds[1], str2, sizeof(str2));
    sleep(3);
  }
  return 0;
}
