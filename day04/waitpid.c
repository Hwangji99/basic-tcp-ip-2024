#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
  int status;
  pid_t pid=fork();

  if(pid==0)
  {
    sleep(15);  // 자식 프로세스의 종료를 늦추기 위해서 sleep 함수를 호출하고 있다. 이로 인해서 약 15초 간의 지연이 생긴다
    return 24;
  }
  else
  {
    while(!waitpid(-1, &status, WNOHANG))  // 세 번째 인자로 WNOHANG을 전달하였으니, 종료된 자식 프로세스가 없으면 0을 반환한다
    {
      sleep(3);
      puts("sleep 3sec.");
    }

    if(WIFEXITED(status))
      printf("Child send %d \n", WEXITSTATUS(status));
  }
  return 0;
}
