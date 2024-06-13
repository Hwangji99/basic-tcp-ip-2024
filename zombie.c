#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  pid_t pid=fork();

  if(pid==0) // if Child Process
  {
    puts("Hi, I am a child process");
  }
  else
  {
    printf("Child Process ID: %d \n", pid);  // 자식 프로세스의 ID 출력. 이 값을 통해 자식 프로세스의 상태(좀비인지 아닌지)를 확인 가능
    sleep(30);  // Sleep 30 sec.  // 부모 프로세스가 종료되면 좀비 상태에 자식 프로세스도 함께 소멸되기 때문에 확인을 위해서는 부모 프로
  }                               // 프로세스의 종료를 지연시킬 필요가 있다

  if(pid==0)
    puts("End child process")
  else
    puts("End parent process");
  return 0;
}
