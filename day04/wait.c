#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
  int status;
  pid_t pid=fork();  // 9행에서 생성된 자식 프로세스는 13행에서 보이듯이 main 함수 내에서의 return문 실행을 통해 종료

  if(pid==0)
  {
    return 3;
  }
  else
  {
    printf("Child PID: %d \n", pid);
    pid=fork();  // 18행에서 생성된 자식 프로세스는 21행에서 보이듯이 exit 함수호출을 통해 종료
    if(pid==0)
    {
      exit(7);
    }
    else
    {
      printf("Child PID: %d \n", pid);
      wait(&status);  // wait 함수를 호출  // 이로 인해 종료된 프로세스 관련 정보는 status에 담기게 되고, 해당 정보의 프로세스는 완전 소멸
      if(WIFEXITED(status))    // WIFEXITED를 통해서 자식 프로세스의 정상종료 여부를 확인
        printf("Child send one: %d \n", WEXITSTATUS(status));  // 정상종료인 경우 WEXITSTATUS 함수를 호출해 자식 프로세스가 
                                                               // 전달한 값을 출력
      wait(&status);
      if(WIFEXITED(status))
        printf("Child send two: %d \n", WEXITSTATUS(status));
      sleep(30); // Sleep 30 sec  // 부모 프로세스의 종료를 멈추기 위해서 삽입한 코드. 이 순간에 자식 프로세스의 상태를 확인
    }
  }
  return 0;
}
