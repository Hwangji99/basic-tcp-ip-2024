#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

void read_childproc(int sig)  
{                     
  int status; 
  pid_t id=waitpid(-1, &status, WNOHANG);
  if(WIFEXITED(status))
  {
    printf("Removed proc id: %d \n", id);
    printf("Child send: %d \n", WEXITSTATUS(status));
  }
}

int main(int argc, char *argv[])
{
  pid_t pid;
  struct sigaction act;              // 21~25행 : 시그널 SIGCHLD에 대한 시그널 핸들러의 등록과정을 보임
  act.sa_handler=read_childproc;     // 자식 프로세스가 종료되면 7행에 정의된 함수가 호출
  sigemptyset(&act.sa_mask);         // 그리고 이 함수 내에서의 waitpid 함수 호출로 인해 자식 프로세스는 좀비가 되지 않고 소멸
  act.sa_flags=0;  
  sigaction(SIGCHLD, &act, 0);  

  pid=fork();    // 27, 37행 : 부모 프로세스를 통해서 총 두 개의 자식 프로세스를 생성
  if(pid==0) /* 자식 프로세스 실행 영역 */
  {
    puts("Hi I'm child process");
    sleep(10);
    return 12;
  }
  else  /* 부모 프로세스 실행 영역 */
  {
    printf("Child proc id: %d \n", pid);
    pid=fork();
    if(pid==0) /* 또 다른 자식 프로세스 실행 영역 */
    {
      puts("Hi I'm child process");
      sleep(10);
      exit(24);
    }
    else
    {
      int i;
      printf("Child proc id: %d \n", pid);
      for(i=0; i<5; i++)      // 48, 51행: 시그널 SIGCHLD의 발생을 대기하기 위해 부모 프로세스를 5초간 5회 멈춰놓음
        {                     // 물론 시그널이 발생하면 부모 프로세스는 깨어나기 때문에 실제 멈춰있는 시간은 25초가 되지 않는다.
          puts("wait..."); 
          sleep(5);
        }
    }
  }
  return 0;
}
// 27행: 시그널의 발생과 시그널 핸들러의 실행을 확인하기 위해서 100초간의 총 3회의 대기시간을 갖도록 반복문 내에서 sleep 함수를 호출
