#include <stdio.h>
#include <unistd.h>

int gval=10;
int main(int argc, char *argv[])
{
  pid_t pid;
  int lval=20;
  gval++, lval+=5;

  pid=fork();  // 자식 프로세스 생성. 따라서 부모 프로세스의 pid에는 자식 프로세스의 ID가 저장, 자식 pid에는 0이 저
  if(pid==0) // if Child Process  // 12,18행 : 자식 프로세스는 이 두 문장을 실행. pid에 0이 저장되기 때문
    gval+=2, lval+=2;
  else        // if Parent Process
    gval-=2, lval-=2;  // 15, 20행: 부모 프로세스는 이 두 문장을 실행. pid에 자식 프로세스의 ID가 저장되기 때문

  if(pid==0)
    printf("Child Proc: [%d, %d] \n", gval, lval);
  else
    printf("Parent Proc: [%d, %d] \n", gval, lval);
  return 0;
}
