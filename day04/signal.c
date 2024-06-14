#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void timeout(int sig)  // 5, 11행: 시그널이 발생했을 때 호출되어야 할 함수가 각각 정의되어 있다. 이러한 유형의 함수를 시그널 핸들러
{                      // 라고 한
  if(sig==SIGALRM)  
    puts("Time out!");
  alarm(2);  // 2초 간격으로 SIGALRM 시그널을 반복 발생시키기 위해 시그널 핸들러 내에서 alarm 함수를 호출
}
void keycontrol(int sig)
{
  if(sig==SIGINT)
    puts("CTRL+C pressed");
}

int main(int argc, char *argv[])
{
  int i;
  signal(SIGALRM, timeout);  // 20, 21행: 시그널 핸들러를 등록
  signal(SIGINT, keycontrol);
  alarm(2);  // SIGALRM의 발생을 2초 뒤로 예약
  for(i=0; i<3; i++)
  {
    puts("wait...");
    sleep(100);
  }  // 27행: 시그널의 발생과 시그널 핸들러의
  return 0;
}
// 27행: 시그널의 발생과 시그널 핸들러의 실행을 확인하기 위해서 100초간의 총 3회의 대기시간을 갖도록 반복문 내에서 sleep 함수를 호출
