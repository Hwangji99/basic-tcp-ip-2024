#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void timeout(int sig)  
{                     
  if(sig==SIGALRM)  
    puts("Time out!");
  alarm(2);  // 2초 간격으로 SIGALRM 시그널을 반복 발생시키기 위해 시그널 핸들러 내에서 alarm 함수를 호출
}

int main(int argc, char *argv[])
{
  int i;
  struct sigaction act;  // 15,16행 : 시그널 발생 시 호출될 함수의 등록을 위해 구조체 변수 선언을 해서 sa_handler에 포인터 값을 저장
  act.sa_handler=timeout;
  sigemptyset(&act.sa_mask);  // sa_mask의 모든 비트를 0으로 초기화해야 하는 목적
  act.sa_flags=0;  // 역시 signal 함수를 대신하기 위해 필요한 멤버가 아니므로 0으로 초기화
  sigaction(SIGALRM, &act, 0);  // 19, 21행 : SIGALRM에 대한 핸들러 지정및 예약
  
  alarm(2);  // SIGALRM의 발생을 2초 뒤로 예약
  
  for(i=0; i<3; i++)
  {
    puts("wait...");
    sleep(100);
  }  
  return 0;
}
// 27행: 시그널의 발생과 시그널 핸들러의 실행을 확인하기 위해서 100초간의 총 3회의 대기시간을 갖도록 반복문 내에서 sleep 함수를 호출
