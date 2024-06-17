#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  int cfd1, cfd2;
  char str1[]="Hi~ \n";
  char str2[]= "It's nice day~ \n";

  cfd1=dup(1);  // 10행은 dup을 통해 1을 복사, 11행에서는 dup2로 복사한 파일을 재복사, 그리고 정수값
  cfd2=dup(cfd1, 7);  // 7로 지정

  printf("fd1=%d, fd2=%d \n", cfd1, cfd2);
  write(cfd1, str1, sizeof(str1));  // 출력,  이 출력 결과를 통해 실제 복사가 이뤄진 것인지 확인가능
  write(cfd2, str2, sizeof(str2));

  close(cfd1);  // 복사된 파일 디스크립터를 모두 종료
  close(cfd2);
  write(1, str1, sizeof(str1));  // 아직 하나가 남아있는 상태라 출력이 여전히 진행
  close(1);  // 마지막 디스크립터 종료
  write(1, str2, sizeof(str2));  // 모두 종료해서 출력 X
  return 0;
}
