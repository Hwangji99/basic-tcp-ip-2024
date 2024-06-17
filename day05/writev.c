#include <stdio.h>
#include <sys/uio.h>

int main(int argc, char *argv[])
{
  struct ivoec vec[2];
  char buf1[]="ABCDEFG";
  char buf2[]="1234567";
  int str_len;

  vec[0].iov_base=buf1;  // 11, 12행 : 첫 번째로 전송할 데이터가 지정된 위치와 크기정보를 담고 있다
  vec[0].iov_len=3;
  vec[1].iov_base=buf2;  // 13, 14행 : 두 번째로 전송할 데이터가 지정된 위치와 크기정보를 담고 있다
  vec[1].iov_len=4;

  str_len=writev(1, vec, 2);  // writev 함수의 첫 번째 전달인자가 1이므로 콘솔로 출력이 이루어짐
  puts("");
  printf("Write bytes: %d \n", str_len);
  return 0;
}
