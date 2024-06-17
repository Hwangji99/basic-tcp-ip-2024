#include <stdio.h>
#include <fcntl.h>

int main(void)
{
  FILE *fp;
  int fd=open("data.dat", O_WRONLY|O_CREAT|O_TRUNC);  
  if(fd==-1)
  {
    fputs("file open error", stdout);
    return -1;
  }

  printf("First file descriptor: %d \n", fd);  // 7행에서 반환된 파일 디스크립터의 정수 값을 출력하고 있다
  fp=fdopen(fd, "w");    // 15행에서는 fdopen 함수호출을 통해 파일 디스크립터를 FILE 포인터로
  fputs("TCP/IP SOCKET PROGRAMMING \n", fp); 
  printf("Second file descriptor: %d \n", fileno(fd));   // 17행에서는 fileno 함수호출을 통해 이를 다시 파일 디스크립터로 변환,  그 정수 값을 출
  fclose(fp);
  return 0;
}
