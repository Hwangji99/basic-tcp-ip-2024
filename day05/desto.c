#include <stdio.h>
#include <fcntl.h>

int main(void)
{
  FILE *fp;
  int fd=open("data.dat", O_WRONLY|O_CREAT|O_TRUNC);  // open 함수를 사용해서 파일을 생성했으므로 파일 디스크립터가 반환된
  if(fd==-1)
  {
    fputs("file open error\n", stdout);
    return -1;
  }

  fp=fdopen(fd, "w");  // fdopen 함수호출을 통해서 파일 디스크립터를 FILE 포인터로 변환하고 있다. 이 때 두 번째 인자로 "w"가 전달되서 FILE 포인터 반환
  fputs("Network C programming \n", fp);  // 14행을 통해 얻은 포인터를 기반으로 fputs 함수 호출
  fclose(fp);
  return 0;
}
