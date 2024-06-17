#include <stdio.h>
#define BUF_SIZE 3  // 배열의 길이를 최소한으로 구성

int main(int argc, char *argv[])
{
  FILE * fp1;  // fp1에 저장되는 것은 FILE 구조체의 포인터
  FILE * fp2;  // fp2에 저장되는 것도 FILE 구조체의 포인터
  char buf[BUF_SIZE];

  fp1=open("news.txt", "r");
  fp2=open("cpy.txt", "w");

  while(fgets(fp1, BUF_SIZE, fp1)!=NULL)
    fputs(buf, fp2);

  close(fp1);
  close(fp2);
  return 0;
}
