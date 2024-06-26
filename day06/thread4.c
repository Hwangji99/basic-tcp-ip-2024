#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#define NUM_THREAD 100 

void * thread_inc(void *arg);
void * thread_des(void *arg);
long long num=0;  // long long형은 64비트 정수 자료형

int main(int argc, char *argv[])
{
  pthread_t thread_id[NUM_THREAD);
  int i;

  printf("sizeof long long: %d \n", sizeof(long; long));  // long long의 크기 확인
  for(i=0; i<NUM_THREAD; i++)
  {
    if(i%2)
      pthread_create(&(thread_id[i]), NULL, thread_inc, NULL);
    else
      pthread_create(&(thread_id[i]), NULL, thread_des, NULL);
  }

  for(i=0; i<NUM_THREAD; i++)
    pthread_join(thread_id[i], NULL);

  printf("result: %lld \n", num);
  return 0;
}

void * thread_inc(void * arg)
{
  int i;
  for(i=0; i<5000000; i++)
    num+=1;
  return NULL;
}

void * thread_des(void * arg)
{
  int i;
  for(i=0; i<5000000; i++)
    num-=1;
  return NULL;
}
