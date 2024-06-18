#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#define NUM_THREAD 100 

void * thread_inc(void *arg);
void * thread_des(void *arg);

long long num=0;  // long long형은 64비트 정수 자료형
pthread_mutex_t mutex;  // 뮤텍스의 참조 값 저장을 위한 변수가 선언되었다. 전역변수로 선언된 이유는 뮤텍스의 접근이 밑에 2개의 함수 내에서 이뤄지기 때문

int main(int argc, char *argv[])
{
  pthread_t thread_id[NUM_THREAD];
  int i;

  pthread_mutex_init(&mutex, NULL);
  
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
  pthread_mutex_destroy(&mutex);  // 뮤텍스의 소멸을 보임. 이렇듯 뮤텍스는 필요가 없어지면 소멸해야 한다
  return 0;
}

void * thread_inc(void * arg)
{
  int i;
  pthread_mutex_lock(&mutex);  // 39, 42행: 실제 임계영역은 41행 하나이다.
  for(i=0; i<5000000; i++)
    num+=1;
  pthread_mutex_unlock(&mutex);
  return NULL;
}

void * thread_des(void * arg)
{
  int i;
  for(i=0; i<5000000; i++)
  {
    pthread_mutex_lock(&mutex);  // 51, 53행: 임계영역에 해당하는 52행만 뮤텍스의 lock, unlock 함수로 감싸고 있다
    num-=1;
    pthread_mutex_unlock(&mutex);
  }
  return NULL;
}
