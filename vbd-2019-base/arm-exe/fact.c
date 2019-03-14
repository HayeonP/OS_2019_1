#include <stdio.h>

int result;

int fact(int n){
  if(n<1) return 1;
  else return n*fact(n-1);
}

int main(){
  int n=5;
  result = fact(n);
  //printf("result = %d\n", result);
  return 0;
}


