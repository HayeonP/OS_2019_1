
int arr[10] = {1,5,4,3,0,7,2,9,6,8};

void bubbleSort(int list[], int n){
  int i;
  int j;
  int temp = 0;

  for(i = n-1; i>0; i--){
    for(j=0; j<i; j++){
      if(list[j] > list[j+1]){
	temp = list[j];
	list[j] = list[j+1];
	list[j+1] = temp;
      }
    }
  }
}

int main(void){
  int len = 10;
  bubbleSort(arr, len);
  return 0;
}
