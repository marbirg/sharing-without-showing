#include <stdio.h>
#include "svm.h"

#include "models.c"
#include "data.c"

#include "svm-predict-lib.c"

svm_model *svm_load_model_from_string(const char *model_string);
  
int main(){
  svm_model *model = svm_load_model_from_string(breast_cancer_model);

  init(model);

  int nLines = 67;
  
  int *prediction = (int*)malloc(nLines * sizeof(int));;

  predict(test_data, prediction);

  return 0;
}

