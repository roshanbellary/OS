#include "../src/util/deque.h"
#include <stdio.h>
int main() {
  Deque* dq = deque_new(free);
  int v = 3;
  deque_push_front(dq, &v);
  int* rv = deque_get_front(dq);
  printf("Deque Value: %d \n", *rv);
}