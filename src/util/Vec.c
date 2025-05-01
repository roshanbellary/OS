#include "./Vec.h"
#include <stdio.h>
#include <stdlib.h>

Vec vec_new(size_t initial_capacity, ptr_dtor_fn ele_dtor_fn) {
  void** allocated_space = malloc(initial_capacity * sizeof(void*));
  Vec newVector = {0};
  if (allocated_space == NULL) {
    return newVector;
  }
  newVector.data = allocated_space;
  newVector.capacity = initial_capacity;
  newVector.ele_dtor_fn = ele_dtor_fn;
  newVector.length = 0;
  return newVector;
}

ptr_t vec_get(Vec* self, size_t index) {
  if (self == NULL) {
    return NULL;
  }
  if (vec_len(self) <= index) {
    return NULL;
  }
  return *((self->data) + index);
}
void vec_set(Vec* self, size_t index, ptr_t new_ele) {
  if (self == NULL) {
    return;
  }
  if (vec_capacity(self) <= index) {
    return;
  }
  if (self->ele_dtor_fn != NULL && (self->data + index) != NULL) {
    self->ele_dtor_fn(*(self->data + index));
  }
  *((self->data) + index) = new_ele;
}

void vec_push_back(Vec* self, ptr_t new_ele) {
  if (self == NULL) {
    return;
  }
  if (vec_capacity(self) <= vec_len(self)) {
    size_t prev_capacity = vec_capacity(self);
    size_t new_capacity =
        (vec_capacity(self) == 0 ? 1 : 2 * vec_capacity(self));
    vec_resize(self, new_capacity);
    if (vec_capacity(self) < 2 * prev_capacity) {
      return;
    }
  }
  self->length++;
  *(self->data + self->length - 1) = new_ele;
}

bool vec_pop_back(Vec* self) {
  if (vec_is_empty(self)) {
    return false;
  }
  size_t len = vec_len(self);
  if (self->ele_dtor_fn != NULL) {
    self->ele_dtor_fn(*(self->data + len - 1));
  }
  self->length--;
  return true;
}

void vec_insert(Vec* self, size_t index, ptr_t new_ele) {
  if (self == NULL) {
    return;
  }
  if (index > vec_len(self)) {
    return;
  }
  if (vec_len(self) + 1 > vec_capacity(self)) {
    size_t new_capacity =
        (vec_capacity(self) == 0 ? 1 : 2 * vec_capacity(self));
    vec_resize(self, new_capacity);
  }
  if (self->data == NULL) {
    return;
  }
  for (size_t i = vec_len(self); i > index; i--) {
    self->data[i] = self->data[i - 1];
  }
  self->data[index] = new_ele;
  self->length++;
}

void vec_erase(Vec* self, size_t index) {
  if (self == NULL) {
    return;
  }
  if (index >= vec_len(self)) {
    return;
  }
  size_t currIndex = index;
  while (currIndex < vec_len(self) - 1) {
    ptr_t swapVal = *(self->data + currIndex + 1);
    *(self->data + currIndex + 1) = *(self->data + currIndex);
    *(self->data + currIndex) = swapVal;
    currIndex++;
  }
  vec_pop_back(self);
}
void vec_resize(Vec* self, size_t new_capacity) {
  if (self == NULL) {
    return;
  }
  if (new_capacity < 0) {
    return;
  }
  ptr_t* new_allocated = malloc(new_capacity * sizeof(ptr_t));
  if (new_allocated == NULL) {
    return;
  }
  for (int i = 0; i < (self->length); i++) {
    *(new_allocated + i) = *(self->data + i);
  }
  size_t len = vec_len(self);
  free(self->data);
  self->data = new_allocated;
  self->length = len;
  self->capacity = new_capacity;
}
void vec_clear(Vec* self) {
  size_t len = vec_len(self);
  for (int i = 0; i < len; i++) {
    vec_pop_back(self);
  }
}
void vec_destroy(Vec* self) {
  vec_clear(self);
  self->capacity = 0;
  ptr_t* data_ptr = self->data;
  self->data = NULL;
  free(data_ptr);
}