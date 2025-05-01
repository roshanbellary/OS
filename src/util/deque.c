#include "deque.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

Deque *deque_new(void (*func)(void *))
{
  Deque *v = (Deque *)malloc(sizeof(Deque));
  if (!v)
    return NULL;
  v->size = 0;
  v->front = NULL;
  v->tail = NULL;
  v->delete_mem = func;
  return v;
}

int deque_size(Deque *q)
{
  if (q != NULL)
  {
    return q->size;
  }
  else
  {
    return 0;
  }
}

void deque_push_front(Deque *q, void *value)
{
  if (!q)
    return;

  Node *new_head = malloc(sizeof(Node));
  if (!new_head)
    return;

  new_head->data = value;
  new_head->prev = NULL;
  new_head->next = q->front;

  if (q->front)
  {
    q->front->prev = new_head;
  }
  else
  {
    q->tail = new_head;
  }

  q->front = new_head;
  q->size++;
}

void deque_push_back(Deque *q, void *value)
{
  if (!q)
    return;

  Node *new_tail = malloc(sizeof(Node));
  if (!new_tail)
    return;

  new_tail->data = value;
  new_tail->next = NULL;
  new_tail->prev = q->tail;

  if (q->tail)
  {
    q->tail->next = new_tail;
  }
  else
  {
    q->front = new_tail;
  }

  q->tail = new_tail;
  q->size++;
}

void *deque_get_nth_elem(Deque *q, int n)
{
  if (!q || n < 0 || n >= q->size)
    return NULL;

  Node *curr = q->front;
  while (n--)
  {
    curr = curr->next;
  }
  return curr ? curr->data : NULL;
}

void *deque_remove_nth_elem(Deque *q, int n)
{
  if (!q || n < 0 || n >= q->size)
    return NULL;

  Node *target;
  if (n == 0)
  {
    return deque_pop_front(q);
  }
  else if (n == q->size - 1)
  {
    return deque_pop_back(q);
  }
  else
  {
    target = q->front;
    while (n--)
    {
      target = target->next;
    }

    target->prev->next = target->next;
    target->next->prev = target->prev;

    // if (q->delete_mem)
    //   q->delete_mem(target->data);
    free(target);
    q->size--;
    return target->data;
  }
}

void *deque_get_front(Deque *q)
{
  return (q && q->front) ? q->front->data : NULL;
}

void *deque_pop_front(Deque *q)
{
  if (!q || q->size == 0)
    return NULL;

  Node *old_front = q->front;
  void *res = old_front->data;

  if (q->size == 1)
  {
    q->front = NULL;
    q->tail = NULL;
  }
  else
  {
    q->front = old_front->next;
    if (q->front)
      q->front->prev = NULL;
  }

  free(old_front);
  q->size--;
  return res;
}

void *deque_get_back(Deque *q)
{
  return (q && q->tail) ? q->tail->data : NULL;
}

void *deque_pop_back(Deque *q)
{
  if (!q || q->size == 0)
    return NULL;

  Node *old_tail = q->tail;
  void *res = old_tail->data;

  if (q->size == 1)
  {
    q->front = NULL;
    q->tail = NULL;
  }
  else
  {
    q->tail = old_tail->prev;
    if (q->tail)
      q->tail->next = NULL;
  }

  free(old_tail);
  q->size--;
  return res;
}

void clear_deque(Deque *q)
{
  if (!q)
    return;
  if (!q->delete_mem)
    return;
  while (q->size > 0)
  {
    void *data = deque_pop_front(q);
    if (q->delete_mem)
      q->delete_mem(data);
  }
}

void *deque_remove_specific(Deque *q, void *data)
{
  if (!q || !data)
    return NULL;
  Node *curr = q->front;
  int index = 0;
  while (curr)
  {
    if (curr->data == data)
    {
      return deque_remove_nth_elem(q, index); // Reuse existing remove by index
    }
    curr = curr->next;
    index++;
  }
  return NULL; // Not found
}

// Checks if data is present in the deque.
bool deque_contains(Deque *q, void *data)
{
  if (!q || !data)
    return false;
  Node *curr = q->front;
  while (curr)
  {
    if (curr->data == data)
    {
      return true;
    }
    curr = curr->next;
  }
  return false;
}