#include <stdlib.h>
// Node structure (reused for all types)
#ifndef NODE_H
#define NODE_H
/**
 * @brief Node structure for doubly-linked list used in Deque.
 *
 * This structure represents a node in the deque, holding a pointer to data and
 * pointers to the next and previous nodes in the list.
 */
typedef struct Node {
  void *data;            /**< Pointer to the data stored in the node. */
  struct Node *next;     /**< Pointer to the next node in the deque. */
  struct Node *prev;     /**< Pointer to the previous node in the deque. */
} Node;
#endif

#ifndef DEQUE_H
#define DEQUE_H
// Deque structure
/**
 * @brief Double-ended queue (deque) structure.
 *
 * The Deque supports insertion and removal of elements from both ends.
 * It uses a doubly-linked list of Node structures.
 * The delete_mem function pointer is used to free memory for stored data.
 */
typedef struct Deque {
  Node *front;                 /**< Pointer to the front node. */
  Node *tail;                  /**< Pointer to the tail node. */
  int size;                    /**< Number of elements in the deque. */
  void (*delete_mem)(void *);  /**< Function pointer to free element memory. */
} Deque;
#endif
/**
 * @brief Create a new deque.
 *
 * @param func Function pointer to free memory for stored data (can be NULL).
 * @return Pointer to the created Deque, or NULL on allocation failure.
 */
Deque *deque_new(void (*func)(void *));

/**
 * @brief Get the number of elements in the deque.
 *
 * @param q Pointer to the Deque.
 * @return Number of elements in the deque, or 0 if q is NULL.
 */
int deque_size(Deque *q);

/**
 * @brief Insert an element at the front of the deque.
 *
 * @param q Pointer to the Deque.
 * @param value Pointer to the data to insert.
 */
void deque_push_front(Deque *q, void *value);

/**
 * @brief Insert an element at the back of the deque.
 *
 * @param q Pointer to the Deque.
 * @param value Pointer to the data to insert.
 */
void deque_push_back(Deque *q, void *value);

/**
 * @brief Get the data at the front of the deque without removing it.
 *
 * @param q Pointer to the Deque.
 * @return Pointer to the data at the front, or NULL if deque is empty or q is NULL.
 */
void *deque_get_front(Deque *q);

/**
 * @brief Remove and return the data at the front of the deque.
 *
 * @param q Pointer to the Deque.
 * @return Pointer to the removed data, or NULL if deque is empty or q is NULL.
 */
void *deque_pop_front(Deque *q);

/**
 * @brief Get the data at the back of the deque without removing it.
 *
 * @param q Pointer to the Deque.
 * @return Pointer to the data at the back, or NULL if deque is empty or q is NULL.
 */
void *deque_get_back(Deque *q);

/**
 * @brief Remove and return the data at the back of the deque.
 *
 * @param q Pointer to the Deque.
 * @return Pointer to the removed data, or NULL if deque is empty or q is NULL.
 */
void *deque_pop_back(Deque *q);

/**
 * @brief Remove all elements from the deque and free their memory using delete_mem.
 *
 * @param q Pointer to the Deque.
 */
void clear_deque(Deque *q);

/**
 * @brief Get the data at the nth position in the deque (0-based index).
 *
 * @param q Pointer to the Deque.
 * @param n Index of the element to retrieve.
 * @return Pointer to the data at position n, or NULL if out of bounds or q is NULL.
 */
void *deque_get_nth_elem(Deque *q, int n);

/**
 * @brief Remove and return the data at the nth position in the deque (0-based index).
 *
 * @param q Pointer to the Deque.
 * @param n Index of the element to remove.
 * @return Pointer to the removed data, or NULL if out of bounds or q is NULL.
 */
void *deque_remove_nth_elem(Deque *q, int n);

/**
 * @brief Remove and return the first occurrence of a specific value from the deque.
 *
 * @param q Pointer to the Deque.
 * @param value Pointer to the data to remove.
 * @return Pointer to the removed data, or NULL if not found or q is NULL.
 */
void *deque_remove_specific(Deque *q, void *value);

/**
 * @brief Check if the deque contains a specific value.
 *
 * @param q Pointer to the Deque.
 * @param value Pointer to the data to search for.
 * @return true if value is found, false otherwise or if q is NULL.
 */
bool deque_contains(Deque *q, void *value);