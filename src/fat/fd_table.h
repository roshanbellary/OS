#ifndef FD_TABLE_H
#define FD_TABLE_H

#include <stdbool.h>

struct dir_entry;

#define F_READ 0
#define F_WRITE 1
#define F_APPEND 2


/**
 * node struct to represent each file in the fd table
 * @param name file name
 * @param fd fd number
 * @param offset pointer offset
 * @param size file size
 * @param mode mode of file (0: read, 1: write, 2: append)
 * @param next pointer to next node in list
 * 
*/
typedef struct fd_node {
    char* name;
    int fd;
    int offset;
    int size;
    int mode;
    struct fd_node* next;
} FD_Node;

/**
 * fd table struct
 * @param head head of the fd_table which is a linkedlist of fd_nodes
*/
typedef struct fd_table {
    FD_Node* head;
} FD_Table;

/**
 * initialize a fd table for a process
 * @param fd_table pointer to fd_table
*/
void initialize_fd_table(FD_Table* fd_table);

/**
 * finds correct position in the linked list to insert a new fd_node
 * done in order to maintain sequential FD numbers with no gaps
 * @param fd_table Pointer to the file descriptor table
 * @return pointer to the node after which to insert, or NULL to insert at head
 */
FD_Node* lookup_add_position(FD_Table* fd_table);

/**
 * add new fd_node to fd_table
 * @param fd_table pointer to fd_table linked list
 * @param name name of file being added
 * @param mode mode of file being added
 * @return fd_node that was added (or NULL on error)
*/
FD_Node* add_fd(FD_Table* fd_table, char* name, int mode);

/**
 * remove fd_node with given fd number from fd_table linked list
 * @param fd_table fd_table
 * @param fd fd number being removed
 * @return fd_node that was removed (or NULL on error)
*/
FD_Node* remove_fd(FD_Table* fd_table, int fd);

/**
 * find the fd_node with the fd number supplied as argument
 * @param fd_table fd_table
 * @param fd fd number that is being searched for
 * @returns fd_node being searched for (or NULL if it's not present)
*/
FD_Node* lookup_fd(FD_Table* fd_table, int fd);

#endif