#ifndef PCB_H
#define PCB_H

#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include "../util/deque.h"
#include "../util/spthread.h"
#include "../util/types/process-status.h"

// The Process Control Block (PCB) structure for kernel processes
// This should match the current implementation as used in sys-call.c and
// kernel-call.c

/**
 * @brief The Process File Descriptor Node structure.
 *
 * This structure represents a file descriptor node in the process's file
 * descriptor table.
 */
typedef struct ProcessFDNode
{
  int fd_num; // process-level FD
  char fname[32];
  int mode;
  int offset;
  struct ProcessFDNode *next;
} ProcessFDNode;

/**
 * @brief The Process Control Block (PCB) structure.
 *
 * This structure represents a process control block (PCB) in the kernel.
 */
typedef struct pcb_t
{
  pid_t pid;                  // Process ID
  pid_t ppid;                 // Parent Process ID
  int priority_level;         // Priority level (0, 1, 2)
  int term_signal;            // Signal that terminated the process
  int stop_signal;            // Signal that stopped the process
  ProcessStatus status;       // Process status (enum)
  bool status_changed;        // Flag to indicate status change
  unsigned long wake_up_tick; // Tick count when sleep should end
  Deque *file_descriptors;    // Set of file descriptors
  ProcessFDNode *fd_table;    // Linked list of file descriptor nodes
  spthread_t *thread;         // Pointer to the thread of execution
  char *name;                 // Process name
  bool foreground;            // Foreground/background process
} pcb_t;

/**
 * @brief Initialize the file descriptor table for a process.
 *
 * @param pcb The process control block to initialize.
 */
void pcb_initialize_fd_table(pcb_t *pcb);

/**
 * @brief Add a file descriptor to the process's file descriptor table.
 *
 * @param pcb The process control block to add the file descriptor to.
 * @param kernel_fd The kernel file descriptor number.
 * @param fname The name of the file.
 * @param mode The mode of the file.
 * @param offset The offset of the file.
 * @return int The file descriptor number.
 */
int pcb_add_fd(pcb_t *pcb, int kernel_fd, const char *fname, int mode, int offset);

/**
 * @brief Get a file descriptor from the process's file descriptor table.
 *
 * @param pcb The process control block to get the file descriptor from.
 * @param fd_num The file descriptor number.
 * @return ProcessFDNode* The file descriptor node.
 */
ProcessFDNode *pcb_get_fd(pcb_t *pcb, int fd_num);

/**
 * @brief Remove a file descriptor from the process's file descriptor table.
 *
 * @param pcb The process control block to remove the file descriptor from.
 * @param fd_num The file descriptor number.
 * @return int The file descriptor number.
 */
int pcb_remove_fd(pcb_t *pcb, int fd_num);

/**
 * @brief Set a file descriptor in the process's file descriptor table.
 *
 * @param pcb The process control block to set the file descriptor in.
 * @param fd_num The file descriptor number.
 * @param fname The name of the file.
 * @param mode The mode of the file.
 * @param offset The offset of the file.
 * @return int The file descriptor number.
 */
int pcb_set_fd(pcb_t *pcb, int fd_num, const char *fname, int mode, int offset);

#endif // PCB_H
