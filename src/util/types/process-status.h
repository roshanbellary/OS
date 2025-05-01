// Process status enum
// This enum is used to represent the status of a process in the system.
// It is used in the PCB (Process Control Block) structure to indicate the
// current state of the process.
// The enum values are used to determine the scheduling and execution
// behavior of the process
#ifndef PROCESS_STATUS_H
#define PROCESS_STATUS_H
typedef enum {
  PROCESS_STATUS_RUNNING,
  PROCESS_STATUS_WAITING,
  PROCESS_STATUS_ZOMBIE,
  PROCESS_STATUS_STOPPED,
  PROCESS_STATUS_BLOCKED,
  PROCESS_STATUS_DEAD
} ProcessStatus;
#endif

#ifndef pid_t
#define pid_t int
#endif