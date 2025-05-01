#include "../util/Vec.h"
#include "../util/spthread.h"
#include "../util/types/process-status.h"
#include "./pcb.h"
#ifndef PROCESS_QUANTA
#define PROCESS_QUANTA 19
#endif

#ifndef MAX_PROC
#define MAX_PROC 100
#endif

/**
 * @brief The kernel state.
 *
 * This structure contains all the state information for the kernel.
 */
typedef struct KernelState
{
  Deque *dq_RUNNING[3];
  Deque *dq_ZOMBIE;
  Deque *dq_DEAD; // Ensure this exists if used, otherwise remove
  Deque *dq_BLOCKED;
  Deque *dq_STOPPED; // Make sure this is uncommented/added
  int curr_thread_num;
  int process_quanta;
  pcb_t *curr_process;
  Vec current_processes;
  pid_t terminal_owner_pid; // Add terminal owner tracking
} KernelState;

/**
 * @brief Global variable to track if a shutdown has been requested.
 */
extern volatile bool g_shutdown_requested;

/**
 * @brief Get the kernel state.
 *
 * @return KernelState* The kernel state.
 */
KernelState *getKernelState();

/**
 * @brief Start the kernel.
 *
 * This function is called once at kernel startup and should perform any
 * necessary initialization tasks.
 */
void start_kernel();

/**
 * @brief Initialize the kernel.
 *
 * This function is called once at kernel startup and should perform any
 * necessary initialization tasks.
 */
void kernel_set_up();

/**
 * @brief Add a process to the appropriate run queue based on its priority. Also
 * set its place in the pid pool.
 *
 * This schedules the process to be picked up by the kernel scheduler
 * during its round-robin cycle. Must only be called on RUNNING processes.
 *
 * @param proc The process to enqueue. Must not be NULL.
 */
void add_process_to_scheduler(pcb_t *proc);

/**
 * @brief Add a process to the appropriate run queue based on its priority.
 *
 *
 * @param proc The process to enqueue. Must not be NULL.
 */

void add_process_to_run_queue(pcb_t *proc);

/**
 * @brief Remove a process from its current run queue.
 *
 * This is typically used when a process blocks, is killed, exits,
 * or is reprioritized. The function will look for the process by PID
 * within its current priority-level queue and remove it if found.
 *
 * @param proc The process to remove. Must not be NULL.
 */

/**
 * @brief Remove a process from its current run queue.
 *
 * This is typically used when a process blocks, is killed, exits,
 * or is reprioritized. The function will look for the process by PID
 * within its current priority-level queue and remove it if found.
 *
 * @param proc The process to remove. Must not be NULL.
 */
void remove_process_from_run_queue(pcb_t *proc);

/**
 * @brief Add a process to the zombie queue.
 *
 * Zombie processes have terminated but are waiting to be reaped
 * by their parent. This function registers such processes into
 * the dq_ZOMBIE queue.
 *
 * @param proc The process to mark as zombie. Must not be NULL.
 */

/**
 * @brief Add a process to the zombie queue.
 *
 * Zombie processes have terminated but are waiting to be reaped
 * by their parent. This function registers such processes into
 * the dq_ZOMBIE queue.
 *
 * @param proc The process to mark as zombie. Must not be NULL.
 */
void add_process_to_zombie_queue(pcb_t *proc);

/**
 * @brief Remove a process from the zombie queue.
 *
 * This is typically done when the parent reaps a zombie child
 * via s_waitpid. The function matches by PID and removes the process.
 *
 * @param proc The zombie process to remove. Must not be NULL.
 */

/**
 * @brief Remove a process from the zombie queue.
 *
 * This is typically done when the parent reaps a zombie child
 * via s_waitpid. The function matches by PID and removes the process.
 *
 * @param proc The zombie process to remove. Must not be NULL.
 */
void remove_process_from_zombie_queue(pcb_t *proc);

/**
 *
 * @brief Check if a process is blocked by sleep and wake it up if the time has
 * come.
 */
void check_blocked_processes();

/**
 * @brief Get the kernel ticks.
 *
 * @return unsigned long The number of ticks since the kernel started.
 */
unsigned long get_kernel_ticks();