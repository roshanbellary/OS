#include <sys/types.h>
#include <unistd.h>
#include "../../util/types/process-status.h"
#include "../pcb.h"

/**
 * @brief Get the pid of the current process.
 * @return The PID of the current process.
 */
pid_t k_get_current_process_pid();

/**
 * @brief Get the current process running in the kernel.
 *
 * @return Reference to the current PCB.
 */
pcb_t *k_get_current_process();

/**
 * @brief Get the current process running in the kernel.
 *
 * @return Reference to the current PCB.
 */

pcb_t *k_get_process_by_pid(pid_t pid);
/**
 * @brief Create a new child process, inheriting applicable properties from the
 * parent.
 *
 * @return Reference to the child PCB.
 */
pcb_t *k_proc_create(pcb_t *parent);

/**
 * @brief Clean up a terminated/finished thread's resources.
 * This may include freeing the PCB, handling children, etc.
 */
void k_proc_cleanup(pcb_t *proc);

/**
 * @brief Releases a process's hold on a file descriptor.
 * This involves finding the corresponding global file table entry,
 * decrementing its reference count, and potentially closing the
 * underlying file/resource if the count reaches zero. It also
 * updates the process's local FD table to mark the descriptor as closed.
 *
 * @param proc The process control block (PCB) of the process closing the FD.
 * @param local_fd The file descriptor number *local* to the given process.
 * @return 0 on success, -1 on error (e.g., invalid local_fd, FD not open by
 * this process).
 * @return 0 on success, -1 on error (e.g., invalid local_fd, FD not open by
 * this process).
 */
int k_release_fd(pcb_t *proc, int local_fd);
int k_release_fd(pcb_t *proc, int local_fd);

/**
 * @brief Get a process by its PID.
 * @param pid The PID of the process to retrieve.
 * @return A pointer to the process control block (PCB) of the process, or NULL
 * if not found.
 * @return A pointer to the process control block (PCB) of the process, or NULL
 * if not found.
 */
pcb_t *k_get_proc(pid_t pid);

/**
 * @brief Read form standard input.
 *
 * @param store_result The buffer to store the read result.
 * @param len The length of the buffer.
 * @param fd The file descriptor to read from (not used in this implementation).
 * @return The number of bytes read.
 */
int k_read(char *store_result, int len, int fd);

/**
 * @brief Write a message to the standard output.
 *
 * @param msg The message to write.
 * @param fd The file descriptor to write to (not used in this implementation).
 */

int k_write(int fd, const char *buf, int n);