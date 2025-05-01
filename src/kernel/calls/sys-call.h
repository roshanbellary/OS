#ifndef SYS_CALL_H
#define SYS_CALL_H

#include <math.h>
#include <sys/types.h>
#include <unistd.h>
#include "../p_errno.h"

// File system call
/**
 * @brief Error number for the last system call.
 */
extern int P_ERRNO;

/**
 * opens a file with specified mode
 * @param fname name of file to open
 * @param mode access mode (F_READ, F_WRITE, or F_APPEND)
 * @return file descriptor on success, negative value on error
 */
int s_open(const char *fname, int mode);

/**
 * closes a file descriptor
 * @param fd file descriptor to close
 * @return 0 on success, negative value on failure
 */
int s_close(int fd);

/**
 * reads data from a file descriptor
 * @param fd file descriptor to read from
 * @param buf buffer to store read data
 * @param n maximum number of bytes to read
 * @return number of bytes read, 0 on EOF, negative value on error
 */
int s_read(int fd, char *buf, int n);

/**
 * writes data to a file descriptor
 * @param fd file descriptor to write to
 * @param str buffer containing data to write
 * @param n number of bytes to write
 * @return number of bytes written, negative value on error
 */
int s_write(int fd, const char *str, int n);

/**
 * repositions file offset of open file descriptor
 * @param fd file descriptor
 * @param offset offset value
 * @param whence reference position (SEEK_SET, SEEK_CUR, SEEK_END)
 * @return new offset on success, negative value on error
 */
int s_lseek(int fd, int offset, int whence);

/**
 * removes a file from filesystem if not in use
 * @param fname name of file to remove
 * @return 0 on success, -1 on error
 */
int s_unlink(const char *fname);

/**
 * lists file(s) in filesystem
 * @param filename specific file to list, or NULL for all files
 */
void s_ls(const char *filename);

/**
 * creates a child process executing specified function
 * @param func function to execute
 * @param argv null-terminated array of args (command name as argv[0])
 * @param fd0 input file descriptor
 * @param fd1 output file descriptor
 * @param foreground true for foreground execution, false for background
 * @return process ID of child, -1 on error
 */
pid_t s_spawn(void *(*func)(void *),
              char *argv[],
              int fd0,
              int fd1,
              int foreground);

/**
 * waits for a child process to change state
 * @param pid process ID of child to wait for (-1 for any child)
 * @param wstatus pointer to store exit status information
 * @param nohang if true, return immediately if no child has exited
 * @return process ID of state-changed child, 0 if nohang and no change, -1 on
 * error
 */
pid_t s_waitpid(pid_t pid, int *wstatus, int nohang);

/**
 * sends a signal to a process
 * @param pid process ID of target process
 * @param signal signal number (P_SIGTERM, P_SIGSTOP, P_SIGCONT)
 * @return 0 on success, -1 on error
 */
int s_kill(pid_t pid, int signal);

/**
 * terminates calling process
 */
void s_exit(void);

/**
 * sets scheduling priority of a process
 * @param pid process ID of target
 * @param priority new priority value (0, 1, or 2)
 * @return 0 on success, -1 on failure
 */
int s_nice(pid_t pid, int priority);

/**
 * suspends calling process for specified clock ticks
 * @param ticks duration of sleep in clock ticks (must be > 0)
 */
void s_sleep(unsigned int ticks);

/**
 * displays information about all processes
 */
void s_ps(void);

/**
 * registers calling process as finished
 */
void s_register_end(void);

/**
 *
 * Sets the priority of a process
 * @param prio new priority value (0, 1, or 2)
 * @param pid process ID of target process
 */
void s_nice_pid(int prio, int pid);

/**
 * gets the process ID of the calling process
 * @return process ID of calling process
 */
pid_t s_getpid(void);

/**
 * changes permissions of a file
 * @param fname name of the file
 * @param mode_str mode string (e.g., "+r", "-wx")
 * @return 0 on success, -1 on failure
 */
int s_chmod(const char *fname, const char *mode_str); // Pass mode string

/**
 * gets the permission bits for a file.
 * @param fname name of the file.
 * @return permission value (int) on success, -1 on failure (sets P_ERRNO).
 */
int s_get_permission(const char *fname);

/**
 * sets the terminal owner
 * @param pid process ID of target
 */
int s_set_terminal_owner(pid_t pid);

#ifndef P_WAIT_STATUS_MACROS_H // Include guard for these macros
#define P_WAIT_STATUS_MACROS_H

#define P_WAIT_FLAG_STOPPED 0x100  // Bit 8 indicates stopped by a signal
#define P_WAIT_FLAG_SIGNALED 0x200 // Bit 9 indicates terminated by a signal
#define P_WAIT_SIG_MASK 0xFF       // Lower 8 bits for signal number

/**
 * @brief Returns true if the child terminated normally (via s_exit or return).
 */
#define P_WIFEXITED(status) (((status) & (P_WAIT_FLAG_STOPPED | P_WAIT_FLAG_SIGNALED)) == 0)

/**
 * @brief Returns true if the child process was terminated by a signal.
 */
#define P_WIFSIGNALED(status) (((status) & P_WAIT_FLAG_SIGNALED) != 0)

/**
 * @brief Returns the number of the signal that caused the child to terminate.
 * (Only valid if P_WIFSIGNALED(status) is true).
 */
#define P_WTERMSIG(status) ((status) & P_WAIT_SIG_MASK)

/**
 * @brief Returns true if the child process was stopped by delivery of a signal.
 */
#define P_WIFSTOPPED(status) (((status) & P_WAIT_FLAG_STOPPED) != 0)

/**
 * @brief Returns the number of the signal which caused the child to stop.
 * (Only valid if P_WIFSTOPPED(status) is true).
 */
#define P_WSTOPSIG(status) ((status) & P_WAIT_SIG_MASK)

#endif // P_WAIT_STATUS_MACROS_H

#endif /* SYS_CALL_H */