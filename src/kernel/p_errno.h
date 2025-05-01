#ifndef P_ERRNO_H
#define P_ERRNO_H

#define P_ERRNO_SUCCESS 0            // No error
#define P_ERRNO_FILE_NOT_FOUND 1     // File not found (maps from FAT: FILE_NOT_FOUND)
#define P_ERRNO_PERMISSION 2         // Permission denied (maps from FAT: PERMISSION_DENIED)
#define P_ERRNO_WRITE_CONFLICT 3     // File open for writing elsewhere
#define P_ERRNO_INTERNAL 4           // General internal kernel/OS error (maps from FAT: MEMORY_ERROR, FILE_SYSTEM)
#define P_ERRNO_INVALID_ARG 5        // Invalid argument provided to syscall (e.g., bad priority) (maps from FAT: INVALID_ARGS)
#define P_ERRNO_NO_SPACE 6           // No space left on device (maps from FAT: NO_SPACE)
#define P_ERRNO_NOT_MOUNTED 7        // Filesystem not mounted (maps from FAT: FS_NOT_MOUNTED)
#define P_ERRNO_ALREADY_MOUNTED 8    // Filesystem already mounted (maps from FAT: FS_ALREADY_MOUNTED)
#define P_ERRNO_INVALID_FD 9         // Invalid file descriptor (maps from FAT: INVALID_FD)
#define P_ERRNO_NOT_A_DIRECTORY 10   // Path is not a directory (maps from FAT: NOT_A_DIRECTORY)
#define P_ERRNO_INVALID_OPERATION 11 // Operation not permitted (e.g., closing stdin, bad mode) (maps from FAT: INVALID_OPERATION)
#define P_ERRNO_INVALID_WHENCE 12    // Invalid 'whence' argument for lseek (maps from FAT: INVALID_WHENCE)
#define P_ERRNO_INVALID_OFFSET 13    // Invalid 'offset' argument for lseek (maps from FAT: INVALID_OFFSET)
#define P_ERRNO_ESRCH 14             // No such process
#define P_ERRNO_EINVAL 15            // Invalid argument (general, e.g., bad signal)
#define P_ERRNO_ECHILD 16            // No child processes (for waitpid)
#define P_ERRNO_UNKNOWN 255          // Unknown error

extern int P_ERRNO; // Make sure this is declared extern @Nikita pls

/**
 * @brief Print an error message to the standard error stream.
 *
 * @param msg The message to print.
 */
void u_perror(const char *msg);

#endif // P_ERRNO_H