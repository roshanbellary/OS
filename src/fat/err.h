#ifndef ERR_H
#define ERR_H

#define FS_SUCCESS 0
#define MKFS 1
#define MOUNT 2
#define UNMOUNT 3
#define FILE_NOT_FOUND 4
#define FILE_SYSTEM 5
#define MEMORY_ERROR 6
#define INVALID_FD 7
#define PERMISSION_DENIED 8
#define INVALID_ARGS 9
#define INVALID_PATH 10
#define INVALID_OFFSET 11
#define INVALID_WHENCE 12
#define INVALID_OPERATION 13
#define FS_NOT_MOUNTED 14
#define FS_ALREADY_MOUNTED 15
#define NOT_A_DIRECTORY 16
#define NO_SPACE 17

extern int ERRNO;

/**
 * @brief Returns a string description of the current error.
 *
 * @return A string description of the current error.
 */
char *error_case(void);

/**
 * @brief Prints an error message to the standard error stream.
 *
 * @param message The message to print.
 */
void f_perror(char *message);

#endif