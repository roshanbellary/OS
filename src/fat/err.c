#include "err.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int ERRNO = 0;

char *error_case(void)
{
    switch (ERRNO)
    {
    case MKFS:
        return "Filesystem creation error: ";
    case MOUNT:
        return "Filesystem mount error: ";
    case UNMOUNT:
        return "Filesystem unmount error: ";
    case FILE_NOT_FOUND:
        return "File not found: ";
    case FILE_SYSTEM:
        return "Filesystem error: ";
    case MEMORY_ERROR:
        return "Memory allocation error: ";
    case INVALID_FD:
        return "Invalid file descriptor: ";
    case PERMISSION_DENIED:
        return "Permission denied: ";
    case INVALID_ARGS:
        return "Invalid arguments: ";
    case INVALID_PATH:
        return "Invalid path: ";
    case INVALID_OFFSET:
        return "Invalid offset: ";
    case INVALID_WHENCE:
        return "Invalid whence value: ";
    case INVALID_OPERATION:
        return "Invalid operation: ";
    case FS_NOT_MOUNTED:
        return "Filesystem not mounted: ";
    case FS_ALREADY_MOUNTED:
        return "Filesystem already mounted: ";
    case NOT_A_DIRECTORY:
        return "Not a directory: ";
    case NO_SPACE:
        return "No space left on device: ";
    default:
        return "Unknown error: ";
    }
}

void f_perror(char *message)
{
    char *error = "Error: ";
    char *error_desc = error_case();
    size_t len = strlen(error) + strlen(error_desc) + strlen(message) + 1;
    char *result = (char *)malloc(len + 1);

    if (result)
    {
        snprintf(result, len + 1, "%s%s%s\n", error, error_desc, message);
        write(STDERR_FILENO, result, len);
        free(result);
    }
    else
    {
        write(STDERR_FILENO, error, strlen(error));
        write(STDERR_FILENO, message, strlen(message));
        write(STDERR_FILENO, "\n", 1);
    }
}