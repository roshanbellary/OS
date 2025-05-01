#include "p_errno.h"
#include <stdio.h>
#include <string.h> // Needed for strcat, strcpy if used

int P_ERRNO = 0;

// Helper to map P_ERRNO to error string
static const char *p_errno_str(int err)
{
    switch (err)
    {
    case P_ERRNO_SUCCESS:
        return "Success";
    case P_ERRNO_FILE_NOT_FOUND:
        return "No such file or directory";
    case P_ERRNO_PERMISSION:
        return "Permission denied";
    case P_ERRNO_WRITE_CONFLICT:
        return "Write conflict: File busy";
    case P_ERRNO_INTERNAL:
        return "Internal error";
    case P_ERRNO_INVALID_ARG:
        return "Invalid argument";
    case P_ERRNO_NO_SPACE:
        return "No space left on device";
    case P_ERRNO_NOT_MOUNTED:
        return "Filesystem not mounted";
    case P_ERRNO_ALREADY_MOUNTED:
        return "Filesystem already mounted";
    case P_ERRNO_INVALID_FD:
        return "Bad file descriptor";
    case P_ERRNO_NOT_A_DIRECTORY:
        return "Not a directory";
    case P_ERRNO_INVALID_OPERATION:
        return "Operation not permitted";
    case P_ERRNO_INVALID_WHENCE:
        return "Invalid whence";
    case P_ERRNO_INVALID_OFFSET:
        return "Invalid offset";
    case P_ERRNO_ESRCH:
        return "No such process";
    case P_ERRNO_EINVAL:
        return "Invalid argument"; // Reused for general invalid args
    case P_ERRNO_ECHILD:
        return "No child processes";
    case P_ERRNO_UNKNOWN:
        return "Unknown error";
    default:
        return "Unknown error code"; // Handle unexpected codes
    }
}

void u_perror(const char *msg)
{
    extern int P_ERRNO;
    // Use fprintf for stderr
    if (msg && strlen(msg) > 0)
    {
        fprintf(stderr, "%s: %s\n", msg, p_errno_str(P_ERRNO));
    }
    else
    {
        fprintf(stderr, "%s\n", p_errno_str(P_ERRNO));
    }
}