#include "err.h"
#include "fd_table.h"
#include "pennfat.h"
#include "fat_core.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "fat_kernel.h"

static bool mounted = false;      // tracks if a filesystem is currently mounted

// helper function to process a command in the pennfat shell
static void process_command(char *args[], int argcount) {
    if (strcmp("mkfs", args[0]) == 0) {
        if (mounted) {
            ERRNO = FS_ALREADY_MOUNTED;
            f_perror("Cannot create new filesystem while another is mounted");
            return;
        }
        
        if (argcount != 4) {
            ERRNO = INVALID_ARGS;
            f_perror("Usage: mkfs <name> <blocks_in_fat> <block_size_config>");
            return;
        }
        
        char* name = args[1];
        int num_blocks_in_fat = atoi(args[2]);
        int block_size_unmapped = atoi(args[3]);
        
        if (num_blocks_in_fat < 1 || num_blocks_in_fat > 32) {
            ERRNO = INVALID_ARGS;
            f_perror("blocks_in_fat must be between 1 and 32");
            return;
        }
        
        if (block_size_unmapped < 0 || block_size_unmapped > 4) {
            ERRNO = INVALID_ARGS;
            f_perror("block_size_config must be between 0 and 4");
            return;
        }
        
        fs_create(name, num_blocks_in_fat, block_size_unmapped);
    } else if (strcmp("mount", args[0]) == 0) {
        if (mounted) {
            ERRNO = FS_ALREADY_MOUNTED;
            f_perror("A filesystem is already mounted");
            return;
        }
        
        if (argcount != 2) {
            ERRNO = INVALID_ARGS;
            f_perror("Usage: mount <filesystem_name>");
            return;
        }
        
        if (fs_mount(args[1]) == 0) {
            mounted = true;
        }
    } else if (strcmp("unmount", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is currently mounted");
            return;
        }
        
        if (argcount != 1) {
            ERRNO = INVALID_ARGS;
            f_perror("Usage: unmount");
            return;
        }
        
        if (fs_unmount() == 0) {
            mounted = false;
        }
    } else if (strcmp("touch", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        f_touch(args);
    } else if (strcmp("mv", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        f_mv(args);
    } else if (strcmp("rm", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        f_rm(args);
    } else if (strcmp("cat", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        f_cat(args, STDIN_FILENO, STDOUT_FILENO);
    } else if (strcmp("cp", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        f_cp(args);
    } else if (strcmp("ls", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        if (argcount == 1) {
            k_ls(NULL);
        } else {
            k_ls(args[1]);
        }
    } else if (strcmp("chmod", args[0]) == 0) {
        if (!mounted) {
            ERRNO = FS_NOT_MOUNTED;
            f_perror("No filesystem is mounted");
            return;
        }
        
        f_chmod(args);
    } else if (strcmp("exit", args[0]) == 0 || strcmp("quit", args[0]) == 0) {
        printf("Exiting...\n");
        if (mounted) {
            fs_unmount();
        }
        exit(0);
    } else if (strlen(args[0]) > 0) {
        char err_str[1024];
        sprintf(err_str, "Unknown command: %s", args[0]);
        f_perror(err_str);
    }
}

int main(int argc, char** argv) {
    init();
    
    while (true) {
        if (write(STDERR_FILENO, "pennfat> ", sizeof("pennfat> ") - 1) == -1) {
            ERRNO = FILE_SYSTEM;
            f_perror("Write error");
        }

        // read command input
        char input[MAX_LINE_LENGTH + 1];
        int read_bytes = read(STDIN_FILENO, input, MAX_LINE_LENGTH);
        
        if (read_bytes == 0) {
            printf("\nExiting...\n");
            break;
        }
        
        if (read_bytes == -1) {
            ERRNO = FILE_SYSTEM;
            f_perror("Read error");
            continue;
        }
        
        input[read_bytes] = '\0';
        
        // make a copy for tokenization
        char inp_copy[read_bytes + 1];
        strcpy(inp_copy, input);

        // count arguments
        int argcount = 0;
        char *s = " \n\t";
        char *token = strtok(inp_copy, s);
        
        if (token == NULL) {
            continue;
        } else {
            argcount = 1;
        }

        while (strtok(NULL, s)) {
            argcount++;
        }

        // parse arguments
        char *args[argcount + 1];
        args[0] = strtok(input, s);
        
        for (int i = 1; i < argcount; ++i) {
            args[i] = strtok(NULL, s);
        }
        
        args[argcount] = NULL;

        // process the command
        process_command(args, argcount);
    }
    
    // clean up before exit
    if (mounted) {
        fs_unmount();
    }
    
    return 0;
}