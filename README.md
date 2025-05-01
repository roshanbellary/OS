# Thread-Based Operating System

## Built By:
- Roshan Bellary
- Jefferson Ding
- Nikita Mounier
- Praneel Varshney

## Source Files

- `src/fat/` - FAT filesystem implementation
  - `pennfat.c`, `pennfat.h` - Main FAT program
  - `fat_core.c`, `fat_core.h` - Core filesystem functions
  - `fat_kernel.c`, `fat_kernel.h` - Kernel-level filesystem functions
  - `fd_table.c`, `fd_table.h` - File descriptor table implementation
  - `err.c`, `err.h` - Error handling for filesystem

- `src/kernel/` - OS kernel implementation
  - `kernel.c`, `kernel.h` - Core kernel functionality
  - `pcb.c`, `pcb.h` - Process Control Block implementation
  - `p_errno.h`, `u_perror.c` - Error handling for the OS
  - `calls/` - System and user-level calls
    - `kernel-call.c`, `kernel-call.h` - Kernel-level calls
    - `sys-call.c`, `sys-call.h` - System calls
    - `user-call.c`, `user-call.h` - User-level commands

- `src/penn-shell/` - OS shell implementation
  - `penn-shell.c`, `penn-shell.h` - Shell implementation
  - `parser.c`, `parser.h` - Command line parser
  - `execute_command.c`, `execute_command.h` - Command execution
  - `stress.c`, `stress.h` - Shell commands for testing

- `src/util/` - Utility functions and data structures
  - `Vec.c`, `Vec.h` - Vector implementation
  - `deque.c`, `deque.h` - Deque implementation
  - `spthread.c`, `spthread.h` - Special thread library
  - `logger/` - Logging functionality
  - `types/` - Type definitions

- `src/pennos.c` - Main OS entry point

## Compilation Instructions

### For the standalone FAT:
1. Change to the fat directory: `cd src/fat`
2. Build the FAT executable: `make`
3. Run the standalone FAT system: `./bin/pennfat`
4. Create a filesystem: `mkfs <filesystem_name> <blocks_in_fat> <block_size_config>`
   - Example: `mkfs fs.img 10 4` (creates a filesystem with 10 blocks in FAT and 4096-byte blocks)

### For the full OS:
1. Create a filesystem using the standalone PennFAT (see instructions above)
2. Move the created filesystem file to the root directory
3. From the root directory, compile the OS: `make`
4. Run the OS with: `./bin/pennos fatfs <filesystem_file> [log_fname]`
   - Example: `./bin/pennos fatfs test_fs pennos.log`

## Overview of Work Accomplished

We've implemented a complete UNIX-like operating system. It runs as a user-level program on a host OS. Some noteworthy components are:

1. **FAT Filesystem**: A FAT-based filesystem implementation that supports file creation, deletion, reading, writing, permission management. Note that this filesystem is stored as a single file on the host OS.

2. **Kernel and Scheduler**: A round-robin scheduler with priority support. Manages processes as 'spthreads' and handles create, block, terminate, and scheduling.

3. **Process Management**: Full process lifecycle support, including zombies, orphans, and cleanup. Also supports parent-child relationships.

4. **Shell**: A command-line shell that supports built-in commands, I/O redirection, job control, and shell scripts.

5. **Error Handling**: Error handling was done similar to UNIX's errno and perror.

## Description of Code and Code Layout

See the Source Files section for information on what each file contains. 

As for the overall layout, we structured the OS into four key layers:

- **Core Infrastructure**: Basic utilities like `Vec`, `deque`, and the custom `spthread` library for lightweight threading.
- **Kernel Layer**: Handles core OS responsibilities—process management, scheduling, and kernel-level calls.
- **System Call Interface**: Bridges user programs and the kernel, isolating privilege boundaries and internal logic.
- **User-Level Applications**: Includes the shell, command parsing, and user-facing built-ins.


Some implementation decisions that we made were:

- **Abstraction**: we used consistent prefixes (`k_`, `s_`, `u_`) to denote kernel, system, and user-level functions.
- **Process Control Block (PCB)**: Stores process metadata—PID, state, priority, file descriptors—used across scheduling and management.
- **Scheduler**: Priority-based with multiple queues for different process states (running, blocked, zombie, etc.).
- **Filesystem Integration**: Kernel interfaces cleanly with the FAT filesystem, maintaining a strict separation.
- **Error Handling**: Unified error system modeled after `errno`/`perror` for consistent diagnostics.

