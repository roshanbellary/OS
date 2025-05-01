#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "../../fat/fat_core.h"
#include "../../fat/fat_kernel.h"
#include "../../util/logger/logger.h"
#include "../../util/spthread.h"
#include "../../util/types/process-status.h"
#include "../../util/types/signals.h"
#include "../fat/err.h"
#include "../fat/fat_kernel.h"
#include "../kernel.h"
#include "../p_errno.h"
#include "../pcb.h"
#include "kernel-call.h"
#include "sys-call.h"

// helper for error stuff
int map_fat_error_to_p_errno(int fat_errno) {
  switch (fat_errno) {
    case FILE_NOT_FOUND:
      return P_ERRNO_FILE_NOT_FOUND;
    case PERMISSION_DENIED:
      return P_ERRNO_PERMISSION;
    case INVALID_ARGS:
      return P_ERRNO_INVALID_ARG;
    case NO_SPACE:
      return P_ERRNO_NO_SPACE;
    case MEMORY_ERROR:
    case FILE_SYSTEM:
    case MOUNT:
    case UNMOUNT:
    case MKFS:
      return P_ERRNO_INTERNAL;
    case INVALID_FD:
      return P_ERRNO_INVALID_FD;
    case INVALID_OPERATION:
      return P_ERRNO_INVALID_OPERATION;
    case FS_NOT_MOUNTED:
      return P_ERRNO_NOT_MOUNTED;
    case FS_ALREADY_MOUNTED:
      return P_ERRNO_ALREADY_MOUNTED;
    case NOT_A_DIRECTORY:
      return P_ERRNO_NOT_A_DIRECTORY;
    case INVALID_WHENCE:
      return P_ERRNO_INVALID_WHENCE;
    case INVALID_OFFSET:
      return P_ERRNO_INVALID_OFFSET;
    default:
      return P_ERRNO_UNKNOWN;
  }
}

int s_open(const char* fname, int mode) {
  if (!fname) {
    P_ERRNO = P_ERRNO_INVALID_ARG;
    return -1;
  }

  pcb_t* pcb = k_get_current_process();
  if (!pcb) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  if (mode == F_WRITE || mode == F_APPEND) {
    KernelState* k = getKernelState();
    for (int i = 0; i < vec_len(&k->current_processes); ++i) {
      pcb_t* proc = (pcb_t*)vec_get(&k->current_processes, i);
      if (!proc || !proc->fd_table)
        continue;

      ProcessFDNode* node = proc->fd_table;
      while (node) {
        if (strcmp(node->fname, fname) == 0 &&
            (node->mode == F_WRITE || node->mode == F_APPEND)) {
          P_ERRNO = P_ERRNO_WRITE_CONFLICT;
          return -1;
        }
        node = node->next;
      }
    }
  }

  int initial_offset = 0;
  if (mode == F_APPEND) {
    Dir_entry entry = name_to_directory((char*)fname);
    if (entry.name[0] != 0) {
      initial_offset = entry.size;
    }
  }

  int fd = k_open(fname, mode);
  if (fd < 0) {
    extern int ERRNO;
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
    return -1;
  }

  int proc_fd = pcb_add_fd(pcb, fd, fname, mode, initial_offset);
  if (proc_fd < 0) {
    k_close(fd);
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  return proc_fd;
}

int s_read(int fd, char* buf, int n) {
  pcb_t* pcb = k_get_current_process();
  if (!pcb) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  ProcessFDNode* node = pcb_get_fd(pcb, fd);
  if (!node) {
    P_ERRNO = P_ERRNO_INVALID_FD;
    return -1;
  }

  if (fd == STDIN_FILENO) {
    spthread_disable_interrupts_self();
    KernelState* k = getKernelState();
    bool is_owner = (pcb->pid == k->terminal_owner_pid);
    spthread_enable_interrupts_self();

    if (!is_owner) {
      s_kill(pcb->pid, P_SIGSTOP);

      P_ERRNO = P_ERRNO_PERMISSION;
      return -1;
    }
  }

  if (node->fname[0] == '\0') {
    if (fd == STDIN_FILENO) {
      int ret = k_read(buf, n, STDIN_FILENO);
      if (ret < 0) {
        P_ERRNO = P_ERRNO_INTERNAL;
      } else {
        P_ERRNO = P_ERRNO_SUCCESS;
      }
      return ret;
    } else {
      P_ERRNO = P_ERRNO_INVALID_OPERATION;
      return -1;
    }
  }

  Dir_entry entry = name_to_directory(node->fname);
  if (entry.name[0] == 0 || entry.name[0] == 1 || entry.name[0] == 2) {
    P_ERRNO = P_ERRNO_FILE_NOT_FOUND;
    return -1;
  }
  if (!(entry.perm & 4)) {
    P_ERRNO = P_ERRNO_PERMISSION;
    return -1;
  }
  if (node->offset >= entry.size) {
    P_ERRNO = P_ERRNO_SUCCESS;
    return 0;
  }
  int bytes_available = entry.size - node->offset;
  int bytes_to_read = (bytes_available < n) ? bytes_available : n;
  if (bytes_to_read < 0)
    bytes_to_read = 0;

  int bytes_read =
      read_file(entry, (uint8_t*)buf, bytes_to_read, 0, node->offset);

  if (bytes_read > 0) {
    node->offset += bytes_read;
    P_ERRNO = P_ERRNO_SUCCESS;
  } else if (bytes_read == 0) {
    P_ERRNO = P_ERRNO_SUCCESS;
  } else {
    extern int ERRNO;
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
  }
  return bytes_read;
}

int s_write(int fd, const char* str, int n) {
  pcb_t* pcb = k_get_current_process();
  if (!pcb) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  ProcessFDNode* node = pcb_get_fd(pcb, fd);

  if (!node) {
    P_ERRNO = P_ERRNO_INVALID_FD;
    return -1;
  }

  if (node->fname[0] == '\0') {
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
      int ret = k_write(fd, (char*)str, n);

      if (ret < 0) {
        P_ERRNO = P_ERRNO_INTERNAL;
        return -1;
      } else {
        P_ERRNO = P_ERRNO_SUCCESS;

        return n;
      }
    } else {
      P_ERRNO = P_ERRNO_INVALID_OPERATION;
      return -1;
    }
  }

  if (node->mode != F_WRITE && node->mode != F_APPEND) {
    P_ERRNO = P_ERRNO_INVALID_OPERATION;
    return -1;
  }

  Dir_entry entry = name_to_directory(node->fname);
  if (entry.name[0] == 0 || entry.name[0] == 1 || entry.name[0] == 2) {
    P_ERRNO = P_ERRNO_FILE_NOT_FOUND;
    return -1;
  }

  if (!(entry.perm & 2)) {
    P_ERRNO = P_ERRNO_PERMISSION;
    return -1;
  }

  int bytes_written = write_file(entry, (uint8_t*)str, n, node->offset);

  if (bytes_written > 0) {
    node->offset += bytes_written;
    P_ERRNO = P_ERRNO_SUCCESS;
  } else if (bytes_written == 0) {
    P_ERRNO = P_ERRNO_SUCCESS;
  } else {
    extern int ERRNO;
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
  }

  return bytes_written;
}

int s_close(int fd) {
  if (fd < 0) {
    P_ERRNO = P_ERRNO_INVALID_FD;
    return -1;
  }

  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    P_ERRNO = P_ERRNO_INVALID_OPERATION;
    return -1;
  }

  pcb_t* pcb = k_get_current_process();
  if (!pcb) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  ProcessFDNode* node = pcb_get_fd(pcb, fd);
  if (!node) {
    P_ERRNO = P_ERRNO_INVALID_FD;
    return -1;
  }

  int result = k_close(fd);

  if (result < 0) {
    extern int ERRNO;
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
    return -1;
  }

  if (pcb_remove_fd(pcb, fd) != 0) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  return 0;
}

int s_lseek(int fd, int offset, int whence) {
  pcb_t* pcb = k_get_current_process();
  if (!pcb) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  ProcessFDNode* node = pcb_get_fd(pcb, fd);
  if (!node) {
    P_ERRNO = P_ERRNO_INVALID_FD;
    return -1;
  }

  if (fd <= 2) {
    P_ERRNO = P_ERRNO_INVALID_OPERATION;
    return -1;
  }

  char* filename = node->fname;

  Dir_entry entry;
  if (whence == SEEK_END) {
    entry = name_to_directory(filename);
    if (entry.name[0] == 0) {
      P_ERRNO = P_ERRNO_FILE_NOT_FOUND;
      return -1;
    }
  }

  int new_offset;
  if (whence == SEEK_SET) {
    new_offset = offset;
  } else if (whence == SEEK_CUR) {
    new_offset = node->offset + offset;
  } else if (whence == SEEK_END) {
    new_offset = entry.size + offset;
  } else {
    P_ERRNO = P_ERRNO_INVALID_WHENCE;
    return -1;
  }

  if (new_offset < 0) {
    P_ERRNO = P_ERRNO_INVALID_OFFSET;
    return -1;
  }

  if (whence == SEEK_END || whence == SEEK_SET) {
    if (whence == SEEK_SET) {
      entry = name_to_directory(filename);
      if (entry.name[0] == 0) {
        P_ERRNO = P_ERRNO_FILE_NOT_FOUND;
        return -1;
      }
    }

    if (new_offset > entry.size) {
      P_ERRNO = P_ERRNO_INVALID_OFFSET;
      return -1;
    }
  }

  k_lseek(fd, offset, whence);

  node->offset = new_offset;

  P_ERRNO = P_ERRNO_SUCCESS;
  return new_offset;
}

int s_unlink(const char* fname) {
  if (!fname) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return -1;
  }

  // check if a process has this file open
  KernelState* k = getKernelState();
  for (int i = 0; i < vec_len(&k->current_processes); ++i) {
    pcb_t* proc = (pcb_t*)vec_get(&k->current_processes, i);
    if (!proc || !proc->fd_table)
      continue;

    ProcessFDNode* node = proc->fd_table;
    while (node) {
      if (strcmp(node->fname, fname) == 0) {
        P_ERRNO = P_ERRNO_PERMISSION;
        return -1;
      }
      node = node->next;
    }
  }

  int result = fs_rm((char*)fname);
  if (result < 0) {
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
    return -1;
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  return 0;
}

/**
 * @brief List files in the filesystem.
 *
 * @param filename List specific file if not NULL, otherwise list all files.
 */
static void s_ls_callback(const Dir_entry* entry, void* user_data) {
  (void)user_data;
  char buffer[4096];
  format_file_info(*entry, buffer);
  s_write(STDERR_FILENO, buffer, strlen(buffer));
}

void s_ls(const char* filename) {
  fs_list_files(filename, s_ls_callback, NULL);
}
pid_t s_spawn(void* (*func)(void*),
              char* argv[],
              int fd0,  // FD number from the PARENT's perspective for stdin
              int fd1,  // FD number from the PARENT's perspective for stdout
              int foreground) {
  spthread_disable_interrupts_self();  //

  pcb_t* parent = k_get_current_process();
  if (parent == NULL) {
    P_ERRNO = P_ERRNO_INTERNAL;
    spthread_enable_interrupts_self();
    return -1;
  }

  // Create child PCB (k_proc_create might set some defaults)
  pcb_t* child = k_proc_create(parent);
  if (child == NULL) {
    P_ERRNO = P_ERRNO_INTERNAL;
    spthread_enable_interrupts_self();
    return -1;
  }

  // --- Set up child's standard FDs (0, 1, 2) ---
  child->fd_table = NULL;  // Ensure it starts empty

  // Configure FD 0 (stdin) for the child
  ProcessFDNode* parent_fd0_node = pcb_get_fd(parent, fd0);  //
  if (fd0 == STDIN_FILENO && !parent_fd0_node) {
    // Parent used standard TTY stdin, child inherits the same conceptually
    if (pcb_set_fd(child, STDIN_FILENO, NULL, F_READ, 0) < 0)
      goto spawn_error;  // Use NULL fname for TTY
  } else if (parent_fd0_node) {
    // Parent had fd0 pointing to a specific file/node, copy details
    if (pcb_set_fd(child, STDIN_FILENO, parent_fd0_node->fname,
                   parent_fd0_node->mode, 0) < 0)
      goto spawn_error;  // Reset offset to 0 for child's stdin
  } else {
    // Invalid fd0 provided by parent
    P_ERRNO = P_ERRNO_INVALID_FD;  // Or internal error?
    goto spawn_error;
  }

  // Configure FD 1 (stdout) for the child
  ProcessFDNode* parent_fd1_node = pcb_get_fd(parent, fd1);
  if (fd1 == STDOUT_FILENO && !parent_fd1_node) {
    // Parent used standard TTY stdout
    if (pcb_set_fd(child, STDOUT_FILENO, NULL, F_WRITE, 0) < 0)
      goto spawn_error;
  } else if (parent_fd1_node) {
    // Parent had fd1 pointing to a specific file/node
    if (pcb_set_fd(child, STDOUT_FILENO, parent_fd1_node->fname,
                   parent_fd1_node->mode,
                   (parent_fd1_node->mode == F_APPEND)
                       ? name_to_directory(parent_fd1_node->fname).size
                       : 0) < 0)  // Set offset based on mode
      goto spawn_error;
  } else {
    // Invalid fd1 provided by parent
    P_ERRNO = P_ERRNO_INVALID_FD;
    goto spawn_error;
  }

  if (fd1 == STDOUT_FILENO && !parent_fd1_node) {  // Inheriting TTY
    if (pcb_set_fd(child, STDERR_FILENO, NULL, F_WRITE, 0) < 0)
      goto spawn_error;
  } else if (parent_fd1_node) {  // Point stderr to the same file as stdout
    if (pcb_set_fd(child, STDERR_FILENO, parent_fd1_node->fname,
                   parent_fd1_node->mode,
                   (parent_fd1_node->mode == F_APPEND)
                       ? name_to_directory(parent_fd1_node->fname).size
                       : 0) < 0)
      goto spawn_error;
  }

  child->thread = malloc(sizeof(spthread_t));
  if (!child->thread) {
    P_ERRNO = P_ERRNO_INTERNAL;
    goto spawn_error;
  }

  // Set process name (using strdup for safety)
  if (argv == NULL || argv[0] == NULL) {
    child->name = strdup("penn-shell");
  } else {
    child->name = strdup(argv[0]);
  }
  if (!child->name) {
    P_ERRNO = P_ERRNO_INTERNAL;
    goto spawn_error_after_thread_alloc;
  }  // Check strdup result

  // Create the actual thread
  if (spthread_create(child->thread, NULL, func, argv) !=
      0) {                       // Check return value
    P_ERRNO = P_ERRNO_INTERNAL;  // Failed to create thread
    goto spawn_error_after_name_alloc;
  }

  child->foreground = foreground;
  // if (foreground) {
  //   KernelState* k = getKernelState();
  //   k->terminal_owner_pid = child->pid;
  // }

  log_event(get_kernel_ticks(), "CREATE", child->pid, child->priority_level,
            child->name);
  add_process_to_scheduler(
      child);  // Assumes this function handles the current_processes vector
  P_ERRNO = P_ERRNO_SUCCESS;
  spthread_enable_interrupts_self();
  return child->pid;

// --- Error Handling Labels for Cleanup ---
spawn_error_after_name_alloc:
  free(child->name);
spawn_error_after_thread_alloc:
  free(child->thread);
spawn_error:
  if (child->fd_table) {  // Free FD table nodes if allocated
    ProcessFDNode* current = child->fd_table;
    ProcessFDNode* next;
    while (current != NULL) {
      next = current->next;
      free(current);
      current = next;
    }
  }
  if (child->name && argv && argv[0] && child->name != argv[0])
    free(child->name);  // Free name if strdup'd
  if (child->thread)
    free(child->thread);
  // How to remove from Vec? vec_erase? Or mark as NULL?
  KernelState* k = getKernelState();
  vec_set(&(k->current_processes), child->pid, NULL);  // Mark slot as free
  free(child);

  spthread_enable_interrupts_self();
  return -1;  // Return error
}

pid_t s_waitpid_helper(pid_t curr_proc_pid, pid_t pid, int* wstatus) {
  KernelState* k = getKernelState();
  if (k == NULL) {
    return -1;
  }
  if (curr_proc_pid < 0) {
    return -1;
  }

  // checks if a given pid is there and in that case it starts checking status
  // of it
  if (pid > 0) {
    pcb_t* child_proc = (pcb_t*)vec_get(&k->current_processes, pid);
    if (child_proc == NULL || child_proc->pid == curr_proc_pid) {
      return -1;
    }
    if (child_proc->status == PROCESS_STATUS_ZOMBIE &&
        child_proc->ppid == curr_proc_pid) {
      if (wstatus != NULL) {
        *wstatus = child_proc->status;
      }
      log_event(get_kernel_ticks(), "WAITED", child_proc->pid,
                child_proc->priority_level, child_proc->name);
      k_proc_cleanup(child_proc);
      return pid;
    } else if (child_proc->ppid == curr_proc_pid &&
               child_proc->status_changed) {
      if (wstatus != NULL) {
        *wstatus = child_proc->status;
      }
      child_proc->status_changed = false;
      log_event(get_kernel_ticks(), "WAITED", child_proc->pid,
                child_proc->priority_level, child_proc->name);
      return child_proc->pid;
    }
  }
  bool child_exists = 0;
  // in the case that pid is -1, we check all the children of the current
  // process
  for (int i = 2; i < vec_len(&k->current_processes); i++) {
    pcb_t* child_proc = (pcb_t*)vec_get(&k->current_processes, i);
    // Checking if child process is null
    if (child_proc == NULL || i == curr_proc_pid) {
      continue;
    }
    if (child_proc->ppid == curr_proc_pid) {
      child_exists = 1;
    }
    // Check if the child process is a child of the current process
    if (child_proc->ppid == curr_proc_pid &&
        child_proc->status == PROCESS_STATUS_ZOMBIE) {
      if (wstatus != NULL) {
        *wstatus = child_proc->status;
      }
      log_event(get_kernel_ticks(), "WAITED", i, child_proc->priority_level,
                child_proc->name);
      k_proc_cleanup(child_proc);
      return i;
      // checking if it was just a simple status change
    } else if (child_proc->ppid == curr_proc_pid &&
               child_proc->status_changed) {
      if (wstatus != NULL) {
        *wstatus = child_proc->status;
      }
      child_proc->status_changed = false;
      log_event(get_kernel_ticks(), "WAITED", i, child_proc->priority_level,
                child_proc->name);
      return i;
    }
  }
  if (!child_exists) {
    return -2;
  }
  return 0;
}
pid_t s_waitpid(pid_t pid, int* wstatus, int nohang) {
  pcb_t* current_proc = k_get_current_process();
  if (!nohang) {
    log_event(get_kernel_ticks(), "BLOCKED", current_proc->pid,
              current_proc->priority_level, current_proc->name);
    current_proc->status = PROCESS_STATUS_WAITING;
  }
  while (!nohang) {
    if (current_proc == NULL) {
      fprintf(stderr,
              "KERNEL PANIC: s_waitpid called by non-existent process!\n");
      P_ERRNO = P_ERRNO_INTERNAL;
      return -1;
    }
    current_proc->status = PROCESS_STATUS_WAITING;
    int result = s_waitpid_helper(current_proc->pid, pid, wstatus);
    if (result != 0) {
      if (current_proc->status == PROCESS_STATUS_WAITING) {
        current_proc->status = PROCESS_STATUS_RUNNING;
        log_event(get_kernel_ticks(), "UNBLOCKED", current_proc->pid,
                  current_proc->priority_level, current_proc->name);
      }
      P_ERRNO = (result != -1) ? P_ERRNO_SUCCESS : P_ERRNO_INTERNAL;
      return result;
    }
  }
  if (current_proc == NULL) {
    fprintf(stderr,
            "KERNEL PANIC: s_waitpid called by non-existent process!\n");
    return -1;
  }
  int v = s_waitpid_helper(current_proc->pid, pid, wstatus);
  current_proc->status = PROCESS_STATUS_RUNNING;
  if (v > 0) {
    P_ERRNO = P_ERRNO_SUCCESS;
  }
  if (v == -2) {
    P_ERRNO = P_ERRNO_SUCCESS;
  }
  if (v == -1) {
    P_ERRNO = P_ERRNO_INTERNAL;
  }
  return v;
}

void s_sleep(unsigned int ticks) {
  spthread_disable_interrupts_self();

  pcb_t* current_proc = k_get_current_process();

  if (current_proc == NULL) {
    fprintf(stderr, "KERNEL PANIC: s_sleep called by non-existent process!\n");
    spthread_enable_interrupts_self();
    return;
  }

  if (current_proc->term_signal != 0 ||
      current_proc->status == PROCESS_STATUS_ZOMBIE) {
    spthread_enable_interrupts_self();
    return;
  }

  if (ticks == 0) {
    spthread_enable_interrupts_self();
    return;
  }

  current_proc->wake_up_tick = get_kernel_ticks() + ticks;

  current_proc->status = PROCESS_STATUS_BLOCKED;
  log_event(get_kernel_ticks(), "BLOCKED", current_proc->pid,
            current_proc->priority_level, current_proc->name);
  spthread_enable_interrupts_self();
  while (current_proc->status == PROCESS_STATUS_BLOCKED) {
  }
  return;
}

static bool remove_from_state_queue(KernelState* k, pcb_t* proc) {
  if (!k || !proc)
    return false;
  bool removed = false;

  // Check Running queues
  for (int i = 0; i < 3; ++i) {
    if (deque_remove_specific(k->dq_RUNNING[i], proc) != NULL) {
      removed = true;
      break;  // Found and removed
    }
  }
  if (removed)
    return true;

  // Check Blocked queue
  if (deque_remove_specific(k->dq_BLOCKED, proc) != NULL) {
    removed = true;
  }
  if (removed)
    return true;

  // Check Stopped queue
  if (deque_remove_specific(k->dq_STOPPED, proc) != NULL) {
    removed = true;
  }

  return removed;
}

int s_kill(pid_t pid, int signal) {
  int result = 0;
  spthread_disable_interrupts_self();  // Lock kernel access
  KernelState* k = getKernelState();

  pcb_t* target_proc = k_get_proc(pid);  // Use the kernel helper
  pcb_t* parent_proc = NULL;             // For potential parent notification

  if (target_proc == NULL) {
    P_ERRNO = P_ERRNO_ESRCH;  // No such process
    result = -1;
    goto kill_cleanup;
  }

  // Cannot signal init (PID 1) except maybe SIGCONT for robustness? Usually
  // disallowed.
  if (pid == 1 && (signal == P_SIGTERM || signal == P_SIGSTOP)) {
    P_ERRNO = P_ERRNO_PERMISSION;
    result = -1;
    goto kill_cleanup;
  }

  // Cannot signal a Zombie process
  if (target_proc->status == PROCESS_STATUS_ZOMBIE) {
    P_ERRNO = P_ERRNO_ESRCH;  // Treat zombie as non-existent for signaling
    result = -1;
    goto kill_cleanup;
  }
  // Cannot signal a Dead process (if you implement DEAD state)
  if (target_proc->status == PROCESS_STATUS_DEAD) {
    P_ERRNO = P_ERRNO_ESRCH;
    result = -1;
    goto kill_cleanup;
  }

  switch (signal) {
    case P_SIGSTOP:
      // Can stop Running or Blocked (incl. Waiting logically) processes
      if (target_proc->status == PROCESS_STATUS_RUNNING ||
          target_proc->status == PROCESS_STATUS_BLOCKED ||
          target_proc->status == PROCESS_STATUS_WAITING) {
        target_proc->status = PROCESS_STATUS_STOPPED;
        target_proc->status_changed = true;  // Mark change for waitpid

        // Remove from its current state queue (if any)
        remove_from_state_queue(k, target_proc);

        // Add to Stopped queue
        if (!deque_contains(k->dq_STOPPED, target_proc)) {
          deque_push_back(k->dq_STOPPED, target_proc);
        }

        log_event(get_kernel_ticks(), "STOPPED", target_proc->pid,
                  target_proc->priority_level, target_proc->name);

        // Check if parent is waiting and notify
        parent_proc = k_get_proc(target_proc->ppid);
        if (parent_proc && parent_proc->status == PROCESS_STATUS_WAITING) {
          parent_proc->status = PROCESS_STATUS_RUNNING;
          parent_proc->status_changed = true;
          // Parent is no longer waiting, add back to scheduler
          add_process_to_scheduler(parent_proc);
          log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
                    parent_proc->priority_level, parent_proc->name);
        }
      }
      // If already stopped, it's a no-op (success)
      break;

    case P_SIGCONT:
      if (target_proc->status == PROCESS_STATUS_STOPPED) {
        target_proc->status = PROCESS_STATUS_RUNNING;
        target_proc->status_changed = true;

        // Remove from Stopped queue
        deque_remove_specific(k->dq_STOPPED, target_proc);

        // Add back to scheduler's run queues
        add_process_to_scheduler(target_proc);

        log_event(get_kernel_ticks(), "CONTINUED", target_proc->pid,
                  target_proc->priority_level, target_proc->name);

        // Notify waiting parent? Usually not needed for CONT.
        parent_proc = k_get_proc(target_proc->ppid);
        if (parent_proc && parent_proc->status == PROCESS_STATUS_WAITING) {
          parent_proc->status = PROCESS_STATUS_RUNNING;
          parent_proc->status_changed = true;
          add_process_to_scheduler(parent_proc);
          log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
                    parent_proc->priority_level, parent_proc->name);
        }
      }
      // If already running, blocked, or waiting, CONT is a no-op (success)
      break;

    case P_SIGTERM:
      log_event(get_kernel_ticks(), "SIGNALED", target_proc->pid,
                target_proc->priority_level, target_proc->name);

      target_proc->term_signal = P_SIGTERM;  // Record termination signal
      target_proc->status_changed = true;

      // Remove from whatever state queue it's currently in
      remove_from_state_queue(k, target_proc);

      target_proc->status = PROCESS_STATUS_ZOMBIE;

      // Add to Zombie queue
      add_process_to_zombie_queue(
          target_proc);  // Assumes this handles potential duplicates safely

      // Wake parent if waiting
      parent_proc = k_get_proc(target_proc->ppid);
      if (parent_proc && parent_proc->status == PROCESS_STATUS_WAITING) {
        parent_proc->status = PROCESS_STATUS_RUNNING;
        parent_proc->status_changed = true;
        add_process_to_scheduler(parent_proc);
        log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
                  parent_proc->priority_level, parent_proc->name);
      }

      // Reparent children (Same logic as before)
      for (int i = 0; i < vec_len(&k->current_processes); i++) {
        pcb_t* child = vec_get(&k->current_processes, i);
        if (child && child != target_proc && child->ppid == target_proc->pid) {
          child->ppid = 1;  // Reparent to init
          log_event(get_kernel_ticks(), "ORPHAN", child->pid,
                    child->priority_level, child->name);
        }
      }
      // int zombie_count = deque_size(k->dq_ZOMBIE);
      // for (int i = 0; i < zombie_count; ++i) {
      //   pcb_t* zombie_child = (pcb_t*)deque_get_nth_elem(k->dq_ZOMBIE, i);
      //   if (zombie_child != NULL && zombie_child != target_proc &&
      //       zombie_child->ppid == target_proc->pid) {
      //     log_event(get_kernel_ticks(), "ORPHAN", zombie_child->pid,
      //               zombie_child->priority_level, zombie_child->name);
      //     zombie_child->ppid = 1;  // Reparent zombie child to init
      //                              // Wake up init if it's waiting
      //     pcb_t* init_proc = k_get_proc(1);
      //     if (init_proc && init_proc->status == PROCESS_STATUS_WAITING) {
      //       init_proc->status = PROCESS_STATUS_RUNNING;
      //       init_proc->status_changed = true;
      //       add_process_to_scheduler(init_proc);
      //       log_event(get_kernel_ticks(), "UNBLOCKED", init_proc->pid,
      //                 init_proc->priority_level, init_proc->name);
      //     }
      //   }
      // }
      break;

    default:
      P_ERRNO = P_ERRNO_EINVAL;  // Invalid signal number
      result = -1;
      break;
  }
  goto kill_cleanup;

kill_cleanup:
  if (result == 0 && P_ERRNO == 0)
    P_ERRNO = P_ERRNO_SUCCESS;
  spthread_enable_interrupts_self();
  return result;
}
int s_set_terminal_owner(pid_t pid) {
  spthread_disable_interrupts_self();
  KernelState* k = getKernelState();
  pcb_t* current_process = k_get_current_process();
  pcb_t* target_process = k_get_proc(pid);

  if (!current_process) {
    P_ERRNO = P_ERRNO_INTERNAL;  // Should not happen
    spthread_enable_interrupts_self();
    return -1;
  }

  // Allow setting owner if pid is valid and exists (or is the shell itself)
  if (pid < 0 || !target_process) {
    P_ERRNO = P_ERRNO_ESRCH;  // Target process doesn't exist
    spthread_enable_interrupts_self();
    return -1;
  }

  k->terminal_owner_pid = pid;
  P_ERRNO = P_ERRNO_SUCCESS;
  spthread_enable_interrupts_self();
  return 0;
}
void s_nice_pid(int prio, int pid) {
  spthread_disable_interrupts_self();
  pcb_t* proc = k_get_process_by_pid(pid);
  if (proc == NULL) {
    fprintf(stderr,
            "KERNEL PANIC: s_nice_pid called on non-existent process!\n");
    spthread_enable_interrupts_self();
    return;
  }
  if (prio < 0 || prio > 2) {
    fprintf(stderr, "KERNEL PANIC: Invalid priority level!\n");
    spthread_enable_interrupts_self();
    return;
  }
  proc->priority_level = prio;
  log_event(get_kernel_ticks(), "NICE_PID", proc->pid, prio, proc->name);
  if (proc->status == PROCESS_STATUS_RUNNING) {
    remove_process_from_run_queue(proc);
    add_process_to_run_queue(proc);
  }
  spthread_enable_interrupts_self();
  return;
}
void s_exit(void) {
  spthread_disable_interrupts_self();
  KernelState* k = getKernelState();
  pcb_t* proc = k_get_current_process();

  if (proc == NULL) {
    fprintf(stderr, "KERNEL PANIC: s_exit called by non-existent process!\n");
    spthread_enable_interrupts_self();
    raise(SIGALRM);
    return;
  }

  if (proc->pid == 1) {
    g_shutdown_requested = true;
  }

  log_event(get_kernel_ticks(), "EXITED", proc->pid, proc->priority_level,
            proc->name);

  proc->term_signal = 0;
  proc->status_changed = true;
  proc->status = PROCESS_STATUS_ZOMBIE;
  deque_push_back(k->dq_ZOMBIE, proc);

  // Handle orphaned children
  for (int i = 0; i < vec_len(&k->current_processes); i++) {
    pcb_t* child_proc = (pcb_t*)vec_get(&k->current_processes, i);
    if (child_proc != NULL && child_proc->ppid == proc->pid) {
      log_event(get_kernel_ticks(), "ORPHAN", child_proc->pid,
                child_proc->priority_level, child_proc->name);
      child_proc->ppid = 1;
    }
  }

  // Wake parent process (if it's waiting)
  pcb_t* parent_proc = k_get_process_by_pid(proc->ppid);
  if (parent_proc != NULL && parent_proc->status == PROCESS_STATUS_WAITING) {
    parent_proc->status = PROCESS_STATUS_RUNNING;
    log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
              parent_proc->priority_level, parent_proc->name);
    add_process_to_run_queue(parent_proc);
  }

  spthread_enable_interrupts_self();

  raise(SIGALRM);
}

int s_nice(pid_t pid, int priority) {
  spthread_disable_interrupts_self();

  // P_ERRNO = 0;

  if (priority < 0 || priority > 2) {
    P_ERRNO = P_ERRNO_EINVAL;
    spthread_enable_interrupts_self();
    return -1;
  }

  pcb_t* target_proc = k_get_proc(pid);
  if (target_proc == NULL) {
    P_ERRNO = P_ERRNO_ESRCH;
    spthread_enable_interrupts_self();
    return -1;
  }

  if (target_proc->status == PROCESS_STATUS_ZOMBIE ||
      target_proc->status == PROCESS_STATUS_DEAD) {
    P_ERRNO = P_ERRNO_ESRCH;
    spthread_enable_interrupts_self();
    return -1;
  }

  int old_priority = target_proc->priority_level;

  if (old_priority != priority) {
    char* name_process = target_proc->name;
    log_event(get_kernel_ticks(), "NICE", target_proc->pid, priority,
              name_process);

    target_proc->priority_level = priority;

    if (target_proc->status == PROCESS_STATUS_RUNNING) {
      remove_process_from_run_queue(target_proc);
      add_process_to_run_queue(target_proc);
    }
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  spthread_enable_interrupts_self();
  return 0;
}

char* s_itos(int n) {
  int is_negative = (n < 0);
  int temp = is_negative ? -n : n;

  if (n == 0) {
    char* str = malloc(2);
    if (!str) {
      P_ERRNO = P_ERRNO_INTERNAL;
      return NULL;
    }
    str[0] = '0';
    str[1] = '\0';
    P_ERRNO = P_ERRNO_SUCCESS;
    return str;
  }

  int l = 0;
  int x = temp;
  while (x > 0) {
    l++;
    x /= 10;
  }

  char* str = malloc(l + is_negative + 1);
  if (!str) {
    P_ERRNO = P_ERRNO_INTERNAL;
    return NULL;
  }

  str[l + is_negative] = '\0';
  for (int i = l + is_negative - 1; i >= is_negative; i--) {
    str[i] = (temp % 10) + '0';
    temp /= 10;
  }

  if (is_negative) {
    str[0] = '-';
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  return str;
}

void s_ps() {
  spthread_disable_interrupts_self();
  KernelState* k = getKernelState();
  int num_processes = vec_len(&k->current_processes);

  for (int i = 0; i < num_processes; i++) {
    pcb_t* proc = (pcb_t*)vec_get(&k->current_processes, i);
    if (proc != NULL) {
      char* pid_str = s_itos(proc->pid);
      char* ppid_str = s_itos(proc->ppid);
      char* prio_str = s_itos(proc->priority_level);
      char* status = "U";

      if (proc->status == PROCESS_STATUS_RUNNING)
        status = "R";
      else if (proc->status == PROCESS_STATUS_BLOCKED ||
               proc->status == PROCESS_STATUS_WAITING)
        status = "B";
      else if (proc->status == PROCESS_STATUS_ZOMBIE)
        status = "Z";
      else if (proc->status == PROCESS_STATUS_STOPPED)
        status = "S";

      s_write(STDOUT_FILENO, pid_str, strlen(pid_str));
      s_write(STDOUT_FILENO, " ", 1);
      s_write(STDOUT_FILENO, ppid_str, strlen(ppid_str));
      s_write(STDOUT_FILENO, " ", 1);
      s_write(STDOUT_FILENO, prio_str, strlen(prio_str));
      s_write(STDOUT_FILENO, " ", 1);
      s_write(STDOUT_FILENO, status, 1);
      s_write(STDOUT_FILENO, " ", 1);
      s_write(STDOUT_FILENO, proc->name, strlen(proc->name));
      s_write(STDOUT_FILENO, "\n", 1);

      free(pid_str);
      free(ppid_str);
      free(prio_str);
    }
  }

  spthread_enable_interrupts_self();
}

void s_register_end() {
  spthread_disable_interrupts_self();
  pcb_t* proc = k_get_current_process();
  if (proc == NULL) {
    log_event(get_kernel_ticks(), "ERROR", -1, -1, "NULL_PROCESS");
  }
  KernelState* k = getKernelState();

  // Orphan all children of the current process
  for (int i = 0; i < vec_len(&k->current_processes); i++) {
    pcb_t* child_proc = (pcb_t*)vec_get(&k->current_processes, i);
    if (child_proc != NULL && child_proc->ppid == proc->pid &&
        child_proc->status == PROCESS_STATUS_RUNNING) {
      log_event(get_kernel_ticks(), "ORPHAN", child_proc->pid,
                child_proc->priority_level, child_proc->name);
      child_proc->ppid = 0;
    }
  }
  // Set the process as a zombie
  proc->status = PROCESS_STATUS_ZOMBIE;
  log_event(get_kernel_ticks(), "EXITED", proc->pid, proc->priority_level,
            proc->name);
  proc->status_changed = true;
  pid_t parent_pid = proc->ppid;
  pcb_t* parent_proc = k_get_proc(parent_pid);

  // If the parent process is waiting which means it called waitpid, unblock it
  if (parent_proc != NULL && parent_proc->status == PROCESS_STATUS_WAITING) {
    parent_proc->status = PROCESS_STATUS_RUNNING;
    add_process_to_scheduler(parent_proc);
    log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
              parent_proc->priority_level, parent_proc->name);
  } else {
    log_event(get_kernel_ticks(), "ZOMBIE", proc->pid, proc->priority_level,
              proc->name);
  }
  spthread_enable_interrupts_self();
}

int s_chmod(const char* fname, const char* mode_str) {
  if (!fname || !mode_str) {
    P_ERRNO = P_ERRNO_INVALID_ARG;
    return -1;
  }

  // Parsing logic for +/-rwx (same as in f_chmod)
  if (strlen(mode_str) < 2 || (mode_str[0] != '+' && mode_str[0] != '-')) {
    P_ERRNO = P_ERRNO_INVALID_ARG;  // Use P_ERRNO code
    return -1;
  }

  // Get current permissions first
  Dir_entry ent = name_to_directory((char*)fname);
  if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2) {
    // name_to_directory should set FAT ERRNO if not found
    extern int ERRNO;
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);  // Use the mapping function
    if (P_ERRNO == P_ERRNO_SUCCESS)
      P_ERRNO = P_ERRNO_FILE_NOT_FOUND;  // Ensure error is set
    return -1;
  }

  uint8_t current_perm = ent.perm;
  uint8_t change_perm = 0;
  for (int i = 1; i < strlen(mode_str); ++i) {
    switch (mode_str[i]) {
      case 'r':
        change_perm |= 4;
        break;
      case 'w':
        change_perm |= 2;
        break;
      case 'x':
        change_perm |= 1;
        break;
      default:
        P_ERRNO = P_ERRNO_INVALID_ARG;
        return -1;
    }
  }

  uint8_t new_perm;
  if (mode_str[0] == '+') {
    new_perm = current_perm | change_perm;
  } else {  // mode_str[0] == '-'
    new_perm = current_perm & (~change_perm);
  }

  // Call the core FAT function directly
  if (fs_chmod((char*)fname, new_perm) < 0) {
    // fs_chmod sets FAT ERRNO, map it
    extern int ERRNO;
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
    return -1;
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  return 0;  // Success
}

// Add this function definition
int s_get_permission(const char* fname) {
  if (!fname) {
    P_ERRNO = P_ERRNO_INVALID_ARG;
    return -1;
  }

  // Call the kernel-level function
  int perm = k_get_permission(fname);

  if (perm < 0) {
    // k_get_permission sets FAT ERRNO, map it to P_ERRNO
    P_ERRNO = map_fat_error_to_p_errno(ERRNO);
    if (P_ERRNO == P_ERRNO_SUCCESS)
      P_ERRNO = P_ERRNO_FILE_NOT_FOUND;  // Ensure error
    return -1;                           // Return error indication
  }

  P_ERRNO = P_ERRNO_SUCCESS;
  return perm;  // Return the permission value
}

pid_t s_getpid(void) {
  return k_get_current_process_pid();
}