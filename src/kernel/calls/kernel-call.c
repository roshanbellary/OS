#include "kernel-call.h"
#include <stdio.h>
#include <string.h>
#include "../../util/Vec.h"
#include "../../util/deque.h"
#include "../../util/logger/logger.h"
#include "../../util/types/process-status.h"
#include "../kernel.h"
#include "signal.h"

pid_t k_get_current_process_pid()
{
  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  spthread_enable_interrupts_self();
  return k->curr_process->pid;
}

pcb_t *k_get_current_process()
{
  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  if (k->curr_process == NULL)
  {
    return NULL;
  }
  pcb_t *proc = k->curr_process;
  spthread_enable_interrupts_self();
  return proc;
}

int k_get_lowest_pid()
{
  // set lock
  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  Vec *current_processes = &(k->current_processes);
  int lowest_pid = -1;
  int length = vec_len(current_processes);
  for (int i = 1; i < length; i++)
  {
    pcb_t *val = vec_get(current_processes, i);
    if (val == NULL)
    {
      lowest_pid = i;
      break;
    }
  }
  if (lowest_pid == -1)
  {
    lowest_pid = vec_len(current_processes);
    pcb_t *v = NULL;
    vec_push_back(current_processes, v);
  }
  spthread_enable_interrupts_self();
  // end lock
  return lowest_pid;
}
pcb_t *k_proc_create(pcb_t *parent)
{
  if (parent == NULL)
  {
    return NULL;
  }
  pcb_t *child = malloc(sizeof(pcb_t));
  if (child == NULL)
  {
    return NULL;
  }
  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  // implemented this get_lowest_pid method to get the lowest available pid
  child->pid = k_get_lowest_pid();
  child->ppid = parent->pid;
  // Copy priority level and set status
  child->priority_level = parent->priority_level;
  child->status = PROCESS_STATUS_RUNNING;
  child->status_changed = false;
  // Copy over the file descriptors
  child->file_descriptors = deque_new(free);
  for (int i = 0; i < deque_size(parent->file_descriptors); i++)
  {
    int *fd = malloc(sizeof(int));
    *fd = *(int *)deque_get_nth_elem(parent->file_descriptors, i);
    deque_push_back(child->file_descriptors, fd);
  }
  // end lock
  child->thread = malloc(sizeof(spthread_t));
  if (child->pid == vec_len(&(k->current_processes)))
  {
    vec_push_back(&(k->current_processes), child);
  }
  else
  {
    vec_set(&(k->current_processes), child->pid, child);
  }
  spthread_enable_interrupts_self();
  return child;
}

void k_proc_cleanup(pcb_t *proc)
{
  spthread_disable_interrupts_self();
  if (proc == NULL)
  {
    return;
  }
  // close open files
  ProcessFDNode *cur = proc->fd_table;
  ProcessFDNode *next;
  while (cur != NULL)
  {
    next = cur->next;
    free(cur);
    cur = next;
  }

  // free the process information
  free(proc->thread);
  // free(proc->name);
  int pid = proc->pid;
  free(proc);
  // remove the process from the current processes vector
  KernelState *k = getKernelState();
  vec_set(&(k->current_processes), pid, NULL);
  spthread_enable_interrupts_self();
}

int k_release_fd(pcb_t *proc, int local_fd)
{
  return 0;
}

pcb_t *k_get_proc(pid_t pid)
{
  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  if (pid < 0 || pid >= vec_len(&(k->current_processes)))
  {
    return NULL;
  }
  pcb_t *proc = vec_get(&(k->current_processes), pid);
  spthread_enable_interrupts_self();
  return proc;
}

int k_write(int fd, const char *buf, int n)
{
  if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
  {
    return -1;
  }
  ssize_t bytesWritten = write(fd, buf, n); // Use n, not strlen
  return (int)bytesWritten;
}

int k_read(char *store_result, int len, int fd)
{
  ssize_t bytesRead = read(STDIN_FILENO, store_result, len);
  if (bytesRead > 0 && store_result[bytesRead - 1] == '\n')
  {
    store_result[bytesRead - 1] = '\0';
  }
  return bytesRead;
}

pcb_t *k_get_process_by_pid(pid_t pid)
{
  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  if (pid < 0 || pid >= vec_len(&(k->current_processes)))
  {
    return NULL;
  }
  pcb_t *proc = vec_get(&(k->current_processes), pid);
  spthread_enable_interrupts_self();
  return proc;
}