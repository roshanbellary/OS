#define _POSIX_C_SOURCE 200809L
#include "kernel.h"
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "../fat/err.h"
#include "../fat/fat_core.h"
#include "../util/logger/logger.h"
#include "../util/types/process-status.h"
#include "pcb.h"
static const int centisecond = 10000;

volatile unsigned long kernel_ticks = 0;

volatile bool g_shutdown_requested = false;

unsigned long get_kernel_ticks()
{
  return kernel_ticks;
}

// handler that
void alarm_handler(int signum) {}

struct KernelState k;

KernelState *getKernelState()
{
  return &k;
}

void stop_handler(int signum)
{
  KernelState *k = getKernelState();
  if (k->curr_process != NULL)
  {
    k->curr_process->status = PROCESS_STATUS_STOPPED;
    k->curr_process->status_changed = true;
    log_event(get_kernel_ticks(), "STOPPED", k->curr_process->pid,
              k->curr_process->priority_level, k->curr_process->name);
    pcb_t *parent_proc =
        vec_get(&(k->current_processes), k->curr_process->ppid);
    if (parent_proc && parent_proc->status == PROCESS_STATUS_WAITING)
    {
      parent_proc->status = PROCESS_STATUS_RUNNING;
      add_process_to_run_queue(parent_proc);
      log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
                parent_proc->priority_level, parent_proc->name);
    }
  }
}

void int_handler(int signum)
{
  KernelState *k = getKernelState();
  if (k->curr_process != NULL)
  {
    if (strcmp(k->curr_process->name, "penn-shell") == 0)
    {
      exit(EXIT_SUCCESS);
    }
    k->curr_process->status = PROCESS_STATUS_ZOMBIE;
    k->curr_process->status_changed = true;
    log_event(get_kernel_ticks(), "SIGNALED", k->curr_process->pid,
              k->curr_process->priority_level, k->curr_process->name);
    pcb_t *parent_proc =
        vec_get(&(k->current_processes), k->curr_process->ppid);
    if (parent_proc && parent_proc->status == PROCESS_STATUS_WAITING)
    {
      parent_proc->status = PROCESS_STATUS_RUNNING;
      add_process_to_run_queue(parent_proc);
      log_event(get_kernel_ticks(), "UNBLOCKED", parent_proc->pid,
                parent_proc->priority_level, parent_proc->name);
    }
  }
}
void kernel_set_up()
{
  // setting up the suspend set and Kernel state
  k.curr_thread_num = 0;
  k.process_quanta = 19;
  k.current_processes = vec_new(3, NULL);
  vec_push_back(&(k.current_processes), NULL);
  k.curr_process = NULL;
  for (int i = 0; i < 3; i++)
  {
    k.dq_RUNNING[i] = deque_new(NULL);
  }
  k.dq_ZOMBIE = deque_new(NULL);
  k.dq_BLOCKED = deque_new(NULL);
  k.dq_STOPPED = deque_new(NULL); // Initialize STOPPED queue
  k.terminal_owner_pid = 2;
}
void start_kernel()
{
  sigset_t suspend_set;
  sigfillset(&suspend_set);
  sigdelset(&suspend_set, SIGALRM);
  sigdelset(&suspend_set, SIGTSTP);
  sigdelset(&suspend_set, SIGINT);

  // setting up alarm signal handler
  struct sigaction act;
  act.sa_handler = alarm_handler;
  act.sa_flags = SA_RESTART;
  sigaction(SIGALRM, &act, NULL);

  struct sigaction stop_act;
  stop_act.sa_handler = stop_handler;
  stop_act.sa_flags = SA_RESTART;
  sigaction(SIGTSTP, &stop_act, NULL);

  struct sigaction int_act;
  int_act.sa_handler = int_handler;
  int_act.sa_flags = SA_RESTART;
  sigaction(SIGINT, &int_act, NULL);

  // unblocking alarm signal
  sigset_t alarm_set;
  sigemptyset(&alarm_set);
  sigaddset(&alarm_set, SIGALRM);
  sigaddset(&alarm_set, SIGTSTP);
  sigaddset(&alarm_set, SIGINT);
  pthread_sigmask(SIG_UNBLOCK, &alarm_set, NULL);

  struct itimerval it;
  it.it_interval = (struct timeval){.tv_usec = centisecond * 10};
  it.it_value = it.it_interval;
  setitimer(ITIMER_REAL, &it, NULL);
  // Ratio of process time based on priority is 2.25:1.5: 1 -> 9:6:4
  // 0: 9/19 of time
  // 1: 6/19 of time
  // 2: 4/19 of time
  while (1)
  {
    // check for shutdown request
    spthread_disable_interrupts_self();
    if (g_shutdown_requested)
    {
      const char *msg1 = "[Kernel] Shutdown detected. Cleaning up...\n";
      write(STDOUT_FILENO, msg1, strlen(msg1));
      if (fs_unmount() != 0)
      {
        f_perror("[Kernel] Filesystem unmount failed during shutdown");
      }
      else
      {
        const char *msg2 = "[Kernel] Filesystem unmounted successfully.\n";
        write(STDOUT_FILENO, msg2, strlen(msg2));
      }
      const char *msg3 = "[Kernel] Exiting scheduler loop.\n";
      write(STDOUT_FILENO, msg3, strlen(msg3));
      spthread_enable_interrupts_self();
      break; // Exit while(1)
    }
    spthread_enable_interrupts_self();

    kernel_ticks++;
    int which_queue = 0;
    int process_running = -1;
    for (int i = 0; i < 3; i++)
    {
      if (deque_size(k.dq_RUNNING[i]) > 0)
      {
        process_running = i;
        break;
      }
    }
    if (process_running < 0)
    {
      log_event(get_kernel_ticks(), "SCHEDULE", -1, -1, "IDLE");
      check_blocked_processes();
      sigsuspend(&suspend_set);
      continue;
    }

    k.curr_thread_num = (k.curr_thread_num + 1) % k.process_quanta;
    if (k.curr_thread_num < 9)
    {
      which_queue = 0;
    }
    else if (k.curr_thread_num < 15)
    {
      which_queue = 1;
    }
    else
    {
      which_queue = 2;
    }
    if (deque_size(k.dq_RUNNING[which_queue]) == 0)
    {
      which_queue = process_running;
    }
    pcb_t *curr_process = (pcb_t *)deque_pop_front(k.dq_RUNNING[which_queue]);
    if (curr_process == NULL)
    {
      log_event(get_kernel_ticks(), "SCHEDULE", -1, -1, "IDLE");
      k.curr_thread_num = (k.curr_thread_num + 1) % k.process_quanta;
      continue;
    }
    k.curr_process = curr_process;
    log_event(get_kernel_ticks(), "SCHEDULE", curr_process->pid,
              curr_process->priority_level, curr_process->name);

    spthread_t *curr_thread = curr_process->thread;
    spthread_continue(*curr_thread);
    sigsuspend(&suspend_set);
    spthread_suspend(*curr_thread);
    if (curr_process->status == PROCESS_STATUS_RUNNING)
    {
      deque_push_back(k.dq_RUNNING[curr_process->priority_level], curr_process);
    }
    else if (curr_process->status == PROCESS_STATUS_BLOCKED)
    {
      deque_push_back(k.dq_BLOCKED, curr_process);
    }
    else if (curr_process->status == PROCESS_STATUS_STOPPED)
    {
      deque_push_back(k.dq_STOPPED, curr_process);
    }
    check_blocked_processes();
  }
}

void check_blocked_processes()
{
  int num_blocked = deque_size(k.dq_BLOCKED);
  for (int i = 0; i < num_blocked; i++)
  {
    pcb_t *proc = (pcb_t *)deque_get_nth_elem(k.dq_BLOCKED, i);
    if (proc == NULL)
      continue;
    if (proc->status == PROCESS_STATUS_BLOCKED &&
        get_kernel_ticks() >= proc->wake_up_tick)
    {
      proc->status = PROCESS_STATUS_RUNNING;
      deque_push_back(k.dq_RUNNING[proc->priority_level], proc);
      log_event(get_kernel_ticks(), "UNBLOCKED", proc->pid,
                proc->priority_level, proc->name);
      deque_remove_nth_elem(k.dq_BLOCKED, i);
      num_blocked--;
    }
  }
}

void add_process_to_scheduler(pcb_t *proc)
{
  if (proc == NULL)
    return;

  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();

  int prio = proc->priority_level;
  if (prio < 0 || prio > 2)
  {
    spthread_enable_interrupts_self();
    return;
  }
  deque_push_back(k->dq_RUNNING[prio], proc);
  if (proc->pid < vec_len(&(k->current_processes)))
  {
    vec_set(&(k->current_processes), proc->pid, proc);
  }
  else
  {
    vec_push_back(&(k->current_processes), proc);
  }
  spthread_enable_interrupts_self();
}

void add_process_to_run_queue(pcb_t *proc)
{
  if (proc == NULL)
    return;

  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();

  int prio = proc->priority_level;
  if (prio < 0 || prio > 2)
  {
    spthread_enable_interrupts_self();
    return;
  }
  if (proc->status == PROCESS_STATUS_RUNNING)
  {
    deque_push_back(k->dq_RUNNING[prio], proc);
  }
  spthread_enable_interrupts_self();
}

void remove_process_from_run_queue(pcb_t *proc)
{
  if (proc == NULL)
    return;

  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();

  int prio = proc->priority_level;
  if (prio < 0 || prio > 2)
  {
    spthread_enable_interrupts_self();
    return;
  }

  Deque *queue = k->dq_RUNNING[prio];
  for (int i = 0; i < deque_size(queue); i++)
  {
    pcb_t *p = deque_get_nth_elem(queue, i);
    if (p == proc || (p && p->pid == proc->pid))
    {
      deque_remove_nth_elem(queue, i);
      break;
    }
  }

  spthread_enable_interrupts_self();
}

void add_process_to_zombie_queue(pcb_t *proc)
{
  if (proc == NULL)
    return;

  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();
  deque_push_back(k->dq_ZOMBIE, proc);
  spthread_enable_interrupts_self();
}

void remove_process_from_zombie_queue(pcb_t *proc)
{
  if (proc == NULL)
    return;

  spthread_disable_interrupts_self();
  KernelState *k = getKernelState();

  for (int i = 0; i < deque_size(k->dq_ZOMBIE); i++)
  {
    pcb_t *p = deque_get_nth_elem(k->dq_ZOMBIE, i);
    if (p == proc || (p && p->pid == proc->pid))
    {
      deque_remove_nth_elem(k->dq_ZOMBIE, i);
      break;
    }
  }

  spthread_enable_interrupts_self();
}
