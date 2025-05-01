#define _POSIX_C_SOURCE 200809L
#include "penn-shell.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../kernel/calls/sys-call.h"
#include "../kernel/p_errno.h"
#include "./execute_command.h"
#include "parser.h"
#include "../kernel/pcb.h" // Include pcb to use ProcessStatus enum
#include "../util/deque.h" // Include deque if using it for job list
#include <errno.h>         // For errno with strtol
#include <limits.h>        // For INT_MAX, INT_MIN with strtol
#include <signals.h>

#define LINE_BUFFER_CHUNK_SIZE 128

// Helper to free job memory
Deque *job_list;
int next_job_id;
pid_t shell_pid;
pid_t terminal_controller_pid = -1; // -1 means uninitialized

void free_job(void *data)
{
  Job *job = (Job *)data;
  if (job)
  {
    free(job->command);
    if (job->pcmd)
    { // Free the stored parsed command
      free(job->pcmd);
    }
    free(job);
  }
}

// Initialize job list (call from shell start)
void initialize_job_control()
{
  if (job_list == NULL)
  {
    job_list = deque_new(free_job);
    if (!job_list)
    {
      perror("Failed to create job list"); // Host OS error
      exit(EXIT_FAILURE);
    }
    // shell_pid assignment removed to avoid overwriting in child/helper processes
  }
}

// Find job by PID
Job *find_job_by_pid(pid_t pid)
{
  if (!job_list)
    return NULL;
  for (int i = 0; i < deque_size(job_list); ++i)
  {
    Job *job = (Job *)deque_get_nth_elem(job_list, i);
    if (job && job->pid == pid)
    {
      return job;
    }
  }
  return NULL;
}

// Find job by Job ID
Job *find_job_by_id(int job_id)
{
  if (!job_list)
    return NULL;
  for (int i = 0; i < deque_size(job_list); ++i)
  {
    Job *job = (Job *)deque_get_nth_elem(job_list, i);
    if (job && job->job_id == job_id)
    {
      return job;
    }
  }
  return NULL;
}

// Find the most recently added job (highest job_id)
Job *find_last_job()
{
  if (!job_list || deque_size(job_list) == 0)
    return NULL;
  Job *last_job = NULL;
  int max_id = -1;
  for (int i = 0; i < deque_size(job_list); ++i)
  {
    Job *job = (Job *)deque_get_nth_elem(job_list, i);
    // Find highest job ID, irrespective of status for general "last job"
    if (job && job->job_id > max_id)
    {
      max_id = job->job_id;
      last_job = job;
    }
  }
  return last_job;
}

// Find the most recently stopped job
Job *find_last_stopped_job()
{
  if (!job_list || deque_size(job_list) == 0)
    return NULL;
  for (int i = deque_size(job_list) - 1; i >= 0; --i)
  {
    Job *job = (Job *)deque_get_nth_elem(job_list, i);
    if (job && job->status == JOB_STATUS_STOPPED)
    {
      // Return the first stopped one found when iterating backwards
      return job;
    }
  }
  return NULL; // No stopped jobs
}

// Helper function to rebuild command string from argv (for logging/display)
char *reconstruct_command(char *argv[])
{
  if (!argv || !argv[0])
    return strdup("");

  size_t total_len = 0;
  int i = 0;
  while (argv[i] != NULL)
  {
    total_len += strlen(argv[i]) + 1; // +1 for space or null terminator
    i++;
  }

  if (total_len == 0)
    return strdup("");

  char *cmd_str = malloc(total_len);
  if (!cmd_str)
  {
    u_perror("reconstruct_command: malloc failed");
    return NULL; // Indicate failure
  }

  cmd_str[0] = '\0'; // Start with an empty string
  i = 0;
  while (argv[i] != NULL)
  {
    strcat(cmd_str, argv[i]);
    if (argv[i + 1] != NULL)
    {
      strcat(cmd_str, " "); // Add space between arguments
    }
    i++;
  }
  return cmd_str;
}

// Add a job to the list
void add_job(pid_t pid, struct parsed_command *cmd, JobStatus status)
{
  if (!job_list || !cmd)
    return;

  Job *new_job = malloc(sizeof(Job));
  if (!new_job)
  {
    u_perror("add_job: malloc failed");
    return;
  }
  new_job->pid = pid;
  new_job->job_id = next_job_id++;

  char *reconstructed_cmd = reconstruct_command(cmd->commands[0]);
  if (!reconstructed_cmd)
  {
    u_perror("add_job: command reconstruction failed");
    free(new_job);
    return;
  }
  new_job->command = reconstructed_cmd; // Store the reconstructed command

  new_job->pcmd = NULL; // Not storing parsed command for now

  new_job->status = status;

  deque_push_back(job_list, new_job);

  // Print background job start message
  if (status == JOB_STATUS_RUNNING && !cmd->is_background)
  { // Only print if explicitly backgrounded
    char buf[MAX_MESSAGE_SIZE];
    snprintf(buf, sizeof(buf), "[%d] %d\n", new_job->job_id, new_job->pid);
    s_write(STDOUT_FILENO, buf, strlen(buf));
  }
}

void remove_job_by_pid(pid_t pid)
{
  if (!job_list)
    return;
  for (int i = 0; i < deque_size(job_list); ++i)
  {
    Job *job = (Job *)deque_get_nth_elem(job_list, i);
    if (job && job->pid == pid)
    {
      Job *removed_job = deque_remove_nth_elem(job_list, i); // Assumes this returns the data pointer
      if (removed_job)
      {
        free_job(removed_job); // Use the helper to free
      }
      return;
    }
  }
}

int read_line_from_fd(int fd,
                      char **line_buffer,
                      size_t *buffer_size,
                      size_t *line_len)
{
  // Terminal control enforcement for stdin
  if (fd == STDIN_FILENO)
  {
    if (s_getpid() != terminal_controller_pid)
    {
      // Only the terminal controller can read from stdin
      s_kill(s_getpid(), P_SIGSTOP); // Send PennOS stop signal to self
      return -1;
    }
  }
  if (!line_buffer || !buffer_size || !line_len)
    return -1; // Invalid args

  // Initialize buffer if necessary
  if (*line_buffer == NULL || *buffer_size == 0)
  {
    *buffer_size = LINE_BUFFER_CHUNK_SIZE;
    *line_buffer = malloc(*buffer_size);
    if (!(*line_buffer))
    {
      P_ERRNO = P_ERRNO_INTERNAL; // Indicate memory error
      return -1;
    }
    *line_len = 0;
  }

  size_t total_bytes_read = 0;
  while (1)
  {
    // Check if buffer needs resizing before reading
    if (*line_len >= *buffer_size - 1)
    { // -1 for null terminator
      size_t new_size = *buffer_size + LINE_BUFFER_CHUNK_SIZE;
      char *new_buffer = realloc(*line_buffer, new_size);
      if (!new_buffer)
      {
        P_ERRNO = P_ERRNO_INTERNAL;
        return -1; // Memory error
      }
      *line_buffer = new_buffer;
      *buffer_size = new_size;
    }

    // Read a chunk into the available space
    int bytes_read =
        s_read(fd, (*line_buffer) + *line_len, *buffer_size - *line_len - 1);

    if (bytes_read > 0)
    {
      *line_len += bytes_read;
      total_bytes_read += bytes_read;
      (*line_buffer)[*line_len] = '\0'; // Null-terminate

      // Check if newline was read
      if (strchr((*line_buffer) + (*line_len - bytes_read), '\n') != NULL)
      {
        return total_bytes_read; // Found newline, return total bytes read in
                                 // this call sequence
      }
    }
    else if (bytes_read == 0)
    {
      // EOF reached
      return total_bytes_read; // Return whatever was read, even if 0
    }
    else
    {
      // Error during s_read (P_ERRNO should be set by s_read)
      return -1;
    }
  }
}

void *shell(void *args)
{
  shell_pid = s_getpid();
  terminal_controller_pid = shell_pid;

  job_list = deque_new(free_job); // Use the custom free function
  if (!job_list)
  {
    perror("Failed to create job list"); // Use perror for host OS errors
    exit(EXIT_FAILURE);
  }
  shell_pid = s_getpid();              // Get the shell's own PID
  terminal_controller_pid = shell_pid; // Shell initially has terminal control

  while (1)
  {
    // updaet job status
    spthread_disable_interrupts_self(); // Protect job list access
    int initial_size = deque_size(job_list);
    int jobs_checked = 0;
    int current_index = 0;
    while (jobs_checked < initial_size && current_index < deque_size(job_list))
    {
      Job *job = (Job *)deque_get_nth_elem(job_list, current_index);
      jobs_checked++; // Count checked attempts

      if (job && job->status != JOB_STATUS_DONE)
      { // Only check active jobs
        int status;
        pid_t changed_pid = s_waitpid(job->pid, &status, 1); // NOHANG = true

        if (changed_pid == job->pid)
        {
          char buf[MAX_MESSAGE_SIZE];
          if (P_WIFEXITED(status) || P_WIFSIGNALED(status))
          {
            snprintf(buf, sizeof(buf), "[%d]+ Done\t\t%s\n", job->job_id, job->command);
            s_write(STDOUT_FILENO, buf, strlen(buf));
            job->status = JOB_STATUS_DONE; // Mark for removal
                                           // remove_job_by_pid(job->pid); // Remove immediately or later
          }
          else if (P_WIFSTOPPED(status))
          {
            snprintf(buf, sizeof(buf), "[%d]+ Stopped\t\t%s\n", job->job_id, job->command);
            s_write(STDOUT_FILENO, buf, strlen(buf));
            job->status = JOB_STATUS_STOPPED;
            // Don't increment current_index, stay to re-check if needed? No, waitpid handles it.
            current_index++; // Move to next job
          }
          else
          {
            // Still running or other state?
            current_index++; // Move to next job
          }
        }
        else if (changed_pid < 0 && (P_ERRNO == P_ERRNO_ECHILD || P_ERRNO == P_ERRNO_ESRCH))
        {
          // Process doesn't exist anymore (e.g., reaped by init after shell exit?)
          char buf[MAX_MESSAGE_SIZE];
          snprintf(buf, sizeof(buf), "[%d]+ Done (No Child)\t%s\n", job->job_id, job->command);
          s_write(STDOUT_FILENO, buf, strlen(buf));
          job->status = JOB_STATUS_DONE; // Mark for removal
                                         // remove_job_by_pid(job->pid); // Remove immediately or later
        }
        else
        {
          // No change or error other than no child
          current_index++; // Move to next job
        }
      }
      else
      {
        // Job was already marked DONE or is NULL
        current_index++; // Move to next job
      }
    }
    // Clean up jobs marked as DONE
    current_index = 0;
    while (current_index < deque_size(job_list))
    {
      Job *job = (Job *)deque_get_nth_elem(job_list, current_index);
      if (job && job->status == JOB_STATUS_DONE)
      {
        Job *removed = deque_remove_nth_elem(job_list, current_index);
        free_job(removed);
        // Don't increment index, next element shifts down
      }
      else
      {
        current_index++;
      }
    }
    spthread_enable_interrupts_self(); // Release lock

    char *input = malloc(sizeof(char) * (MAX_MESSAGE_SIZE + 1));
    if (input == NULL)
    {
      exit(EXIT_FAILURE);
    }
    int wait_ret;
    while ((wait_ret = s_waitpid(-1, NULL, 1)) > 0)
    {
      // Wait for any child process to change state
    }
    if (wait_ret == -1)
      u_perror("waitpid");

    // Print the shell prompt
    if (s_write(STDOUT_FILENO, "$ ", 3) == -1)
      u_perror("write");

    // Reading user input
    int read_size = s_read(STDIN_FILENO, input, MAX_MESSAGE_SIZE);
    if (read_size == 0)
    {
      exit(EXIT_SUCCESS); // EOF, exit shell
    }
    if (read_size == -1)
      u_perror("read");
    if (read_size <= 0 || input[0] == '\0' || input[0] == '\n')
    {
      free(input);
      continue;
    }
    input[read_size] = '\0';

    struct parsed_command *cmd;
    int parse_result = parse_command(input, &cmd);
    if (parse_result == 0)
    {
      if (cmd->num_commands > 0)
      {
        pid_t child_pid = execute_command(cmd);
        if (child_pid < 0)
        {
          char *msg = "Invalid command\n";
          if (s_write(STDERR_FILENO, msg, 17) == -1)
            u_perror("write");
        }
      }
    }
    else
    {
      const char *msg = "Invalid command\n";
      s_write(STDERR_FILENO, msg, 17);
    }
    free(cmd);
  }
  return NULL;
}
