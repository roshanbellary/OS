#include "execute_command.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signals.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../fat/fat_core.h"
#include "../fat/fat_kernel.h"
#include "../kernel/calls/kernel-call.h"
#include "../kernel/calls/sys-call.h"
#include "../kernel/calls/user-call.h"
#include "../kernel/pcb.h"
#include "../kernel/p_errno.h"
#include "../util/deque.h"
#include "parser.h"
#include "penn-shell.h"
#include "stress.h"

int handle_shell_builtin(struct parsed_command *cmd)
{
  if (!cmd || cmd->num_commands == 0 || !cmd->commands[0] ||
      !cmd->commands[0][0])
  {
    return -1; // Not a valid command
  }

  char *command_name = cmd->commands[0][0];
  char **argv = cmd->commands[0]; // Arguments for the first (and only
                                  // relevant) command part

  if (strcmp(command_name, "jobs") == 0)
  {
    spthread_disable_interrupts_self(); // Protect job list access
    if (!job_list || deque_size(job_list) == 0)
    {
      s_write(STDOUT_FILENO, "No active jobs.\n", 16);
    }
    else
    {
      for (int i = 0; i < deque_size(job_list); ++i)
      {
        Job *job = (Job *)deque_get_nth_elem(job_list, i);
        if (job)
        {
          char buf[MAX_MESSAGE_SIZE];
          const char *status_str = "Unknown";
          if (job->status == JOB_STATUS_RUNNING)
            status_str = "Running";
          else if (job->status == JOB_STATUS_STOPPED)
            status_str = "Stopped";
          else
            continue; // Don't display DONE jobs

          snprintf(buf, sizeof(buf), "[%d]+ %s\t\t%s\n", job->job_id,
                   status_str, job->command);
          s_write(STDOUT_FILENO, buf, strlen(buf));
        }
      }
    }
    spthread_enable_interrupts_self();
    P_ERRNO = P_ERRNO_SUCCESS;
    return 0; // Built-in handled
  }
  else if (strcmp(command_name, "bg") == 0)
  {
    spthread_disable_interrupts_self();
    Job *target_job = NULL;
    if (argv[1] != NULL)
    { // Job ID specified
      char *endptr;
      long id_long = strtol(argv[1], &endptr, 10);
      if (argv[1] == endptr || *endptr != '\0' || id_long > INT_MAX ||
          id_long < 1)
      { // Job IDs start from 1
        s_write(STDERR_FILENO, "bg: invalid job ID\n", 19);
        P_ERRNO = P_ERRNO_INVALID_ARG;
        spthread_enable_interrupts_self();
        return 0; // Handled (with error)
      }
      int id = (int)id_long;
      target_job = find_job_by_id(id);
      if (!target_job)
      {
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "bg: %s: no such job\n", argv[1]);
        s_write(STDERR_FILENO, err_buf, strlen(err_buf));
        P_ERRNO = P_ERRNO_ESRCH;
        spthread_enable_interrupts_self();
        return 0; // Handled (with error)
      }
    }
    else
    { // No job ID, use last stopped
      target_job = find_last_stopped_job();
      if (!target_job)
      {
        s_write(STDERR_FILENO, "bg: no current job\n",
                19); // Or no stopped job
        P_ERRNO = P_ERRNO_ESRCH;
        spthread_enable_interrupts_self();
        return 0; // Handled (with error)
      }
    }

    if (target_job->status != JOB_STATUS_STOPPED)
    {
      s_write(STDERR_FILENO, "bg: job already running or finished\n", 36);
      P_ERRNO = P_ERRNO_INVALID_OPERATION;
      spthread_enable_interrupts_self();
      return 0; // Handled (with error)
    }

    // Send SIGCONT
    pid_t target_pid =
        target_job->pid;                                // Copy PID before potential list modification
    char *target_cmd_str = strdup(target_job->command); // Copy command string

    spthread_enable_interrupts_self(); // Unlock before syscall

    if (s_kill(target_pid, P_SIGCONT) == 0)
    {
      spthread_disable_interrupts_self();             // Relock
      Job *updated_job = find_job_by_pid(target_pid); // Find job again
      if (updated_job)
      { // Update status if job still exists
        updated_job->status = JOB_STATUS_RUNNING;
      }
      spthread_enable_interrupts_self(); // Unlock

      char buf[MAX_MESSAGE_SIZE];
      snprintf(buf, sizeof(buf), "[%d]+ %s &\n", target_job->job_id,
               target_cmd_str);
      s_write(STDOUT_FILENO, buf, strlen(buf));
      P_ERRNO = P_ERRNO_SUCCESS;
    }
    else
    {
      u_perror("bg: s_kill(CONT) failed"); // s_kill sets P_ERRNO
    }
    free(target_cmd_str);
    return 0; // Built-in handled
  }
  else if (strcmp(command_name, "fg") == 0)
  {
    spthread_disable_interrupts_self(); // Lock
    Job *target_job = NULL;

    if (argv[1] != NULL)
    { // Job ID specified
      char *endptr;
      long id_long = strtol(argv[1], &endptr, 10);
      if (argv[1] == endptr || *endptr != '\0' || id_long > INT_MAX ||
          id_long < 1)
      {
        s_write(STDERR_FILENO, "fg: invalid job ID\n", 19);
        P_ERRNO = P_ERRNO_INVALID_ARG;
        spthread_enable_interrupts_self();
        return 0; // Handled (with error)
      }
      int id = (int)id_long;
      target_job = find_job_by_id(id);
      if (!target_job)
      {
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "fg: %s: no such job\n", argv[1]);
        s_write(STDERR_FILENO, err_buf, strlen(err_buf));
        P_ERRNO = P_ERRNO_ESRCH;
        spthread_enable_interrupts_self();
        return 0; // Handled (with error)
      }
    }
    else
    {
      target_job = find_last_job(); // Get the most recently added job
      if (!target_job)
      {
        s_write(STDERR_FILENO, "fg: no current job\n", 19);
        P_ERRNO = P_ERRNO_ESRCH;
        spthread_enable_interrupts_self();
        return 0; // Handled (with error)
      }
    }

    pid_t fg_pid = target_job->pid;
    char *fg_command =
        strdup(target_job->command); // Copy command before removing job
    JobStatus fg_status = target_job->status;

    remove_job_by_pid(fg_pid); // This frees the original job structure

    spthread_enable_interrupts_self(); // Unlock before potentially blocking
                                       // calls

    // Print command being brought to foreground
    s_write(STDOUT_FILENO, fg_command, strlen(fg_command));
    s_write(STDOUT_FILENO, "\n", 1);

    // Set terminal owner
    if (s_set_terminal_owner(fg_pid) != 0)
    {
      u_perror("fg: failed to set terminal owner");
      free(fg_command);
      // Attempt to give terminal back to shell on error, idk, double check @Roshan
      s_set_terminal_owner(shell_pid);
      terminal_controller_pid = shell_pid;
      return 0; // Handled (with error)
    }
    terminal_controller_pid = fg_pid;

    // Continue if stopped
    if (fg_status == JOB_STATUS_STOPPED)
    {
      if (s_kill(fg_pid, P_SIGCONT) != 0)
      {
        u_perror("fg: s_kill(CONT) failed");
        s_set_terminal_owner(shell_pid); // Give terminal back to shell
        free(fg_command);
        // Don't re-add job here, it failed to continue
        return 0; // Handled (with error)
      }
    }

    // Wait for the foreground process
    int wait_status;
    pid_t waited_pid = s_waitpid(fg_pid, &wait_status, 0); // Blocking wait
    // Give terminal control back to shell *regardless* of wait outcome
    s_set_terminal_owner(shell_pid);
    terminal_controller_pid = shell_pid;

    if (waited_pid < 0)
    {
      // Error during waitpid (unless it's ECHILD, meaning process finished
      // quickly)
      if (P_ERRNO != P_ERRNO_ECHILD)
      {
        u_perror("fg: s_waitpid failed");
      }
      // Don't re-add the job if wait failed or ECHILD
    }
    else
    {
      // Check if the foreground process was stopped again *after* waiting
      if (P_WIFSTOPPED(wait_status))
      {
        spthread_disable_interrupts_self();
        add_job(fg_pid, NULL, JOB_STATUS_STOPPED); // Re-add as stopped job
        Job *readded_job = find_job_by_pid(fg_pid);
        if (readded_job)
        {
          free(readded_job->command); // Free the default ""
          readded_job->command =
              strdup(fg_command); // Assign the correct command
        }
        spthread_enable_interrupts_self();
        // Print stopped message? The shell loop's update might catch this too.
        char buf[MAX_MESSAGE_SIZE];
        snprintf(buf, sizeof(buf), "\n[%d]+ Stopped\t\t%s\n",
                 find_job_by_pid(fg_pid)->job_id,
                 fg_command); // Use find_job again for potentially new ID
        s_write(STDOUT_FILENO, buf, strlen(buf));
      }
      // If exited or signaled, it's handled, no need to re-add.
    }

    free(fg_command);
    return 0;
  }
  else if (strcmp(command_name, "nice") == 0)
  {
    if (argv[1] == NULL || argv[2] == NULL)
    {
      s_write(STDERR_FILENO, "nice: requires priority and command\n", 36);
      P_ERRNO = P_ERRNO_INVALID_ARG;
      return 0; // Handled (with error)
    }

    char *prio_str = argv[1];
    char *target_cmd_name = argv[2];
    char **target_argv =
        &argv[2]; // argv for the target command starts from argv[2]

    char *endptr;
    long prio_long = strtol(prio_str, &endptr, 10);
    if (prio_str == endptr || *endptr != '\0' || prio_long < 0 ||
        prio_long > 2)
    {
      s_write(STDERR_FILENO, "nice: invalid priority (must be 0, 1, or 2)\n",
              44);
      P_ERRNO = P_ERRNO_INVALID_ARG;
      return 0; // Handled (with error)
    }
    int priority = (int)prio_long;

    // Find the function pointer for the target command
    void *(*func_ptr)(void *) = NULL;
    // (Copy the func_ptr lookup logic from execute_single_command here)
    if (strcmp(target_cmd_name, "cat") == 0)
      func_ptr = u_cat;
    else if (strcmp(target_cmd_name, "sleep") == 0)
      func_ptr = u_sleep;
    else if (strcmp(target_cmd_name, "busy") == 0)
      func_ptr = u_busy;
    else if (strcmp(target_cmd_name, "echo") == 0)
      func_ptr = u_echo;
    else if (strcmp(target_cmd_name, "ls") == 0)
      func_ptr = u_ls;
    else if (strcmp(target_cmd_name, "touch") == 0)
      func_ptr = u_touch;
    else if (strcmp(target_cmd_name, "mv") == 0)
      func_ptr = u_mv;
    else if (strcmp(target_cmd_name, "cp") == 0)
      func_ptr = u_cp;
    else if (strcmp(target_cmd_name, "rm") == 0)
      func_ptr = u_rm;
    else if (strcmp(target_cmd_name, "chmod") == 0)
      func_ptr = u_chmod; // Note: chmod is now also a shell builtin
    else if (strcmp(target_cmd_name, "ps") == 0)
      func_ptr = u_ps;
    else if (strcmp(target_cmd_name, "zombify") == 0)
      func_ptr = u_zombify;
    else if (strcmp(target_cmd_name, "orphanify") == 0)
      func_ptr = u_orphanify;
    // Cannot 'nice' shell builtins like fg, bg, jobs, nice, nice_pid, logout,
    // man
    else
    {
      char err_buf[MAX_MESSAGE_SIZE];
      snprintf(err_buf, sizeof(err_buf),
               "nice: command not found or cannot be niced: %s\n",
               target_cmd_name);
      s_write(STDERR_FILENO, err_buf, strlen(err_buf));
      P_ERRNO = P_ERRNO_FILE_NOT_FOUND; // Or appropriate error
      return 0;                         // Handled (with error)
    }

    bool is_foreground = !cmd->is_background;

    pid_t child_pid = s_spawn(func_ptr, target_argv, STDIN_FILENO,
                              STDOUT_FILENO, is_foreground);

    if (child_pid < 0)
    {
      u_perror("nice: s_spawn failed");
      return 0; // Handled (with error)
    }

    if (s_nice(child_pid, priority) != 0)
    {
      u_perror("nice: s_nice failed");
    }

    if (is_foreground)
    {
      int status;
      // Give terminal control to child
      s_set_terminal_owner(child_pid);
      pid_t waited_pid = s_waitpid(child_pid, &status, 0); // Blocking wait
      // Give terminal control back to shell
      s_set_terminal_owner(shell_pid);

      if (waited_pid < 0 && P_ERRNO != P_ERRNO_ECHILD)
      {
        u_perror("nice: s_waitpid failed");
      }
      // Check if stopped
      if (P_WIFSTOPPED(status))
      {
        spthread_disable_interrupts_self();
        char *reconstructed_target_cmd = reconstruct_command(target_argv);
        add_job(child_pid, NULL, JOB_STATUS_STOPPED); // Add as stopped
        Job *stopped_job = find_job_by_pid(child_pid);
        if (stopped_job)
        {
          free(stopped_job->command);
          stopped_job->command =
              reconstructed_target_cmd ? reconstructed_target_cmd : strdup("");
        }
        else if (reconstructed_target_cmd)
        {
          free(reconstructed_target_cmd);
        }
        spthread_enable_interrupts_self();
        char buf[MAX_MESSAGE_SIZE];
        snprintf(buf, sizeof(buf), "\n[%d]+ Stopped\t\t%s\n",
                 find_job_by_pid(child_pid)->job_id,
                 find_job_by_pid(child_pid)->command);
        s_write(STDOUT_FILENO, buf, strlen(buf));
      }
    }
    else
    {
      // Background process
      spthread_disable_interrupts_self();
      char *reconstructed_target_cmd = reconstruct_command(target_argv);
      add_job(child_pid, NULL,
              JOB_STATUS_RUNNING); // Add as running background job
      Job *bg_job = find_job_by_pid(child_pid);
      if (bg_job)
      {
        free(bg_job->command);
        bg_job->command =
            reconstructed_target_cmd ? reconstructed_target_cmd : strdup("");
      }
      else if (reconstructed_target_cmd)
      {
        free(reconstructed_target_cmd);
      }
      spthread_enable_interrupts_self();
      // Print job ID info
      char buf[MAX_MESSAGE_SIZE];
      snprintf(buf, sizeof(buf), "[%d] %d\n",
               find_job_by_pid(child_pid)->job_id, child_pid);
      s_write(STDOUT_FILENO, buf, strlen(buf));
    }
    return 0; // Built-in handled
  }
  else if (strcmp(command_name, "nice_pid") == 0)
  {
    if (argv[1] == NULL || argv[2] == NULL)
    {
      s_write(STDERR_FILENO, "nice_pid: requires priority and pid\n", 36);
      P_ERRNO = P_ERRNO_INVALID_ARG;
      return 0; // Handled (with error)
    }
    char *prio_str = argv[1];
    char *pid_str = argv[2];
    char *endptr;

    long prio_long = strtol(prio_str, &endptr, 10);
    if (prio_str == endptr || *endptr != '\0' || prio_long < 0 ||
        prio_long > 2)
    {
      s_write(STDERR_FILENO,
              "nice_pid: invalid priority (must be 0, 1, or 2)\n", 48);
      P_ERRNO = P_ERRNO_INVALID_ARG;
      return 0; // Handled (with error)
    }
    int priority = (int)prio_long;

    long pid_long = strtol(pid_str, &endptr, 10);
    if (pid_str == endptr || *endptr != '\0' || pid_long > INT_MAX ||
        pid_long < 0)
    { // PID >= 0
      s_write(STDERR_FILENO, "nice_pid: invalid pid\n", 22);
      P_ERRNO = P_ERRNO_INVALID_ARG;
      return 0; // Handled (with error)
    }
    pid_t pid = (pid_t)pid_long;

    if (s_nice(pid, priority) != 0)
    {
      u_perror("nice_pid"); // s_nice sets P_ERRNO
    }
    return 0; // Built-in handled
  }
  else if (strcmp(command_name, "man") == 0)
  {
    // (Copy the man page text printing logic from u_man here)
    const char *command_names[] = {
        "cat", "sleep", "busy", "echo", "ls", "touch",
        "mv", "cp", "rm", "chmod", "ps", "kill",
        "nice", "nice_pid", "man", "bg", "fg", "jobs",
        "logout", "zombify", "orphanify", NULL};

    const char *command_descriptions[] = {
        "Displays content of files or combines multiple files. With no "
        "arguments, reads from standard input.\n  Usage: cat [file1 file2...] "
        "or "
        "cat < input_file",
        "Pauses execution for the specified number of clock ticks.\n  Usage: "
        "sleep <ticks>",
        "Enters an infinite loop until interrupted by a signal. Useful for "
        "testing process control.\n  Usage: busy",
        "Outputs the provided text arguments to standard output.\n  Usage: "
        "echo "
        "[text...]",
        "Shows all files in the current directory.\n  Usage: ls",
        "Creates new empty files or updates timestamps of existing ones.\n  "
        "Usage: touch file1 [file2...]",
        "Renames or relocates a file. Will overwrite destination if it "
        "exists.\n "
        " Usage: mv <source> <destination>",
        "Duplicates a file to a new location. Will overwrite destination if it "
        "exists.\n "
        " Usage: cp <source> <destination>",
        "Deletes one or more files from the filesystem.\n  Usage: rm file1 "
        "[file2...]",
        "Modifies file permissions by adding (+) or removing (-) read (r), "
        "write "
        "(w), or execute (x) rights.\n  Usage: chmod +rw file or chmod -x file",
        "Lists all running processes with their PID, PPID, priority level, "
        "status, and name.\n  Usage: ps",
        "Sends signals to specified processes (PIDs). Use P_SIGTERM, "
        "P_SIGSTOP, P_SIGCONT.\n"
        "  Usage: kill <signal_num> <pid...>", // Updated usage
        "Spawns a command with a specified priority level (0-2).\n  Usage: "
        "nice <priority> <command> [args...]",
        "Adjusts the priority level (0-2) of an existing process.\n  Usage: "
        "nice_pid "
        "<priority> <pid>",
        "Displays help information for available commands.\n  Usage: man "
        "[command]", // Added optional command
        "Continues a stopped job in the background.\n  Usage: bg [%job_id]",
        "Brings a background or stopped job to the foreground.\n  Usage: fg "
        "[%job_id]",
        "Shows a list of all current jobs and their states.\n  Usage: jobs",
        "Exits the shell and shuts down PennOS.\n  Usage: logout",
        "Creates a zombie process for testing kernel zombie handling.\n  "
        "Usage: "
        "zombify",
        "Creates an orphaned process for testing kernel orphan handling.\n  "
        "Usage: orphanify"};

    if (argv[1] != NULL)
    {
      bool found = false;
      for (int i = 0; command_names[i] != NULL; ++i)
      {
        if (strcmp(argv[1], command_names[i]) == 0)
        {
          char cmd_header[100];
          snprintf(cmd_header, sizeof(cmd_header), "• %s:\n", command_names[i]);
          s_write(STDOUT_FILENO, cmd_header, strlen(cmd_header));
          s_write(STDOUT_FILENO, "  ", 2);
          s_write(STDOUT_FILENO, command_descriptions[i],
                  strlen(command_descriptions[i]));
          s_write(STDOUT_FILENO, "\n\n", 2);
          found = true;
          break;
        }
      }
      if (!found)
      {
        char err_buf[100];
        snprintf(err_buf, sizeof(err_buf), "man: no manual entry for %s\n",
                 argv[1]);
        s_write(STDERR_FILENO, err_buf, strlen(err_buf));
      }
    }
    else
    {
      // Print all commands
      s_write(STDOUT_FILENO, "PennOS Command Reference:\n", 26);
      s_write(STDOUT_FILENO, "=======================\n\n", 24);
      int i = 0;
      while (command_names[i] != NULL)
      {
        char cmd_header[100];
        snprintf(cmd_header, sizeof(cmd_header), "• %s:\n", command_names[i]);
        s_write(STDOUT_FILENO, cmd_header, strlen(cmd_header));
        s_write(STDOUT_FILENO, "  ", 2);
        s_write(STDOUT_FILENO, command_descriptions[i],
                strlen(command_descriptions[i]));
        s_write(STDOUT_FILENO, "\n\n", 2);
        i++;
      }
    }
    P_ERRNO = P_ERRNO_SUCCESS;
    return 0; // Built-in handled
  }
  else if (strcmp(command_name, "logout") == 0)
  {
    s_write(STDOUT_FILENO, "logout\n", 7);
    exit(EXIT_SUCCESS);
  }
  else if (strcmp(command_name, "chmod") == 0)
  {
    if (argv[1] == NULL || argv[2] == NULL)
    {
      s_write(STDERR_FILENO, "chmod: missing operand\n", 23);
      P_ERRNO = P_ERRNO_INVALID_ARG;
      return 0; // Handled (with error)
    }
    char *mode_str = argv[1];
    char *file_name = argv[2];

    if (s_chmod(file_name, mode_str) < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "chmod: cannot change mode of '%s'",
               file_name);
      u_perror(err_msg);
    }
    return 0;
  }

  return -1;
}

int execute_script_command(const char *command, int input_fd, int output_fd) {
  struct parsed_command *cmd;
  int parse_result = parse_command(command, &cmd);

  if (parse_result != 0) {
    char err_buf[256];
    snprintf(err_buf, sizeof(err_buf), "script: parse error: %s\n", command);
    s_write(STDERR_FILENO, err_buf, strlen(err_buf));
    return -1;
  }

  if (cmd->num_commands == 1 && cmd->commands[0] &&
      strcmp(cmd->commands[0][0], "echo") == 0) {
    char output[MAX_MESSAGE_SIZE] = "";
    for (int i = 1; cmd->commands[0][i] != NULL; i++) {
      if (i > 1) strcat(output, " ");
      strcat(output, cmd->commands[0][i]);
    }
    strcat(output, "\n");

    s_write(output_fd, output, strlen(output));
    free(cmd);
    return 0;
  }

  if (input_fd != STDIN_FILENO && !cmd->stdin_file) {
  }
  if (output_fd != STDOUT_FILENO && !cmd->stdout_file) {
  }

  int result = execute_single_command(cmd, 0, input_fd, output_fd, command);

  free(cmd);
  return result;
}

int execute_script_file(const char *script_path, int inherit_fd0,
                        int inherit_fd1, const char *output_file) {
  int script_fd = s_open(script_path, F_READ);
  if (script_fd < 0) {
    char err_buf[256];
    snprintf(err_buf, sizeof(err_buf), "shell: cannot open script '%s'",
            script_path);
    u_perror(err_buf);
    return -1;
  }

  int output_fd = inherit_fd1;
  bool close_output = false;

  if (output_file) {
    s_unlink(output_file);

    output_fd = s_open(output_file, F_WRITE);
    if (output_fd < 0) {
      char err_buf[256];
      snprintf(err_buf, sizeof(err_buf), "shell: cannot open output file '%s'",
              output_file);
      u_perror(err_buf);
      s_close(script_fd);
      return -1;
    }
    close_output = true;
  }

  char *line_buffer = NULL;
  size_t buffer_size = 0;
  size_t line_len = 0;
  int final_status = 0;

  int line_read_status;
  
  while ((line_read_status = read_line_from_fd(script_fd, &line_buffer,
                                             &buffer_size, &line_len)) > 0) {
    char *line = line_buffer;
    char *line_end = strchr(line, '\n');

    while (line_end) {
      *line_end = '\0';

      if (*line && *line != '#') {
        execute_script_command(line, inherit_fd0, output_fd);
      }

      line = line_end + 1;
      line_end = strchr(line, '\n');
    }

    if (*line && *line != '#') {
      execute_script_command(line, inherit_fd0, output_fd);
    }

    line_len = 0;
  }

    s_close(script_fd);
    if (close_output) {
      s_close(output_fd);
    }
    free(line_buffer);

    return final_status;
  }

pid_t execute_single_command(struct parsed_command *cmd,
                             int cmd_index,
                             int input_fd,
                             int output_fd,
                             const char *full_command_line)
{
  if (!cmd || cmd_index >= cmd->num_commands || !cmd->commands[cmd_index] ||
      !cmd->commands[cmd_index][0])
  {
    P_ERRNO = P_ERRNO_INVALID_ARG;
    return -1;
  }

  char *cmd_name = cmd->commands[cmd_index][0];
  void *(*func_ptr)(void *) = NULL;

  // Map command name string to function pointer (ONLY SPAWNABLE built-ins)
  if (strcmp(cmd_name, "cat") == 0)
    func_ptr = u_cat;
  else if (strcmp(cmd_name, "sleep") == 0)
    func_ptr = u_sleep;
  else if (strcmp(cmd_name, "busy") == 0)
    func_ptr = u_busy;
  else if (strcmp(cmd_name, "echo") == 0)
    func_ptr = u_echo;
  else if (strcmp(cmd_name, "ls") == 0)
    func_ptr = u_ls;
  else if (strcmp(cmd_name, "touch") == 0)
    func_ptr = u_touch;
  else if (strcmp(cmd_name, "mv") == 0)
    func_ptr = u_mv;
  else if (strcmp(cmd_name, "cp") == 0)
    func_ptr = u_cp;
  else if (strcmp(cmd_name, "rm") == 0)
    func_ptr = u_rm;
  else if (strcmp(cmd_name, "ps") == 0)
    func_ptr = u_ps;
  else if (strcmp(cmd_name, "zombify") == 0)
    func_ptr = u_zombify;
  else if (strcmp(cmd_name, "orphanify") == 0)
    func_ptr = u_orphanify;
  else if (strcmp(cmd_name, "hang") == 0)
    func_ptr = u_hang;
  else if (strcmp(cmd_name, "nohang") == 0)
    func_ptr = u_nohang;
  else if (strcmp(cmd_name, "recur") == 0)
    func_ptr = u_recur;
  else if (strcmp(cmd_name, "u_crash") == 0)
  {
    func_ptr = u_crash;
  }
  else if (strcmp(cmd_name, "kill") == 0)
    func_ptr = u_kill;
  else if (strcmp(cmd_name, "chmod") == 0)
    func_ptr = u_chmod;
  // else if (strcmp(cmd_name, "nice") == 0)
  //   u_nice(cmd->commands[cmd_index]);
  // else if (strcmp(cmd_name, "nice_pid") == 0)
  //   u_nice_pid(cmd->commands[cmd_index]);
  // else if (strcmp(cmd_name, "man") == 0)
  //   u_man(cmd->commands[cmd_index]);
  // else if (strcmp(cmd_name, "bg") == 0)
  //   u_bg(cmd->commands[cmd_index]);
  // else if (strcmp(cmd_name, "fg") == 0)
  //   u_fg(cmd->commands[cmd_index]);
  // else if (strcmp(cmd_name, "jobs") == 0)
  //   u_jobs(cmd->commands[cmd_index]);
  // else if (strcmp(cmd_name, "logout") == 0)
  //   u_logout(cmd->commands[cmd_index]);

  if (func_ptr)
  {
    // It's a spawnable built-in
    bool is_foreground = !cmd->is_background; // Spawn foreground unless &
    pid_t child_pid = s_spawn(func_ptr, cmd->commands[cmd_index], input_fd,
                              output_fd, is_foreground);

    if (child_pid == -1)
    {
      char err_buf[256];
      snprintf(err_buf, sizeof(err_buf), "shell: failed to spawn builtin '%s'",
               cmd_name);
      u_perror(err_buf);
      return -1; // Spawn error
    }

    // If it's a background job, add it to the job list
    if (!is_foreground)
    {
      spthread_disable_interrupts_self();
      add_job(child_pid, cmd, JOB_STATUS_RUNNING); // Pass the parsed command
      spthread_enable_interrupts_self();
    }

    return child_pid; // Return PID of spawned process
  }
  else
  {
    int perm = s_get_permission(cmd_name);
    bool is_executable_script = false;

    if (perm >= 0)
    { // File exists
      if (perm & 1)
      { // Execute permission
        is_executable_script = true;
      }
      else
      {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "shell: %s: Permission denied\n",
                 cmd_name);
        s_write(STDERR_FILENO, err_msg, strlen(err_msg));
        P_ERRNO = P_ERRNO_PERMISSION;
        return -1;
      }
    }
    else if (P_ERRNO !=
             P_ERRNO_FILE_NOT_FOUND)
    { // Error other than not found
      char err_buf[256];
      snprintf(err_buf, sizeof(err_buf),
               "shell: error checking permissions for '%s'", cmd_name);
      u_perror(err_buf);
      return -1;
    }

    if (is_executable_script)
    {
      const char *output_file = cmd->stdout_file;
    
      int script_result = execute_script_file(cmd_name, input_fd, output_fd, output_file);
      return (script_result == 0) ? 0 : -1;
    }
    else
    {
      // Command not found
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "%s: command not found\n", cmd_name);
      s_write(STDERR_FILENO, err_msg, strlen(err_msg));
      P_ERRNO = P_ERRNO_FILE_NOT_FOUND;
      return -1; // Return -1 for command not found
    }
  }
}

int execute_command(struct parsed_command *cmd)
{
  if (!cmd || cmd->num_commands == 0 || !cmd->commands[0] ||
      !cmd->commands[0][0])
  {
    P_ERRNO = P_ERRNO_INVALID_ARG;
    return -1;
  }

  initialize_job_control();

  // check for built in sub
  int builtin_result = handle_shell_builtin(cmd);
  if (builtin_result == 0)
  {
    return 0; // Built-in handled successfully
  }
  else if (builtin_result == -2)
  {
    return 0;
  }
  if (cmd->num_commands > 1)
  {
    char *msg = "Piping is not implemented in this version.\n";
    s_write(STDERR_FILENO, msg, strlen(msg));
    P_ERRNO = P_ERRNO_INVALID_OPERATION;
    return -1;
  }

  int top_level_input_fd = STDIN_FILENO;
  int top_level_output_fd = STDOUT_FILENO;
  int top_level_open_flags = 0; // Bit 0: input opened, Bit 1: output opened

  if (cmd->stdin_file)
  {
    top_level_input_fd = s_open(cmd->stdin_file, F_READ);
    if (top_level_input_fd < 0)
    {
      char err_buf[256];
      snprintf(err_buf, sizeof(err_buf), "shell: cannot open input file '%s'",
               cmd->stdin_file);
      u_perror(err_buf);
      return -1; // Error opening input redirection
    }
    top_level_open_flags |= 1;
  }

  if (cmd->stdout_file) {
  int mode = cmd->is_file_append ? F_APPEND : F_WRITE;
  top_level_output_fd = s_open(cmd->stdout_file, mode);
  if (top_level_output_fd < 0) {
    char err_buf[256];
    snprintf(err_buf, sizeof(err_buf), "shell: cannot open output file '%s'",
             cmd->stdout_file);
    u_perror(err_buf);
    if (top_level_open_flags & 1) s_close(top_level_input_fd);
    return -1;
  }
  top_level_open_flags |= 2;
}

  char *full_cmd_line =
      reconstruct_command(cmd->commands[0]); // Use first command part

  pid_t child_pid = execute_single_command(cmd, 0, top_level_input_fd,
                                           top_level_output_fd, full_cmd_line);

  // --- Wait for Foreground Process ---
  if (!cmd->is_background && child_pid > 0)
  {
    int status;
    // Give terminal control to foreground child
    if (s_set_terminal_owner(child_pid) != 0)
    { // Check return value
      u_perror("shell: failed to set terminal owner for child");
    }
    else
    {
      terminal_controller_pid = child_pid;
    }
    pid_t waited_pid = s_waitpid(child_pid, &status, 0); // Blocking wait

    // Only reclaim terminal control if we're in the main shell process
    if (s_getpid() == shell_pid)
    {
      if (s_set_terminal_owner(shell_pid) != 0)
      { // Check return value
        // This is a more serious problem, shell might lose input capability
        u_perror("shell: CRITICAL: failed to reclaim terminal owner");
        // Consider exiting or trying again?
      }
      else
      {
        terminal_controller_pid = shell_pid;
      }
    }

    if (waited_pid < 0)
    {
      if (P_ERRNO != P_ERRNO_ECHILD && P_ERRNO != P_ERRNO_ESRCH &&
          P_ERRNO != P_ERRNO_SUCCESS)
      { // Ignore "no child" error
        u_perror("shell: waitpid failed");
      }
    }
    else
    {
      // Check if the foreground process was stopped
      if (P_WIFSTOPPED(status))
      {
        spthread_disable_interrupts_self();
        char *recon_cmd = reconstruct_command(cmd->commands[0]);
        add_job(child_pid, NULL, JOB_STATUS_STOPPED); // Add as stopped
        Job *stopped_job = find_job_by_pid(child_pid);
        if (stopped_job)
        {
          free(stopped_job->command); // Free default "" if any
          stopped_job->command =
              recon_cmd ? recon_cmd : strdup(""); // Assign the actual command
        }
        else if (recon_cmd)
        {
          free(recon_cmd); // Free if not used
        }

        spthread_enable_interrupts_self();
        // Print stopped message
        char buf[MAX_MESSAGE_SIZE];
        Job *job_info = find_job_by_pid(child_pid); // Find again to get job ID
        if (job_info)
        {
          snprintf(buf, sizeof(buf), "\n[%d]+ Stopped\t\t%s\n",
                   job_info->job_id, job_info->command);
          s_write(STDOUT_FILENO, buf, strlen(buf));
        }
        else
        {
          // Fallback message if job somehow not found immediately
          snprintf(buf, sizeof(buf), "\n[?]+ Stopped\t\tPID %d\n", child_pid);
          s_write(STDOUT_FILENO, buf, strlen(buf));
        }
      }
    }
  }

  free(full_cmd_line);

  if (top_level_open_flags & 1)
  { // Input was opened
    if (s_close(top_level_input_fd) == -1)
    {
      u_perror("shell: warning: failed to close input redirection fd");
    }
  }
  if (top_level_open_flags & 2)
  { // Output was opened
    if (s_close(top_level_output_fd) == -1)
    {
      u_perror("shell: warning: failed to close output redirection fd");
    }
  }

  return child_pid;
}
