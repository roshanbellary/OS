#include "user-call.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../util/types/signals.h"
#include "fat_kernel.h"
#include "sys-call.h"
#include "../util/types/signals.h"

void *u_cat(void *arg)
{
  if (arg == NULL)
  {
    char buffer[4096];
    int bytes_read;

    while ((bytes_read = s_read(STDIN_FILENO, buffer, sizeof(buffer))) > 0)
    {
      if (s_write(STDOUT_FILENO, buffer, bytes_read) < 0)
      {
        u_perror("cat: write error");
        break;
      }
    }

    if (bytes_read < 0)
    {
      u_perror("cat: read error");
    }

    s_register_end();
    return NULL;
  }

  char **args = (char **)arg;

  if (args[1] == NULL)
  {
    char buffer[4096];
    int bytes_read;

    while ((bytes_read = s_read(STDIN_FILENO, buffer, sizeof(buffer))) > 0)
    {
      if (s_write(STDOUT_FILENO, buffer, bytes_read) < 0)
      {
        u_perror("cat: write error");
        break;
      }
    }

    if (bytes_read < 0)
    {
      u_perror("cat: read error");
    }

    s_register_end();
    return NULL;
  }

  int i = 1;
  char *output_file = NULL;
  bool append_mode = false;

  while (args[i] != NULL)
  {
    if (strcmp(args[i], "-w") == 0 || strcmp(args[i], "-a") == 0)
    {
      append_mode = (strcmp(args[i], "-a") == 0);

      if (args[i + 1] == NULL)
      {
        s_write(STDERR_FILENO, "cat: missing output file after option\n", 37);
        s_register_end();
        return NULL;
      }

      output_file = args[i + 1];
      break;
    }
    i++;
  }

  bool reading_from_files = (args[1] != NULL && (strcmp(args[1], "-w") != 0) &&
                             (strcmp(args[1], "-a") != 0));

  int output_fd = STDOUT_FILENO;
  if (output_file != NULL)
  {
    output_fd = s_open(output_file, append_mode ? F_APPEND : F_WRITE);
    if (output_fd < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cat: cannot open '%s' for writing",
               output_file);
      u_perror(err_msg);
      s_register_end();
      return NULL;
    }
  }

  if (!reading_from_files)
  {
    char buffer[4096];
    int bytes_read;

    while ((bytes_read = s_read(STDIN_FILENO, buffer, sizeof(buffer))) > 0)
    {
      if (s_write(output_fd, buffer, bytes_read) < 0)
      {
        u_perror("cat: write error");
        break;
      }
    }

    if (bytes_read < 0)
    {
      u_perror("cat: read error");
    }

    if (output_fd != STDOUT_FILENO)
    {
      s_close(output_fd);
    }

    s_register_end();
    return NULL;
  }

  i = 1;
  while (args[i] != NULL && strcmp(args[i], "-w") != 0 &&
         strcmp(args[i], "-a") != 0)
  {
    int input_fd = s_open(args[i], F_READ);
    if (input_fd < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cat: cannot open '%s' for reading",
               args[i]);
      u_perror(err_msg);
      i++;
      continue;
    }

    char buffer[4096];
    int bytes_read;

    while ((bytes_read = s_read(input_fd, buffer, sizeof(buffer))) > 0)
    {
      if (s_write(output_fd, buffer, bytes_read) < 0)
      {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "cat: write error");
        u_perror(err_msg);
        break;
      }
    }

    if (bytes_read < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cat: read error from '%s'", args[i]);
      u_perror(err_msg);
    }

    s_close(input_fd);
    i++;
  }

  if (output_fd != STDOUT_FILENO)
  {
    s_close(output_fd);
  }

  s_register_end();
  return NULL;
}

void *u_ps(void *arg)
{
  char *headers[5] = {"PID", "PPID", "PRI", "STAT", "CMD"};
  for (int i = 0; i < 5; i++)
  {
    if (s_write(STDOUT_FILENO, headers[i], strlen(headers[i])) == -1)
      u_perror("ps: write");
    if (i < 5)
    {
      if (s_write(STDOUT_FILENO, " ", 2) == -1)
        u_perror("ps: write");
    }
  }
  if (s_write(STDOUT_FILENO, "\n", 2) == -1)
    u_perror("ps: write");
  s_ps();
  s_register_end();
  return NULL;
}

void *u_kill(void *arg)
{
  char **argv = (char **)arg;
  int signal_to_send = P_SIGTERM;
  int pid_start_index = 1;

  if (argv == NULL || argv[1] == NULL)
  {
    s_write(STDERR_FILENO, "kill: usage: kill [-signal] pid ...\n", 36);
    s_register_end();
    return NULL;
  }

  if (strncmp(argv[1], "-", 1) == 0 && strlen(argv[1]) > 1)
  {
    if (strcmp(argv[1], "-term") == 0)
    {
      signal_to_send = P_SIGTERM;
    }
    else if (strcmp(argv[1], "-stop") == 0)
    {
      signal_to_send = P_SIGSTOP;
    }
    else if (strcmp(argv[1], "-cont") == 0)
    {
      signal_to_send = P_SIGCONT;
    }
    else
    {
      char err_msg[100];
      snprintf(err_msg, sizeof(err_msg), "kill: invalid signal specifier: %s\nValid signals: -term, -stop, -cont\n", argv[1]);
      s_write(STDERR_FILENO, err_msg, strlen(err_msg));
      s_register_end();
      return NULL;
    }
    pid_start_index = 2;
  }

  if (argv[pid_start_index] == NULL)
  {
    s_write(STDERR_FILENO, "kill: missing process ID\n", 25);
    s_write(STDERR_FILENO, "kill: usage: kill [-signal] pid ...\n", 36);
    s_register_end();
    return NULL;
  }

  for (int i = pid_start_index; argv[i] != NULL; ++i)
  {
    char *endptr;
    long pid_long = strtol(argv[i], &endptr, 10);

    if (endptr == argv[i] || *endptr != '\0' || pid_long <= 0)
    {
      char err_msg[100];
      snprintf(err_msg, sizeof(err_msg), "kill: invalid pid specified: '%s'\n", argv[i]);
      s_write(STDERR_FILENO, err_msg, strlen(err_msg));
      continue;
    }

    pid_t pid = (pid_t)pid_long;

    if (s_kill(pid, signal_to_send) == -1)
    {
      char err_prefix[100];
      snprintf(err_prefix, sizeof(err_prefix), "kill (pid %d)", pid);
      u_perror(err_prefix);
    }
  }

  s_register_end();
  return NULL;
}

void *u_zombify(void *arg)
{
  char *msg = malloc(MAX_MESSAGE_SIZE + 1);
  strcpy(msg, "zombie_child");
  msg[13] = '\0';
  char **args = malloc(sizeof(char *) * 2);
  args[0] = msg;
  args[1] = NULL;
  int pid = s_spawn(zombie_child, args, STDIN_FILENO, STDOUT_FILENO, 1);
  if (pid < 0)
  {
    u_perror("zombify: spawn");
    return NULL;
  }
  while (1)
    ;
  s_register_end();
  return NULL;
}

void *zombie_child(void *arg)
{
  printf("I'm a zombie arghhhh\n");
  s_register_end();
  return NULL;
}

void *u_nice(void *arg)
{
  if (arg == NULL)
  {
    return NULL;
  }
  int *inputs = (int *)arg;
  int *pid = &inputs[0];
  int *new_prio = &inputs[1];
  if (s_nice(*pid, *new_prio) == -1)
    u_perror("nice");
  return NULL;
}

/**
 *
 * @brief Adjust the priority level of an existing process.
 * @param prio The new priority level (0, 1, or 2).
 * @param pid The PID of the target process.
 */

void *u_nice_pid(void *arg)
{
  char **args = (char **)arg;
  if (args == NULL || args[1] == NULL || args[2] == NULL)
  {
    u_perror("nice_pid: missing arguments");
    return NULL;
  }
  int prio = stoi(args[1]);
  int pid = stoi(args[2]);
  s_nice_pid(prio, pid);
  return NULL;
}

void *u_orphanify(void *arg)
{
  char *msg = malloc(MAX_MESSAGE_SIZE + 1);
  strcpy(msg, "orphan_child");
  msg[14] = '\0';
  char **args = malloc(sizeof(char *) * 2);
  args[0] = msg;
  args[1] = NULL;
  int pid = s_spawn(u_orphan_child, args, STDIN_FILENO, STDOUT_FILENO, 1);
  if (pid < 0)
  {
    return NULL;
  }
  s_register_end();
  return NULL;
}

void *u_orphan_child(void *arg)
{
  printf("I'm an orphan :(\n");
  sleep(1);
  s_register_end();
  return NULL;
}

int stoi(char *str)
{
  int len = strlen(str);
  int n = 0;
  int pow = 1;
  for (int i = len - 1; i >= 0; i--)
  {
    n += (pow * (str[i] - '0'));
    pow *= 10;
  }
  return n;
}

void *u_sleep(void *arg)
{
  if (arg == NULL)
  {
    return NULL;
  }
  if (strlen(arg) <= 1)
  {
    return NULL;
  }
  char *input = ((char **)arg)[1];
  int ticks = stoi(input);
  if (ticks > 0)
  {
    s_sleep(ticks);
  }
  s_register_end();
  return NULL;
}

void *u_busy(void *arg)
{
  while (1)
  {
  }
  s_register_end();
  return NULL;
}

void *u_echo(void *arg)
{
  if (arg == NULL)
  {
    return NULL;
  }

  char **args = (char **)arg;
  int i = 1;
  while (args[i] != NULL)
  {
    if (s_write(STDOUT_FILENO, args[i], strlen(args[i])) == -1)
      u_perror("echo: write");
    if (args[i + 1] != NULL)
    {
      if (s_write(STDOUT_FILENO, " ", 1) == -1)
        u_perror("echo: write");
    }
    i++;
  }
  if (s_write(STDOUT_FILENO, "\n", 1) == -1)
    u_perror("echo: write");

  s_register_end();
  return NULL;
}

void *u_ls(void *arg)
{
  s_ls(NULL);
  s_register_end();
  return NULL;
}

void *u_touch(void *arg)
{
  if (arg == NULL)
  {
    return NULL;
  }

  char **args = (char **)arg;
  int i = 1;

  if (args[i] == NULL)
  {
    s_write(STDERR_FILENO, "touch: missing file operand\n", 28);
    s_register_end();
    return NULL;
  }

  while (args[i] != NULL)
  {
    int fd = s_open(args[i], F_WRITE);
    if (fd < 0)
    {
      char err_msg[256];
      sprintf(err_msg, "touch: cannot touch '%s': ", args[i]);
      u_perror(err_msg);
    }
    else
    {
      s_close(fd);
    }
    i++;
  }

  s_register_end();
  return NULL;
}

void *u_mv(void *arg)
{
  if (arg == NULL)
  {
    s_write(STDERR_FILENO, "mv: missing file operand\n", 25);
    s_register_end();
    return NULL;
  }

  char **args = (char **)arg;

  if (args[1] == NULL || args[2] == NULL)
  {
    s_write(STDERR_FILENO, "mv: missing file operand\n", 25);
    s_register_end();
    return NULL;
  }

  char *src_file = args[1];
  char *dst_file = args[2];

  int src_fd = s_open(src_file, F_READ);
  if (src_fd < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "mv: cannot access '%s'", src_file);
    u_perror(err_msg);
    s_register_end();
    return NULL;
  }

  s_close(src_fd);

  int dst_perm = s_get_permission(dst_file);

  if (dst_perm >= 0)
  {
    if (!(dst_perm & 2))
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg),
               "mv: cannot overwrite '%s': Permission denied", dst_file);
      u_perror(err_msg);
      s_register_end();
      return NULL;
    }

    if (s_unlink(dst_file) < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "mv: cannot remove destination '%s'",
               dst_file);
      u_perror(err_msg);
      s_register_end();
      return NULL;
    }
  }

  src_fd = s_open(src_file, F_READ);
  if (src_fd < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "mv: cannot reopen '%s'", src_file);
    u_perror(err_msg);
    s_register_end();
    return NULL;
  }

  int dst_fd = s_open(dst_file, F_WRITE);
  if (dst_fd < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "mv: cannot create '%s'", dst_file);
    u_perror(err_msg);
    s_close(src_fd);
    s_register_end();
    return NULL;
  }

  char buffer[4096];
  int bytes_read;

  while ((bytes_read = s_read(src_fd, buffer, sizeof(buffer))) > 0)
  {
    if (s_write(dst_fd, buffer, bytes_read) < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "mv: write error to '%s'", dst_file);
      u_perror(err_msg);
      s_close(src_fd);
      s_close(dst_fd);
      s_register_end();
      return NULL;
    }
  }

  if (bytes_read < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "mv: read error from '%s'", src_file);
    u_perror(err_msg);
    s_close(src_fd);
    s_close(dst_fd);
    s_register_end();
    return NULL;
  }

  s_close(src_fd);
  s_close(dst_fd);

  if (s_unlink(src_file) < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "mv: cannot remove '%s'", src_file);
    u_perror(err_msg);
  }

  s_register_end();
  return NULL;
}

void *u_cp(void *arg)
{
  if (arg == NULL)
  {
    s_write(STDERR_FILENO, "cp: missing file operand\n", 25);
    s_register_end();
    return NULL;
  }

  char **args = (char **)arg;

  if (args[1] == NULL || args[2] == NULL)
  {
    s_write(STDERR_FILENO, "cp: missing file operand\n", 25);
    s_register_end();
    return NULL;
  }

  bool source_is_host = false;
  bool dest_is_host = false;
  char *src_file = args[1];
  char *dst_file = args[2];

  if (strcmp(args[1], "-h") == 0)
  {
    source_is_host = true;
    if (args[2] == NULL || args[3] == NULL)
    {
      s_write(STDERR_FILENO, "cp: missing file operand after -h\n", 33);
      s_register_end();
      return NULL;
    }
    src_file = args[2];
    dst_file = args[3];
  }
  else if (args[2] != NULL && args[3] != NULL && strcmp(args[2], "-h") == 0)
  {
    dest_is_host = true;
    dst_file = args[3];
  }

  if (source_is_host)
  {
    FILE *host_src = fopen(src_file, "rb");
    if (host_src == NULL)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cp: cannot open host file '%s'",
               src_file);
      perror(err_msg);
      s_register_end();
      return NULL;
    }

    int dst_fd = s_open(dst_file, F_WRITE);
    if (dst_fd < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cp: cannot create '%s'", dst_file);
      u_perror(err_msg);
      fclose(host_src);
      s_register_end();
      return NULL;
    }

    char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), host_src)) > 0)
    {
      if (s_write(dst_fd, buffer, bytes_read) < 0)
      {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "cp: write error to '%s'", dst_file);
        u_perror(err_msg);
        fclose(host_src);
        s_close(dst_fd);
        s_register_end();
        return NULL;
      }
    }

    fclose(host_src);
    s_close(dst_fd);
    s_register_end();
    return NULL;
  }

  if (dest_is_host)
  {
    int src_fd = s_open(src_file, F_READ);
    if (src_fd < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cp: cannot open '%s'", src_file);
      u_perror(err_msg);
      s_register_end();
      return NULL;
    }

    FILE *host_dst = fopen(dst_file, "wb");
    if (host_dst == NULL)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cp: cannot create host file '%s'",
               dst_file);
      perror(err_msg);
      s_close(src_fd);
      s_register_end();
      return NULL;
    }

    char buffer[4096];
    int bytes_read;
    while ((bytes_read = s_read(src_fd, buffer, sizeof(buffer))) > 0)
    {
      if (fwrite(buffer, 1, bytes_read, host_dst) != bytes_read)
      {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "cp: write error to host file '%s'",
                 dst_file);
        perror(err_msg);
        s_close(src_fd);
        fclose(host_dst);
        s_register_end();
        return NULL;
      }
    }

    if (bytes_read < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cp: read error from '%s'", src_file);
      u_perror(err_msg);
    }

    s_close(src_fd);
    fclose(host_dst);
    s_register_end();
    return NULL;
  }

  int src_fd = s_open(src_file, F_READ);
  if (src_fd < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "cp: cannot open '%s'", src_file);
    u_perror(err_msg);
    s_register_end();
    return NULL;
  }

  int dst_fd = s_open(dst_file, F_WRITE);
  if (dst_fd < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "cp: cannot create '%s'", dst_file);
    u_perror(err_msg);
    s_close(src_fd);
    s_register_end();
    return NULL;
  }

  char buffer[4096];
  int bytes_read;
  while ((bytes_read = s_read(src_fd, buffer, sizeof(buffer))) > 0)
  {
    if (s_write(dst_fd, buffer, bytes_read) < 0)
    {
      char err_msg[256];
      snprintf(err_msg, sizeof(err_msg), "cp: write error to '%s'", dst_file);
      u_perror(err_msg);
      s_close(src_fd);
      s_close(dst_fd);
      s_register_end();
      return NULL;
    }
  }

  if (bytes_read < 0)
  {
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "cp: read error from '%s'", src_file);
    u_perror(err_msg);
  }

  s_close(src_fd);
  s_close(dst_fd);
  s_register_end();
  return NULL;
}

void *u_rm(void *arg)
{
  if (arg == NULL)
  {
    return NULL;
  }

  char **args = (char **)arg;
  int i = 1;

  if (args[i] == NULL)
  {
    s_write(STDERR_FILENO, "rm: missing file operand\n", 25);
    s_register_end();
    return NULL;
  }

  while (args[i] != NULL)
  {
    if (s_unlink(args[i]) < 0)
    {
      char err_msg[256];
      sprintf(err_msg, "rm: cannot remove '%s': ", args[i]);
      u_perror(err_msg);
    }
    i++;
  }

  s_register_end();
  return NULL;
}

void *u_bg(void *arg)
{
  return NULL;
}

void *u_fg(void *arg)
{
  return NULL;
}

void *u_man(void *arg)
{
  const char *command_names[] = {
      "cat", "sleep", "busy", "echo", "ls", "touch", "mv",
      "cp", "rm", "chmod", "ps", "kill", "nice", "nice_pid",
      "man", "bg", "fg", "jobs", "logout", "zombify", "orphanify",
      "hang", "nohang", "recur", "crash", NULL};

  const char *command_descriptions[] = {
      "Displays content of files or combines multiple files. With no "
      "arguments, reads from standard input.\n  Usage: cat [file1 file2...] or "
      "cat < input_file",
      "Pauses execution for the specified number of clock ticks.\n  Usage: "
      "sleep <ticks>",
      "Enters an infinite loop until interrupted by a signal. Useful for "
      "testing process control.\n  Usage: busy",
      "Outputs the provided text arguments to standard output.\n  Usage: echo "
      "[text...]",
      "Shows all files in the current directory.\n  Usage: ls",
      "Creates new empty files or updates timestamps of existing ones.\n  "
      "Usage: touch file1 [file2...]",
      "Renames or relocates a file. Will overwrite destination if it exists.\n "
      " Usage: mv <source> <destination>",
      "Duplicates a file to a new location. Will overwrite destination if it "
      "exists.\n  Usage: cp <source> <destination>",
      "Deletes one or more files from the filesystem.\n  Usage: rm file1 "
      "[file2...]",
      "Modifies file permissions by adding (+) or removing (-) read (r), write "
      "(w), or execute (x) rights.\n  Usage: chmod +rw file or chmod -x file",
      "Lists all running processes with their PID, PPID, priority level, "
      "status, and name.\n  Usage: ps",
      "Sends signals to specified processes. Default is terminate (term).\n  "
      "Usage: kill [pid...] or kill -signal [pid...]",
      "Launches a program with a specified priority level (0-2).\n  Usage: "
      "nice <priority> <command> [args...]",
      "Adjusts the priority level of an existing process.\n  Usage: nice_pid "
      "<priority> <pid>",
      "Displays help information for available commands.\n  Usage: man",
      "Continues a stopped job in the background.\n  Usage: bg [job_id]",
      "Brings a background or stopped job to the foreground.\n  Usage: fg "
      "[job_id]",
      "Shows a list of all current jobs and their states.\n  Usage: jobs",
      "Exits the shell and shuts down PennOS.\n  Usage: logout",
      "Creates a zombie process for testing kernel zombie handling.\n  Usage: "
      "zombify",
      "Creates an orphaned process for testing kernel orphan handling.\n  "
      "Usage: orphanify",
      "Spawns 10 child processes and waits on them in blocking mode. Tests "
      "scheduler and wait functionality.\n  Usage: hang",
      "Spawns 10 child processes and waits on them in non-blocking mode. Tests "
      "scheduler with non-blocking waits.\n  Usage: nohang",
      "Recursively spawns 26 processes named Gen_A through Gen_Z. Tests deep "
      "process hierarchies.\n  Usage: recur",
      "Writes a large pattern to a file and then crashes PennOS. Tests "
      "filesystem durability.\n  Usage: crash",
  };

  s_write(STDOUT_FILENO, "PennOS Command Reference:\n", 26);
  s_write(STDOUT_FILENO, "=======================\n\n", 24);

  int i = 0;
  while (command_names[i] != NULL)
  {
    char cmd_header[100];
    sprintf(cmd_header, "• %s:\n", command_names[i]);
    s_write(STDOUT_FILENO, cmd_header, strlen(cmd_header));

    s_write(STDOUT_FILENO, "  ", 2);
    s_write(STDOUT_FILENO, command_descriptions[i],
            strlen(command_descriptions[i]));
    s_write(STDOUT_FILENO, "\n\n", 2);

    i++;
  }

  return NULL;
}

void *u_jobs(void *arg)
{
  return NULL;
}

void *u_logout(void *arg)
{
  s_exit();
  const char *err_msg = "Error: s_exit failed to terminate shell.\n";
  s_write(STDERR_FILENO, err_msg, strlen(err_msg));
  return NULL;
}

void *u_chmod(void *arg)
{
  if (arg == NULL)
  {
    // Handle error: maybe print usage or set P_ERRNO?
    s_register_end();
    return NULL;
  }

  char **args = (char **)arg;

  if (args[1] == NULL || args[2] == NULL)
  {
    // Using s_write for direct error message as it's a user program
    s_write(STDERR_FILENO, "chmod: missing operand\n", 23);
    s_register_end();
    return NULL;
  }

  char *mode_str = args[1];
  char *file_name = args[2];

  // Call the system call
  if (s_chmod(file_name, mode_str) < 0)
  {
    // s_chmod sets P_ERRNO, so u_perror will work
    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "chmod: cannot change mode of '%s'",
             file_name);
    u_perror(err_msg); // Report error using u_perror
  }

  s_register_end();
  return NULL;
}