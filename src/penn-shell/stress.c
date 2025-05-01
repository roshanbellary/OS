/******************************************************************************
 *                                                                            *
 *                             Author(s): Travis McGaha & Hannah Pan          *
 *                             Date(s):   04/17/20205 & 04/15/2021            *
 *                                                                            *
 ******************************************************************************/

#include "stress.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h> // for malloc
#include <string.h> // for memcpy and strlen
#include <stdio.h>  // just for snprintf
#include <signal.h> // for kill(SIGKILL) to mimic crashing for one of the tests
#include <time.h>   // for time()
#include "../kernel/calls/sys-call.h"
#include "../kernel/p_errno.h"
#include "../fat/fat_kernel.h"

// You can tweak the function signature to make it work.
static void *nap(void *arg)
{
  s_sleep(10); // sleep for 10 ticks for visibility
  s_register_end();
  return NULL;
}

/*
 * The function below spawns 10 nappers named child_0 through child_9 and waits
 * on them. The wait is non-blocking if nohang is true, or blocking otherwise.
 */
static void *spawn(bool nohang)
{
  char name[] = "child_0";
  char *argv[2];
  argv[0] = name;
  argv[1] = NULL;
  int pid = 0;

  // Spawn 10 nappers named child_0 through child_9.
  for (int i = 0; i < 10; i++)
  {
    argv[0][sizeof name - 2] = '0' + i;

    // Use the implementation's s_spawn
    const int id = s_spawn(nap, argv, STDIN_FILENO, STDOUT_FILENO, 1);

    if (i == 0)
      pid = id;

    char msg[64];
    sprintf(msg, "%s was spawned\n", argv[0]);
    s_write(STDERR_FILENO, msg, strlen(msg));
  }

  // Wait on all children.
  while (1)
  {
    const int cpid = s_waitpid(-1, NULL, nohang);

    if (cpid < 0)
    {
      // no more waitable children (if block-waiting) or error
      break;
    }

    // polling if nonblocking wait and no waitable children yet
    if (nohang && cpid == 0)
    {
      s_sleep(9); // 9 ticks
      continue;
    }

    char msg[64];
    sprintf(msg, "child_%d was reaped\n", cpid - pid);
    s_write(STDERR_FILENO, msg, strlen(msg));
  }

  s_register_end();
  return NULL;
}

/*
 * The function below recursively spawns itself 26 times and names the spawned
 * processes Gen_A through Gen_Z. Each process is block-waited by its parent.
 */
static void *spawn_r(void *arg)
{
  static int i = 0;

  int pid = 0;
  char name[] = "Gen_A";
  char *argv[2];
  argv[0] = name;
  argv[1] = NULL;

  if (i < 26)
  {
    argv[0][sizeof name - 2] = 'A' + i++;

    pid = s_spawn(spawn_r, argv, STDIN_FILENO, STDOUT_FILENO, 1);

    char msg[64];
    sprintf(msg, "%s was spawned\n", argv[0]);
    s_write(STDERR_FILENO, msg, strlen(msg));

    s_sleep(1); // 1 tick
  }

  if (pid > 0 && pid == s_waitpid(pid, NULL, 0))
  {
    char msg[64];
    sprintf(msg, "%s was reaped\n", argv[0]);
    s_write(STDERR_FILENO, msg, strlen(msg));
  }

  s_register_end();
  return NULL;
}

static char *gen_pattern_str()
{
  size_t len = 5480;

  char pattern[9];
  pattern[8] = '\0';

  srand(time(NULL));

  for (size_t i = 0; i < 8; i++)
  {
    // random ascii printable character
    pattern[i] = (char)((rand() % 95) + 32);
  }

  char *str = malloc((len + 1) * sizeof(char));

  str[5480] = '\0';

  for (size_t i = 0; i < 5480; i += 8)
  {
    memcpy(&(str[i]), pattern, 8 * sizeof(char));
  }

  return str;
}

static void crash_main()
{
  const char *fname = "CRASHING.txt";
  s_unlink(fname);

  int fd = s_open(fname, F_WRITE);
  if (fd < 0)
  {
    u_perror("crash: Could not open CRASHING.txt");
    s_register_end();
    return;
  }

  char *str = gen_pattern_str();

  const char *msg = "writing a string that consists of the following pattern 685 times to CRASHING.txt: ";
  s_write(STDERR_FILENO, msg, strlen(msg));
  s_write(STDERR_FILENO, str, 8);
  s_write(STDERR_FILENO, "\n", 1);

  // write the str to the file
  s_write(fd, str, 5480);
  s_close(fd);

  msg = "crashing pennos. Our write should be safe in the file system.\n";
  s_write(STDERR_FILENO, msg, strlen(msg));

  msg = "We should see this file and this message in a hexdump of the fs\n";
  s_write(STDERR_FILENO, msg, strlen(msg));

  // The original killed with SIGKILL, replace this with a faster way to crash
  // Just exit the entire process by calling exit(1)
  exit(1);

  msg = "ERROR: PENNOS WAS SUPPOSED TO CRASH\n";
  s_write(STDERR_FILENO, msg, strlen(msg));
}

// Public interface functions
void *u_hang(void *arg)
{
  spawn(false);
  s_register_end();
  return NULL;
}

void *u_nohang(void *arg)
{
  spawn(true);
  s_register_end();
  return NULL;
}

void *u_recur(void *arg)
{
  spawn_r(NULL);
  s_register_end();
  return NULL;
}

void *u_crash(void *arg)
{
  // This one only works on a file system big enough to hold 5480 bytes
  crash_main();
  // This shouldn't be reached if crash_main works correctly
  s_register_end();
  return NULL;
}