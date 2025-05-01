#include <stdio.h>
#include <string.h>
#include "../fat/fat_core.h"
#include "../kernel/calls/sys-call.h"
#include "../kernel/kernel.h"
#include "../penn-shell/penn-shell.h"
#include "../util/Vec.h"
#include "../util/logger/logger.h"
void* torta(void* args) {
  pid_t v = s_spawn(shell, NULL, STDIN_FILENO, STDOUT_FILENO, 1);
  printf("init: spawned shell process with pid %d\n", v);
  // llog("init: spawned shell process with pid %d\n", p);
  while (1) {
    int status;
    s_waitpid(-1, &status, 0);
  }
  return NULL;
}
int main(int argc, char* argv[]) {
  // Filesystem mounting logic
  if (argc >= 3 && strcmp(argv[1], "fatfs") == 0) {
    char* fs_filename = argv[2];
    if (fs_mount(fs_filename) != 0) {
      fprintf(stderr,
              "[PennOS] ERROR: Failed to mount FAT filesystem '%s'. Exiting.\n",
              fs_filename);
      return 1;
    }
  } else {
    fprintf(stderr, "[PennOS] Usage: %s fatfs <filesystem_file> [log_fname]\n",
            argv[0]);
    return 1;
  }

  kernel_set_up();
  pcb_t* init_process = malloc(sizeof(pcb_t));
  init_process->pid = 1;
  init_process->ppid = 0;
  init_process->priority_level = 0;

  // Change these later to true defaults
  init_process->term_signal = 0;
  init_process->stop_signal = 0;

  init_process->file_descriptors = deque_new(free);

  init_process->status = PROCESS_STATUS_RUNNING;
  spthread_t* init_thread = malloc(sizeof(spthread_t));
  spthread_create(init_thread, NULL, torta, NULL);
  init_process->thread = init_thread;

  init_process->name = "init";
  init_process->foreground = true;
  add_process_to_scheduler(init_process);
  start_kernel();
  return 0;
}
