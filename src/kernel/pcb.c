#include <stdlib.h>
#include <string.h>

#include "pcb.h"

void pcb_initialize_fd_table(pcb_t *pcb) { pcb->fd_table = NULL; }


int pcb_add_fd(pcb_t *pcb, int fd, const char *fname, int mode, int offset) {
  if (!pcb) {
    return -1;
  }

  ProcessFDNode *node = malloc(sizeof(ProcessFDNode));
  if (!node) {
    return -1;
  }

  node->fd_num = fd;

  if (fname) {
    strncpy(node->fname, fname, 31);
    node->fname[31] = '\0';
  } else {
    node->fname[0] = '\0';
  }

  node->mode = mode;
  node->offset = offset;

  node->next = pcb->fd_table;
  pcb->fd_table = node;

  return fd;
}

int pcb_remove_fd(pcb_t *pcb, int fd) {
  if (!pcb) {
    return -1;
  }

  ProcessFDNode **curr = &pcb->fd_table;
  while (*curr) {
    if ((*curr)->fd_num == fd) {
      ProcessFDNode *to_free = *curr;
      *curr = (*curr)->next;
      free(to_free);
      return 0;
    }
    curr = &((*curr)->next);
  }

  return -1;
}

ProcessFDNode *pcb_get_fd(pcb_t *pcb, int fd_num) {
  ProcessFDNode *curr = pcb->fd_table;
  while (curr) {
    if (curr->fd_num == fd_num) return curr;
    curr = curr->next;
  }
  return NULL;
}

pcb_t *pcb_create(pid_t pid, pid_t ppid, int priority_level, char *name,
                  bool foreground) {
  pcb_t *pcb = malloc(sizeof(pcb_t));
  if (!pcb) return NULL;
  pcb->pid = pid;
  pcb->ppid = ppid;
  pcb->priority_level = priority_level;
  pcb->term_signal = 0;
  pcb->stop_signal = 0;
  pcb->status = PROCESS_STATUS_RUNNING;
  pcb->wake_up_tick = 0;
  pcb->file_descriptors = deque_new(free);
  pcb->thread = NULL;
  pcb->name = name ? strdup(name) : NULL;
  pcb->foreground = foreground;
  return pcb;
}

void pcb_destroy(pcb_t *pcb) {
  if (!pcb) return;
  if (pcb->file_descriptors) {
    clear_deque(pcb->file_descriptors);
    free(pcb->file_descriptors);
  }
  if (pcb->thread) {
    free(pcb->thread);
  }
  if (pcb->name) {
    free(pcb->name);
  }
  free(pcb);
}
int pcb_set_fd(pcb_t *pcb, int fd_num, const char *fname, int mode,
               int offset) {
  if (!pcb || fd_num < 0) {
    return -1;
  }

  pcb_remove_fd(pcb, fd_num);

  ProcessFDNode *node = malloc(sizeof(ProcessFDNode));
  if (!node) {
    return -1;
  }

  node->fd_num = fd_num;
  node->mode = mode;
  node->offset = offset;

  if (fname && strlen(fname) > 0) {
    strncpy(node->fname, fname, sizeof(node->fname) - 1);
    node->fname[sizeof(node->fname) - 1] = '\0'; 
  } else {
    node->fname[0] = '\0';
  }

  node->next = pcb->fd_table;
  pcb->fd_table = node;

  return fd_num;
}