#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE* log_fp = NULL;

void init_logger(const char* log_filename) {
  if (log_fp != NULL)
    return;
  log_fp = fopen(log_filename, "w");
  if (log_fp == NULL) {
    perror("Failed to open log file");
    exit(1);
  }
}

void log_event(unsigned long tick,
               const char* event,
               pid_t pid,
               int priority,
               const char* name) {
  if (log_fp == NULL) {
    init_logger("pennos.log");
  }

  fprintf(log_fp, "[%lu]\t%s\t%d\t%d\t%s\n", tick, event, pid, priority, name);
  fflush(log_fp);
}
