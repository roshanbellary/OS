#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <sys/types.h>

/**
 * @brief Initializes the logger.
 *
 * @param log_filename The name of the log file.
 */
void init_logger(const char *log_filename);

/**
 * @brief Logs an event.
 *
 * @param tick The tick count.
 * @param event The event description.
 * @param pid The process ID.
 * @param priority The priority level.
 * @param name The process name.
 */
void log_event(unsigned long tick, const char *event,
               pid_t pid, int priority, const char *name);

#endif
