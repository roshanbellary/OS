#ifndef EXECUTE_COMMAND_H
#define EXECUTE_COMMAND_H

#include <sys/types.h>
#include "parser.h"

// handle built-in commands, returns 0 if handled, -1 if not a built-in
int handle_shell_builtin(struct parsed_command *cmd);

// run commands from a script file, returns 0 on success, -1 on error
int execute_script_file(const char *script_path,
                        int inherit_fd0,
                        int inherit_fd1,
                        const char *output_file);

// execute a single command entry, returns pid (>0), 0 for scripts, -1 on error
pid_t execute_single_command(struct parsed_command *cmd,
                             int cmd_index,
                             int input_fd,
                             int output_fd,
                             const char *full_command_line);

// execute a parsed command with redirections and job control,
// returns child pid (>0) or -1 on error
int execute_command(struct parsed_command *cmd);

#endif