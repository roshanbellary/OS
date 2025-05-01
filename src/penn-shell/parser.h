/* Penn-Shell Parser
   hanbangw, 21fa    */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define UNEXPECTED_FILE_INPUT 1
#define UNEXPECTED_FILE_OUTPUT 2
#define UNEXPECTED_PIPELINE 3
#define UNEXPECTED_AMPERSAND 4
#define EXPECT_INPUT_FILENAME 5
#define EXPECT_OUTPUT_FILENAME 6
#define EXPECT_COMMANDS 7

/**
 * @brief struct parsed_command stored all necessary
 * information needed for penn-shell.
 *
 */
struct parsed_command
{
  // indicates the command shall be executed in background
  // (ends with an ampersand '&')
  bool is_background;

  // indicates if the stdout_file shall be opened in append mode
  // ignore this value when stdout_file is NULL
  bool is_file_append;

  // filename for redirecting input from
  const char *stdin_file;

  // filename for redirecting output to
  const char *stdout_file;

  // number of commands (pipeline stages)
  size_t num_commands;

  // an array to a list of arguments
  // size of `commands` is `num_commands`
  char **commands[];
};

/**
 * @brief Parse a command line into a parsed_command structure.
 *
 * @param cmd_line The command line to parse.
 * @param result A pointer to a pointer to a parsed_command structure.
 * @return int 0 on success, -1 on failure.
 */
int parse_command(const char *cmd_line, struct parsed_command **result);

/**
 * @brief Print a parsed command line.
 *
 * @param cmd The parsed command to print.
 */
void print_parsed_command(const struct parsed_command *cmd);

/**
 * @brief Print a debugging message for a parser error code.
 *
 * @param output The output stream to print to.
 * @param err_code The error code to print.
 */
void print_parser_errcode(FILE *output, int err_code);

/**
 * @brief Print a parsed command line without the trailing newline.
 *
 * @param cmd The parsed command to print.
 */
void print_parsed_command_without_end(struct parsed_command *cmd);
