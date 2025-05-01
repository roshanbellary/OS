#ifndef MAX_MESSAGE_SIZE
#define MAX_MESSAGE_SIZE 4096
#endif
/**
 * @brief The ususal `cat` program.
 *
 * If `files` arg is provided, concatenate these files and print to stdout
 * If `files` arg is *not* provided, read from stdin and print back to stdout
 *
 * Example Usage: cat f1 f2 (concatenates f1 and f2 and print to stdout)
 * Example Usage: cat f1 f2 < f3 (concatenates f1 and f2 and prints to stdout,
 * ignores f3) Example Usage: cat < f3 (concatenates f3, prints to stdout)
 */
void* u_cat(void* arg);

/**
 * @brief Sleep for `n` seconds.
 *
 * Note that you'll have to convert the number of seconds to the correct number
 * of ticks.
 *
 * Example Usage: sleep 10
 */
void* u_sleep(void* arg);

/**
 * @brief Busy wait indefinitely.
 * It can only be interrupted via signals.
 *
 * Example Usage: busy
 */
void* u_busy(void* arg);

/**
 * @brief Echo back an input string.
 *
 * Example Usage: echo Hello World
 */
void* u_echo(void* arg);

/**
 * @brief Lists all files in the working directory.
 * For extra credit, it should support relative and absolute file paths.
 *
 * Example Usage: ls (regular credit)
 * Example Usage: ls ../../foo/./bar/sample (only for EC)
 */
void* u_ls(void* arg);

/**
 * @brief For each file, create an empty file if it doesn't exist, else update
 * its timestamp.
 *
 * Example Usage: touch f1 f2 f3 f4 f5
 */
void* u_touch(void* arg);

/**
 * @brief Rename a file. If the `dst_file` file already exists, overwrite it.
 *
 * Print appropriate error message if:
 * - `src_file` is not a file that exists
 * - `src_file` does not have read permissions
 * - `dst_file` file already exists but does not have write permissions
 *
 * Example Usage: mv src_file dst_file
 */
void* u_mv(void* arg);

/**
 * Copy a file. If the `dst_file` file already exists, overwrite it.
 *
 * Print appropriate error message if:
 * - `src_file` is not a file that exists
 * - `src_file` does not have read permissions
 * - `dst_file` file already exists but does not have write permissions
 *
 * Example Usage: cp src_file dst_file
 */
void* u_cp(void* arg);

/**
 * @brief Remove a list of files.
 * Treat each file in the list as a separate transaction. (i.e. if removing
 * file1 fails, still attempt to remove file2, file3, etc.)
 *
 * Print appropriate error message if:
 * - `file` is not a file that exists
 *
 * Example Usage: rm f1 f2 f3 f4 f5
 */
void* u_rm(void* arg);

/**
 * @brief Change permissions of a file.
 * There's no need to error if a permission being added already exists, or
 * if a permission being removed is already not granted.
 *
 * Print appropriate error message if:
 * - `file` is not a file that exists
 * - `perms` is invalid
 *
 * Example Usage: chmod +x file (adds executable permission to file)
 * Example Usage: chmod +rw file (adds read + write permissions to file)
 * Example Usage: chmod -wx file (removes write + executable permissions from
 * file)
 */
void* u_chmod(void* arg);

/**
 * @brief List all processes on PennOS, displaying PID, PPID, priority, status,
 * and command name.
 *
 * Example Usage: ps
 */
void* u_ps(void* arg);

/**
 * @brief Sends a specified signal to a list of processes.
 * If a signal name is not specified, default to "term".
 * Valid signals are -term, -stop, and -cont.
 *
 * Example Usage: kill 1 2 3 (sends term to processes 1, 2, and 3)
 * Example Usage: kill -term 1 2 (sends term to processes 1 and 2)
 * Example Usage: kill -stop 1 2 (sends stop to processes 1 and 2)
 * Example Usage: kill -cont 1 (sends cont to process 1)
 */
void* u_kill(void* arg);

/**
 * @brief Helper for zombify.
 */
void* zombie_child(void* arg);

/**
 * @brief Used to test zombifying functionality of your kernel.
 *
 * Example Usage: zombify
 */
void* u_zombify(void* arg);

/**
 * @brief Helper for orphanify.
 */
void* u_orphan_child(void* arg);

/**
 * @brief Used to test orphanifying functionality of your kernel.
 *
 * Example Usage: orphanify
 */
void* u_orphanify(void* arg);

/**
 * @brief Spawn a new process for `command` and set its priority to `priority`.
 * 2. Adjust the priority level of an existing process.
 *
 * Example Usage: nice 2 cat f1 f2 f3 (spawns cat with priority 2)
 */
void* u_nice(void* arg);

/**
 * @brief Adjust the priority level of an existing process.
 *
 * Example Usage: nice_pid 0 123 (sets priority 0 to PID 123)
 */
void* u_nice_pid(void* arg);

/**
 * @brief Lists all available commands.
 *
 * Example Usage: man
 */
void* u_man(void* arg);

/**
 * @brief Resumes the most recently stopped job in the background, or the job
 * specified by job_id.
 *
 * Example Usage: bg
 * Example Usage: bg 2 (job_id is 2)
 */
void* u_bg(void* arg);

/**
 * @brief Brings the most recently stopped or background job to the foreground,
 * or the job specified by job_id.
 *
 * Example Usage: fg
 * Example Usage: fg 2 (job_id is 2)
 */
void* u_fg(void* arg);

/**
 * @brief Lists all jobs.
 *
 * Example Usage: jobs
 */
void* u_jobs(void* arg);

/**
 * @brief Exits the shell and shutsdown PennOS.
 *
 * Example Usage: logout
 */
void* u_logout(void* arg);

/**
 *
 * @brief Converts a string to an integer.
 */
int stoi(char* str);

/**
 * @brief Test command that spawns 10 child processes and waits on them (blocking).
 * Useful for testing the scheduler and wait functionality.
 *
 * Example Usage: hang
 */
void* u_hang(void* arg);

/**
 * @brief Test command that spawns 10 child processes and waits on them (non-blocking).
 * Useful for testing the scheduler with non-blocking waits.
 *
 * Example Usage: nohang
 */
void* u_nohang(void* arg);

/**
 * @brief Test command that recursively spawns 26 processes (Gen_A through Gen_Z).
 * Useful for testing recursive spawning and deep process hierarchies.
 *
 * Example Usage: recur
 */
void* u_recur(void* arg);

/**
 * @brief Test command that writes a large pattern to a file and then crashes.
 * Useful for testing file system durability and crash recovery.
 * Requires the filesystem to be able to hold at least 5480 bytes in a file.
 *
 * Example Usage: crash
 */
void* u_crash(void* arg);