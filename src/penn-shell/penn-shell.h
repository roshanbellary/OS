#include "../util/deque.h" // Include deque if using it for job list

#ifndef PENSHELL_H
#define PENSHELL_H
// #include "../util/types/process-status.h"
#ifndef MAX_MESSAGE_SIZE
#define MAX_MESSAGE_SIZE 4096
#endif

#ifndef SHELL_PROMPT
#define SHELL_PROMPT "$"
#endif

#ifndef pid_t
typedef int pid_t;
#endif

#ifndef JobStatus

/**
 * @brief enum for job status
 *
 */
typedef enum
{
    JOB_STATUS_RUNNING,
    JOB_STATUS_STOPPED,
    JOB_STATUS_DONE // Transient state before removal
} JobStatus;
#endif

#ifndef Job

/**
 * @brief struct for job
 *
 */
typedef struct Job
{
    int job_id;
    pid_t pid;
    char *command; // Store a copy of the command line
    JobStatus status;
    struct parsed_command *pcmd; // Store the parsed command for potential restart/display
} Job;
#endif

/**
 * @brief Main shell function to be run as a thread.
 * @param args Arguments passed to the shell thread.
 * @return void* Return value of the thread.
 */
void *shell(void *args);

/**
 * @brief Frees memory associated with a job.
 * @param data Pointer to the job to be freed.
 */
void free_job(void *data);

/**
 * @brief Initializes job control mechanisms.
 */
void initialize_job_control();

/**
 * @brief Finds a job by its process ID.
 * @param pid Process ID to search for.
 * @return Job* Pointer to the found job, or NULL if not found.
 */
Job *find_job_by_pid(pid_t pid);

/**
 * @brief Finds a job by its job ID.
 * @param job_id Job ID to search for.
 * @return Job* Pointer to the found job, or NULL if not found.
 */
Job *find_job_by_id(int job_id);

/**
 * @brief Finds the most recently added job.
 * @return Job* Pointer to the last job, or NULL if no jobs exist.
 */
Job *find_last_job();

/**
 * @brief Finds the most recently stopped job.
 * @return Job* Pointer to the last stopped job, or NULL if no stopped jobs exist.
 */
Job *find_last_stopped_job();

/**
 * @brief Adds a new job to the job list.
 * @param pid Process ID of the new job.
 * @param cmd Parsed command structure for the job.
 * @param status Initial status of the job.
 */
void add_job(pid_t pid, struct parsed_command *cmd, JobStatus status);

/**
 * @brief Removes a job from the job list by its process ID.
 * @param pid Process ID of the job to remove.
 */
void remove_job_by_pid(pid_t pid);

/**
 * @brief Reconstructs a command string from an argument vector.
 * @param argv Array of command arguments.
 * @return char* Reconstructed command string.
 */
char *reconstruct_command(char *argv[]);

int read_line_from_fd(int fd,
                      char **line_buffer,
                      size_t *buffer_size,
                      size_t *line_len);

/** @brief Global job list. */
extern Deque *job_list;

/** @brief Next available job ID. */
extern int next_job_id;

/** @brief Process ID of the shell. */
extern pid_t shell_pid;

/** @brief Process ID of the terminal controller. */
extern pid_t terminal_controller_pid;

#endif
