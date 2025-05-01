#ifndef FAT_KERNEL_H
#define FAT_KERNEL_H

#include "fat_core.h"
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

/* File opening modes */
#define F_READ 0
#define F_WRITE 1
#define F_APPEND 2

/* Standard file descriptors */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* File positioning constants */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/**
 * initializes the pennfat system
 */
void init(void);

/*
 * File descriptor management functions
 */

/**
 * opens a file with specified mode
 * @param fname name of the file to open
 * @param mode access mode (F_READ, F_WRITE, F_APPEND)
 * @return file descriptor on success, negative value on failure
 */
int k_open(const char *fname, int mode);

/**
 * reads data from a file
 * @param fd file descriptor
 * @param n maximum number of bytes to read
 * @param buf buffer to store read data
 * @return number of bytes read, 0 on EOF, negative value on error
 */
int kf_read(int fd, int n, char *buf);

/**
 * writes data to a file
 * @param fd file descriptor
 * @param str buffer containing data to write
 * @param n number of bytes to write
 * @return number of bytes written, negative value on error
 */
int kf_write(int fd, const char *str, int n);

/**
 * reads data from a file at specified offset
 * @param fd file descriptor
 * @param n maximum number of bytes to read
 * @param buf buffer to store read data
 * @param offset position in file to start reading from
 * @return number of bytes read, 0 on EOF, negative value on error
 */
int k_read_at_offset(int fd, int n, char *buf, int offset);

/**
 * writes data to a file at specified offset
 * @param fd file descriptor
 * @param str buffer containing data to write
 * @param n number of bytes to write
 * @param offset position in file to start writing at
 * @return number of bytes written, negative value on error
 */
int k_write_at_offset(int fd, const char *str, int n, int offset);

/**
 * closes a file descriptor
 * @param fd file descriptor to close
 * @return 0 on success, negative value on failure
 */
int k_close(int fd);

/**
 * removes a file from the filesystem
 * @param fname name of the file to remove
 */
void k_unlink(const char *fname);

/**
 * repositions the file offset
 * @param fd file descriptor
 * @param offset offset value
 * @param whence reference position (SEEK_SET, SEEK_CUR, SEEK_END)
 */
void k_lseek(int fd, int offset, int whence);

/*
 * File listing functions
 */

/**
 * lists file(s) in the filesystem
 * @param filename specific file to list, or NULL for all files
 */
void k_ls(const char *filename);

/*
 * File manipulation command functions
 */

/**
 * creates empty files or updates timestamps of existing files
 * @param args command arguments array (args[0] is command name)
 */
void f_touch(char *args[]);

/**
 * removes files from the filesystem
 * @param args command arguments array (args[0] is command name)
 */
void f_rm(char *args[]);

/**
 * renames a file
 * @param args command arguments array (args[0] is command name)
 */
void f_mv(char *args[]);

/**
 * concatenates files or displays input
 * @param args command arguments array (args[0] is command name)
 * @param fd_in input file descriptor
 * @param fd_out output file descriptor
 */
void f_cat(char *args[], int fd_in, int fd_out);

/**
 * copies a file
 * @param args command arguments array (args[0] is command name)
 */
void f_cp(char *args[]);

/**
 * changes file permissions
 * @param args command arguments array (args[0] is command name)
 */
void f_chmod(char *args[]);

/**
 * gets permission value for a file
 * @param file_name name of the file
 * @return permission value or -1 if file not found
 */
int f_get_permission(char *file_name);

/**
 * changes permissions of a file
 * @param fname name of the file
 * @param new_perm new permission value
 * @return 1 on success, -1 on failure
 */
int k_chmod(const char *fname, uint8_t new_perm);

/**
 * gets permission value for a file
 * @param fname name of the file
 * @return permission value or -1 if file not found
 */
int k_get_permission(const char *fname);

#endif