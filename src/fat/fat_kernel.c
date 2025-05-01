#include "err.h"
#include "fd_table.h"
#include "pennfat.h"
#include "fat_core.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

static FD_Table fd_table; // global file descriptor table

#define MAX_LINE_LENGTH 4096

void init()
{
    initialize_fd_table(&fd_table);
}

int k_open(const char *fname, int mode) {
  char *file_name = (char *)fname;

  int ent_offset = lookup_directory_offset(file_name, 1);

  FD_Node *existing = fd_table.head;
  while (existing) {
    if (strcmp(existing->name, file_name) == 0) {
      if ((mode == F_WRITE || mode == F_APPEND) &&
          (existing->mode == F_WRITE || existing->mode == F_APPEND)) {
        ERRNO = FILE_SYSTEM;
        f_perror("Write conflict: File busy");
        return -1;
      }

      break;
    }
    existing = existing->next;
  }

  if (ent_offset == -1) {
    if (mode == F_WRITE) {
      fs_touch(file_name);
    } else {
      ERRNO = FILE_NOT_FOUND;
      f_perror("File not found");
      return -1;
    }
  }

  FD_Node *node = add_fd(&fd_table, file_name, mode);
  if (!node) {
    ERRNO = FILE_SYSTEM;
    f_perror("Failed to create file descriptor");
    return -2;
  }

  return node->fd;
}

int kf_read(int fd, int n, char *buf)
{
    if (fd < 0)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    // handle standard input/output
    if (fd < 3)
    {
        return read(fd, buf, n);
    }

    FD_Node *node = lookup_fd(&fd_table, fd);
    if (!node)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    Dir_entry curr_entry = name_to_directory(node->name);

    // check read permission
    if (curr_entry.perm != 4 && curr_entry.perm != 5 &&
        curr_entry.perm != 6 && curr_entry.perm != 7)
    {
        ERRNO = PERMISSION_DENIED;
        f_perror("Permission denied");
        return -1;
    }

    // check if we're at EOF
    int bytes_left_to_read = curr_entry.size - node->offset;
    if (bytes_left_to_read <= 0)
    {
        return 0;
    }

    int bytes_to_read = (bytes_left_to_read < n) ? bytes_left_to_read : n;

    int bytes_read = read_file(curr_entry, (uint8_t *)buf, bytes_to_read, 0, node->offset);

    if (bytes_read < 0)
    {
        return bytes_read;
    }
    else
    {
        node->offset += bytes_read;
        return bytes_read;
    }
}

int kf_write(int fd, const char *str, int n)
{
    if (fd < 0)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    // handle standard input/output
    if (fd < 3)
    {
        return write(fd, str, n);
    }

    FD_Node *node = lookup_fd(&fd_table, fd);
    if (!node)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    // check file open mode
    if (node->mode != F_WRITE && node->mode != F_APPEND)
    {
        ERRNO = PERMISSION_DENIED;
        f_perror("File not opened for writing");
        return -1;
    }

    Dir_entry curr_entry = name_to_directory(node->name);
    int ent_offset = lookup_directory_offset(node->name, 1);

    // check write permission
    if (curr_entry.perm != 2 && curr_entry.perm != 6 && curr_entry.perm != 7)
    {
        ERRNO = PERMISSION_DENIED;
        f_perror("Permission denied");
        return -1;
    }

    int bytes_written = write_file(curr_entry, (uint8_t *)str, n, node->offset);

    if (bytes_written < 0)
    {
        return bytes_written;
    }
    else
    {
        node->offset += bytes_written;
        curr_entry = offset_to_directory(ent_offset);
        curr_entry.size = node->size + bytes_written;
        node->size = curr_entry.size;
        update_directory(curr_entry, ent_offset);
        return bytes_written;
    }
}

int k_read_at_offset(int fd, int n, char *buf, int offset)
{
    if (fd < 0)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    if (fd == STDIN_FILENO)
    {
        return read(fd, buf, n);
    }

    FD_Node *node = lookup_fd(&fd_table, fd);
    if (!node)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    Dir_entry curr_entry = name_to_directory(node->name);

    if (curr_entry.perm != 4 && curr_entry.perm != 5 &&
        curr_entry.perm != 6 && curr_entry.perm != 7)
    {
        ERRNO = PERMISSION_DENIED;
        f_perror("Permission denied");
        return -1;
    }

    if (offset >= curr_entry.size)
    {
        return 0;
    }

    int bytes_to_read = ((curr_entry.size - offset) < n) ? (curr_entry.size - offset) : n;

    return k_read_at(curr_entry, buf, bytes_to_read, offset);
}

int k_write_at_offset(int fd, const char *str, int n, int offset)
{
    if (fd < 0)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
    {
        return write(fd, str, n);
    }

    FD_Node *node = lookup_fd(&fd_table, fd);
    if (!node)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    if (node->mode != F_WRITE && node->mode != F_APPEND)
    {
        ERRNO = PERMISSION_DENIED;
        f_perror("File not opened for writing");
        return -1;
    }

    Dir_entry curr_entry = name_to_directory(node->name);
    int ent_offset = lookup_directory_offset(node->name, 1);

    if (curr_entry.perm != 2 && curr_entry.perm != 6 && curr_entry.perm != 7)
    {
        ERRNO = PERMISSION_DENIED;
        f_perror("Permission denied");
        return -1;
    }

    int bytes_written = k_write_at(curr_entry, str, n, offset);

    if (bytes_written > 0)
    {
        curr_entry = offset_to_directory(ent_offset);
        if (offset + bytes_written > curr_entry.size)
        {
            curr_entry.size = offset + bytes_written;
            update_directory(curr_entry, ent_offset);
        }
    }

    return bytes_written;
}

int k_close(int fd)
{
    if (fd < 3)
    {
        ERRNO = INVALID_OPERATION;
        f_perror("Cannot close standard I/O streams");
        return -1;
    }

    FD_Node *node = remove_fd(&fd_table, fd);
    if (!node)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return -1;
    }

    free(node);
    return 0;
}

void k_unlink(const char *fname)
{
    fs_rm((char *)fname);
}

void k_lseek(int fd, int offset, int whence)
{
    FD_Node *node = lookup_fd(&fd_table, fd);
    if (!node)
    {
        ERRNO = INVALID_FD;
        f_perror("Invalid file descriptor");
        return;
    }

    Dir_entry curr_entry = name_to_directory(node->name);

    // handle different seek modes
    if (whence == SEEK_SET)
    {
        if (offset >= curr_entry.size)
        {
            ERRNO = INVALID_OFFSET;
            f_perror("Offset beyond end of file");
            return;
        }
        node->offset = offset;
    }
    else if (whence == SEEK_CUR)
    {
        if (node->offset + offset >= curr_entry.size)
        {
            ERRNO = INVALID_OFFSET;
            f_perror("Offset beyond end of file");
            return;
        }
        node->offset = node->offset + offset;
    }
    else if (whence == SEEK_END)
    {
        if (offset > 0 || offset <= -curr_entry.size)
        {
            ERRNO = INVALID_OFFSET;
            f_perror("Invalid offset from end of file");
            return;
        }
        node->offset = curr_entry.size - offset;
    }
    else
    {
        ERRNO = INVALID_WHENCE;
        f_perror("Invalid whence value");
    }
}

// callback function for ls
static void pennfat_ls_callback(const Dir_entry *entry, void *user_data)
{
    (void)user_data;
    char buffer[4096];
    format_file_info(*entry, buffer);
    kf_write(STDERR_FILENO, buffer, strlen(buffer));
}

void k_ls(const char *filename)
{
    // If specific file requested, check existence for error reporting
    if (filename)
    {
        Dir_entry curr_entry = name_to_directory((char *)filename);
        if (curr_entry.name[0] == 0)
        {
            ERRNO = FILE_NOT_FOUND;
            f_perror("File not found");
            return;
        }
    }
    fs_list_files(filename, pennfat_ls_callback, NULL);
}

void f_touch(char *args[])
{
    if (!args[1])
    {
        ERRNO = INVALID_ARGS;
        f_perror("touch: missing file operand");
        return;
    }

    // process all file arguments
    int i = 1;
    while (args[i] != NULL)
    {
        fs_touch(args[i]);
        i++;
    }
}

void f_rm(char *args[])
{
    if (!args[1])
    {
        ERRNO = INVALID_ARGS;
        f_perror("rm: missing file operand");
        return;
    }

    // process all file arguments
    int i = 1;
    while (args[i] != NULL)
    {
        if (fs_rm(args[i]) == -1)
        {
            ERRNO = FILE_NOT_FOUND;
            char err_str[1024];
            sprintf(err_str, "rm: cannot remove '%s': No such file", args[i]);
            f_perror(err_str);
        }
        i++;
    }
}

void f_mv(char *args[])
{
    if (!args[1] || !args[2])
    {
        ERRNO = INVALID_ARGS;
        f_perror("mv: missing file operand");
        return;
    }

    char *source = args[1];
    char *dest = args[2];

    if (fs_mv(source, dest) == -1)
    {
        ERRNO = FILE_NOT_FOUND;
        char err_str[1024];
        sprintf(err_str, "mv: cannot move '%s': No such file", source);
        f_perror(err_str);
    }
}

// helper function to read multiple files into a buffer
static Buffer read_many_files(char **names, int num_files_to_read)
{
    Buffer buff;
    buff.size = 0;
    buff.arr = NULL;

    // calculate total size needed
    for (int i = 0; i < num_files_to_read; ++i)
    {
        int file_ent_offset = lookup_directory_offset(names[i], 1);

        if (file_ent_offset == -1)
        {
            ERRNO = FILE_NOT_FOUND;
            char err_str[1024];
            sprintf(err_str, "File %s not found!", names[i]);
            f_perror(err_str);
            buff.size = -1;
            return buff;
        }

        Dir_entry ent = offset_to_directory(file_ent_offset);
        buff.size += ent.size;
    }

    // allocate buffer for all files
    buff.arr = (uint8_t *)malloc(buff.size);
    if (!buff.arr && buff.size > 0)
    {
        ERRNO = MEMORY_ERROR;
        f_perror("Memory allocation failed");
        buff.size = -1;
        return buff;
    }

    // read each file into buffer
    int starting_pos = 0;
    for (int i = 0; i < num_files_to_read; ++i)
    {
        int file_ent_offset = lookup_directory_offset(names[i], 1);
        Dir_entry ent = offset_to_directory(file_ent_offset);

        read_file(ent, buff.arr, ent.size, starting_pos, 0);
        starting_pos += ent.size;
    }

    return buff;
}

// helper function to handle cat input redirection to file
static void cat_stdin_to_file(char *output_file, bool append, int fd_in)
{
    char input[4096];
    int bytes_read = kf_read(fd_in, 4096, input);

    if (bytes_read > 0)
    {
        int out_fd = k_open(output_file, append ? F_APPEND : F_WRITE);
        if (out_fd >= 0)
        {
            kf_write(out_fd, input, bytes_read);
            k_close(out_fd);
        }
    }
}

// helper function to handle cat file redirection to file
static void cat_files_to_file(char **input_files, int num_input_files, char *output_file, bool append)
{
    Buffer buf = read_many_files(input_files, num_input_files);
    if (buf.size > 0)
    {
        int out_fd = k_open(output_file, append ? F_APPEND : F_WRITE);
        if (out_fd >= 0)
        {
            kf_write(out_fd, (char *)buf.arr, buf.size);
            k_close(out_fd);
        }
        free(buf.arr);
    }
}

void f_cat(char *args[], int fd_in, int fd_out)
{
    if (!args[1])
    {
        // cat with no arguments reads from stdin and writes to stdout
        char input[4096];
        int bytes_read = kf_read(fd_in, 4096, input);
        if (bytes_read > 0)
        {
            kf_write(fd_out, input, bytes_read);
        }
        return;
    }

    int i = 1;
    char buf[1];

    // process file arguments until -w or -a flag
    while (args[i] != NULL)
    {
        if (strcmp(args[i], "-w") == 0 || strcmp(args[i], "-a") == 0)
        {
            break;
        }

        int file_fd = k_open(args[i], F_READ);
        if (file_fd < 0)
        {
            i++;
            continue;
        }

        // read file byte by byte and write to output
        while (1)
        {
            int bytes_read = kf_read(file_fd, 1, buf);
            if (bytes_read <= 0)
            {
                break;
            }
            kf_write(fd_out, buf, 1);
        }

        k_close(file_fd);
        i++;
    }

    // handle -a and -w flags for output redirection
    if (args[i] != NULL && (strcmp(args[i], "-w") == 0 || strcmp(args[i], "-a") == 0))
    {
        bool append = (strcmp(args[i], "-a") == 0);

        if (args[i + 1] == NULL)
        {
            ERRNO = INVALID_ARGS;
            f_perror("cat: missing output file");
            return;
        }

        if (i == 1)
        {
            // no input files specified, read from stdin
            cat_stdin_to_file(args[i + 1], append, fd_in);
        }
        else
        {
            // concatenate input files and write to output file
            int num_input_files = i - 1;
            char *input_files[num_input_files];

            for (int j = 0; j < num_input_files; j++)
            {
                input_files[j] = args[j + 1];
            }

            cat_files_to_file(input_files, num_input_files, args[i + 1], append);
        }
    }
}

// helper function to copy from host OS to filesystem
static void cp_host_to_fs(char *host_file, char *fs_file)
{
    int host_fd = open(host_file, O_RDONLY);
    if (host_fd == -1)
    {
        ERRNO = FILE_NOT_FOUND;
        char err_str[1024];
        sprintf(err_str, "cp: cannot open '%s'", host_file);
        f_perror(err_str);
        return;
    }

    // get file size
    struct stat st;
    if (fstat(host_fd, &st) == -1)
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to get file size");
        close(host_fd);
        return;
    }

    // allocate buffer
    char *buffer = malloc(st.st_size);
    if (!buffer && st.st_size > 0)
    {
        ERRNO = MEMORY_ERROR;
        f_perror("Memory allocation failed");
        close(host_fd);
        return;
    }

    // read host file
    if (read(host_fd, buffer, st.st_size) != st.st_size)
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to read host file");
        free(buffer);
        close(host_fd);
        return;
    }

    close(host_fd);

    // create and write to filesystem file
    fs_touch(fs_file);
    int fs_fd = k_open(fs_file, F_WRITE);
    if (fs_fd < 0)
    {
        free(buffer);
        return;
    }

    kf_write(fs_fd, buffer, st.st_size);
    k_close(fs_fd);
    free(buffer);
}

// helper function to copy from filesystem to host OS
static void cp_fs_to_host(char *fs_file, char *host_file)
{
    int fs_fd = k_open(fs_file, F_READ);
    if (fs_fd < 0)
    {
        return;
    }

    Dir_entry ent = name_to_directory(fs_file);
    if (ent.name[0] == 0)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("File not found");
        k_close(fs_fd);
        return;
    }

    // allocate buffer
    char *buffer = malloc(ent.size);
    if (!buffer && ent.size > 0)
    {
        ERRNO = MEMORY_ERROR;
        f_perror("Memory allocation failed");
        k_close(fs_fd);
        return;
    }

    // read filesystem file
    if (kf_read(fs_fd, ent.size, buffer) != ent.size)
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to read file");
        free(buffer);
        k_close(fs_fd);
        return;
    }

    k_close(fs_fd);

    // write to host file
    int host_fd = open(host_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (host_fd == -1)
    {
        ERRNO = FILE_SYSTEM;
        char err_str[1024];
        sprintf(err_str, "cp: cannot create '%s'", host_file);
        f_perror(err_str);
        free(buffer);
        return;
    }

    if (write(host_fd, buffer, ent.size) != ent.size)
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to write to host file");
    }

    close(host_fd);
    free(buffer);
}

// helper function to copy file within filesystem
static void cp_fs_to_fs(char *src_file, char *dst_file)
{
    int source_fd = k_open(src_file, F_READ);
    if (source_fd < 0)
    {
        return;
    }

    fs_touch(dst_file);
    int dest_fd = k_open(dst_file, F_WRITE);
    if (dest_fd < 0)
    {
        k_close(source_fd);
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to open destination file");
        return;
    }

    // get source file size
    int src_offset = lookup_directory_offset(src_file, 1);
    Dir_entry src_ent = offset_to_directory(src_offset);
    int src_file_size = src_ent.size;

    // allocate buffer for file data
    char *buff = malloc(src_file_size);
    if (!buff && src_file_size > 0)
    {
        k_close(source_fd);
        k_close(dest_fd);
        ERRNO = MEMORY_ERROR;
        f_perror("Memory allocation failed");
        return;
    }

    // read source and write to destination
    int bytes_read = kf_read(source_fd, src_file_size, buff);

    if (bytes_read > 0)
    {
        kf_write(dest_fd, buff, bytes_read);
    }

    free(buff);
    k_close(source_fd);
    k_close(dest_fd);
}

void f_cp(char *args[])
{
    if (!args[1] || !args[2])
    {
        ERRNO = INVALID_ARGS;
        f_perror("cp: missing file operand");
        return;
    }
    bool source_h = (strcmp(args[1], "-h") == 0);
    bool dest_h = (strcmp(args[2], "-h") == 0);

    if (source_h && args[2] && args[3])
    {
        // copy from host OS to filesystem
        cp_host_to_fs(args[2], args[3]);
    }
    else if (dest_h && args[1] && args[3])
    {
        // copy from filesystem to host OS
        cp_fs_to_host(args[1], args[3]);
    }
    else
    {
        // copy file within filesystem
        cp_fs_to_fs(args[1], args[2]);
    }
}

int f_get_permission(char *file_name)
{
    return k_get_permission(file_name);
}

int k_chmod(const char *fname, uint8_t new_perm)
{
    return fs_chmod((char *)fname, new_perm);
}

// for standalone FAT shit
void f_chmod(char *args[])
{
    if (!args[1] || !args[2])
    {
        ERRNO = INVALID_ARGS;
        f_perror("chmod: missing operand");
        return;
    }

    char *mode_str = args[1];
    char *file_name = args[2];

    // --- Parsing logic for +/-rwx ---
    if (strlen(mode_str) < 2 || (mode_str[0] != '+' && mode_str[0] != '-'))
    {
        ERRNO = INVALID_ARGS;
        f_perror("chmod: invalid mode format (e.g., +r, -wx)");
        return;
    }

    int current_perm_val = get_file_permission(file_name); // Assumes get_file_permission exists and works
    if (current_perm_val < 0)
    {
        return; // Error already printed by get_file_permission or f_perror called internally
    }
    uint8_t current_perm = (uint8_t)current_perm_val;
    uint8_t change_perm = 0;

    for (int i = 1; i < strlen(mode_str); ++i)
    {
        switch (mode_str[i])
        {
        case 'r':
            change_perm |= 4;
            break;
        case 'w':
            change_perm |= 2;
            break;
        case 'x':
            change_perm |= 1;
            break;
        default:
            ERRNO = INVALID_ARGS;
            f_perror("chmod: invalid permission character");
            return;
        }
    }

    uint8_t new_perm;
    if (mode_str[0] == '+')
    {
        new_perm = current_perm | change_perm;
    }
    else
    { // mode_str[0] == '-'
        new_perm = current_perm & (~change_perm);
    }

    if (k_chmod(file_name, new_perm) < 0)
    {
        // k_chmod calls fs_chmod which sets ERRNO, just call f_perror
        char err_buf[100];
        snprintf(err_buf, sizeof(err_buf), "chmod: failed to change mode of '%s'", file_name);
        f_perror(err_buf); // f_perror will use the ERRNO set by fs_chmod
    }
}

int k_get_permission(const char *fname)
{
    int offset = lookup_directory_offset((char *)fname, 1); // Assuming root dir block is 1
    if (offset == -1)
    {
        ERRNO = FILE_NOT_FOUND; // Set FAT-specific errno
        // f_perror("k_get_permission: File not found"); // Internal logging optional
        return -1; // Indicate file not found/error
    }

    Dir_entry ent = offset_to_directory(offset);
    if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2)
    {
        // Should not happen if lookup succeeded, but double-check
        ERRNO = FILE_NOT_FOUND;
        return -1;
    }

    // Return the permission bits as an integer
    return (int)ent.perm;
}
