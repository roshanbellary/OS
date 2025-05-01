#ifndef FAT_CORE_H
#define FAT_CORE_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>

/* File types */
#define UNKNOWN_FILE 0
#define REGULAR_FILE 1
#define DIRECTORY_FILE 2
#define LINK_FILE 4

/* Special flags */
#define EOD_FLAG 0x00

/* Block status values */
#define LAST_BLOCK 0xFFFF
#define FREE_BLOCK 0x0000

/* File positioning constants */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/**
 * directory entry structure representing a file in the filesystem
 * @param name file name
 * name[0] is a special marker
 * - 0: end of directory
 * - 1: deleted entry; the file is also deleted
 * - 2: deleted entry; the file is still being used
 * @param size number of bytes in file
 * @param first_block first block number of file (undefined if 0 size)
 * @param type type of file
 * - 0: unknown
 * - 1: regular file
 * - 2: directory file
 * - 3: symbolic link
 * @param perm file permissions
 * - 0: none
 * - 2: write only
 * - 4: read only
 * - 5: read and executable (shell scripts)
 * - 6: read and write
 * - 7: read, write, and executable
 * @param mtime creation/modification time
 * @param reserved reserved bytes (last 16)
 */
typedef struct dir_entry
{
    char name[32];
    uint32_t size;
    uint16_t first_block;
    uint8_t type;
    uint8_t perm;
    time_t mtime;
    long double reserved;
} Dir_entry;

/**
 * buffer structure for holding data
 * @param arr pointer to data array
 * @param size size of buffer in bytes
 */
typedef struct buffer
{
    uint8_t *arr;
    int size;
} Buffer;

/*
 * Filesystem core management functions
 */

/**
 * maps block size configuration to actual byte size
 * @param input block size configuration (0-4)
 * @return size in bytes or -1 if invalid input
 */
int convert_block_size(int input);

/**
 * creates a new pennfat filesystem
 * @param fs_name name of the filesystem file
 * @param new_fat_block_count number of blocks in FAT region
 * @param block_config block size configuration (0-4)
 * @return 1 on success, -1 on failure
 */
int fs_create(char *fs_name, int new_fat_block_count, int block_config);

/**
 * mounts a pennfat filesystem into memory
 * @param fs_name name of the filesystem file to mount
 * @return 0 on success, -1 on failure
 */
int fs_mount(char *fs_name);

/**
 * unmounts the currently mounted filesystem
 * @return 0 on success, -1 on failure
 */
int fs_unmount(void);

/*
 * File operation functions
 */

/**
 * creates a file or updates its timestamp if it exists
 * @param file_name name of the file to touch
 * @return 1 on success, -1 on failure
 */
int fs_touch(char *file_name);

/**
 * removes a file from the filesystem
 * @param file_name name of the file to remove
 * @return 1 on success, -1 on failure
 */
int fs_rm(char *file_name);

/**
 * renames a file in the filesystem
 * @param source original filename
 * @param dest new filename
 * @return 1 on success, -1 on failure
 */
int fs_mv(char *source, char *dest);

/**
 * creates a new file with specified type
 * @param filename name of the file to create
 * @param type file type (regular, directory, etc.)
 * @return 1 on success, -1 on failure
 */
int create_file(char *filename, uint8_t type);

/*
 * File data read/write functions
 */

/**
 * reads data from a file
 * @param ent directory entry for the file
 * @param arr buffer to store read data
 * @param num_bytes number of bytes to read
 * @param buff_pos starting position in buffer
 * @param file_pos starting position in file
 * @return number of bytes read or -1 on error
 */
int read_file(Dir_entry ent, uint8_t *arr, int num_bytes, int buff_pos, int file_pos);

/**
 * writes data to a file
 * @param ent directory entry for the file
 * @param arr buffer containing data to write
 * @param num_bytes number of bytes to write
 * @param start starting position in file
 * @return number of bytes written or -1 on error
 */
int write_file(Dir_entry ent, uint8_t *arr, int num_bytes, int start);

/**
 * reads data from a file with explicit offset
 * @param ent directory entry for the file
 * @param arr buffer to store read data
 * @param num_bytes number of bytes to read
 * @param file_pos position in file to start reading from
 * @return number of bytes read or -1 on error
 */
int k_read_at(Dir_entry ent, char *buf, int n, int offset);

/**
 * writes data to a file with explicit offset
 * @param ent directory entry for the file
 * @param str buffer containing data to write
 * @param n number of bytes to write
 * @param offset position in file to start writing at
 * @return number of bytes written or -1 on error
 */
int k_write_at(Dir_entry ent, const char *str, int n, int offset);

/*
 * Directory entry management functions
 */

/**
 * gets the root directory entry
 * @return root directory entry
 */
Dir_entry get_directory(void);

/**
 * finds the location of a directory entry by name
 * @param name filename to find
 * @param block block to start search from
 * @return offset of directory entry or -1 if not found
 */
int lookup_directory_offset(char *name, int block);

/**
 * gets directory entry at specified offset
 * @param offset file offset of directory entry
 * @return directory entry at specified offset
 */
Dir_entry offset_to_directory(int offset);

/**
 * gets directory entry by filename
 * @param name filename to find
 * @return directory entry for specified file or empty entry if not found
 */
Dir_entry name_to_directory(char *name);

/**
 * gets directory entry by index
 * @param index index of directory entry
 * @return directory entry at specified index or empty entry if not found
 */
Dir_entry index_to_directory(int index);

// Callback type for file listing
typedef void (*file_info_callback_t)(const Dir_entry *, void *);

/**
 * @brief List files in the filesystem, invoking a callback for each entry.
 * @param filename If not NULL, only list that file; else list all files.
 * @param callback Function called for each file entry found.
 * @param user_data Opaque pointer passed to callback.
 */
void fs_list_files(const char *filename, file_info_callback_t callback, void *user_data);

// Formats a Dir_entry into a printable string for ls output
void format_file_info(Dir_entry entry, char *buffer);

/**
 * updates a directory entry
 * @param ent updated directory entry
 * @param offset offset of entry to update
 * @return 1 on success, -1 on failure
 */
int update_directory(Dir_entry ent, int offset);

/*
 * Utility functions
 */

/**
 * converts permission value to string representation
 * @param perm permission value
 * @param permission_str output string buffer (should be at least 4 bytes)
 */
void perm_to_rwx(int perm, char *permission_str);

/**
 * gets permission value for a file
 * @param name filename
 * @return permission value or -1 if file not found
 */
int get_file_permission(char *name);

/**
 * changes permissions of a file
 * @param filename name of the file
 * @param new_perm new permission value
 * @return 1 on success, -1 on failure
 */
int fs_chmod(char *filename, uint8_t new_perm);

#endif