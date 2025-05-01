#include "err.h"
#include "fat_core.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

static uint16_t *fat;        // pointer to memory-mapped FAT region
static Dir_entry root;       // root directory entry
static int filesystem_fd;    // file descriptor for the filesystem file
static int fat_block_count;  // number of blocks in the FAT region
static int data_block_count; // number of blocks in the data region
static int block_size;       // size of each block in bytes

static int get_free_block()
{
    for (int i = 2; i < data_block_count + 2; ++i)
    {
        if (fat[i] == FREE_BLOCK)
        {
            return i;
        }
    }
    return -1;
}

static int get_last_block(int first_block)
{
    int dir_block = first_block;
    while (fat[dir_block] != LAST_BLOCK)
    {
        dir_block = fat[dir_block];
    }
    return dir_block;
}

static void free_block_chain(int start_block)
{
    int cur = start_block;

    while (cur != LAST_BLOCK)
    {
        int next = fat[cur];
        fat[cur] = FREE_BLOCK;
        cur = next;
    }
}

int convert_block_size(int input)
{
    switch (input)
    {
    case 0:
        return 256;
    case 1:
        return 512;
    case 2:
        return 1024;
    case 3:
        return 2048;
    case 4:
        return 4096;
    default:
        return -1;
    }
}

int fs_create(char *fs_name, int new_fat_block_count, int block_config)
{
    int new_filesystem_fd = open(fs_name, O_RDWR | O_CREAT | O_APPEND | O_SYNC, 0666);
    if (new_filesystem_fd == -1)
    {
        ERRNO = MKFS;
        f_perror("Failed to create filesystem file");
        return -1;
    }

    int actual_size = convert_block_size(block_config);
    if (actual_size == -1)
    {
        ERRNO = MKFS;
        f_perror("Invalid block size configuration");
        close(new_filesystem_fd);
        return -1;
    }

    // calculate filesystem parameters
    int fat_bytes = new_fat_block_count * actual_size;
    int fat_entries = fat_bytes / 2;
    int data_blocks = fat_entries - 1;

    // ensure we don't exceed maximum block numbers
    if (data_blocks >= LAST_BLOCK)
    {
        data_blocks = LAST_BLOCK - 1;
    }
    int data_size = data_blocks * actual_size;

    // initialize the first two FAT entries
    uint16_t init_fat[2];
    init_fat[1] = LAST_BLOCK;
    init_fat[0] = (uint16_t)((new_fat_block_count << 8) | block_config);

    if (write(new_filesystem_fd, init_fat, 4) != 4)
    {
        ERRNO = MKFS;
        f_perror("Failed to write FAT entries");
        close(new_filesystem_fd);
        return -1;
    }

    // set total filesystem size (FAT + data regions)
    if (ftruncate(new_filesystem_fd, fat_bytes + data_size) == -1)
    {
        ERRNO = MKFS;
        f_perror("Failed to set filesystem size");
        close(new_filesystem_fd);
        return -1;
    }
    close(new_filesystem_fd);
    return 1;
}

int fs_mount(char *fs_name)
{
    filesystem_fd = open(fs_name, O_RDWR);
    if (filesystem_fd == -1)
    {
        ERRNO = MOUNT;
        f_perror("Failed to mount filesystem");
        return -1;
    }

    // read metadata from first FAT entry
    uint16_t *buffer = malloc(sizeof(u_int16_t));
    int num_read = read(filesystem_fd, buffer, 2);
    if (num_read != 2)
    {
        free(buffer);
        ERRNO = MOUNT;
        f_perror("Failed to read filesystem metadata");
        close(filesystem_fd);
        return -1;
    }

    block_size = convert_block_size(*buffer & 0x00FF);
    fat_block_count = *buffer >> 8;

    if (block_size == -1)
    {
        ERRNO = MOUNT;
        f_perror("Invalid block size in filesystem");
        close(filesystem_fd);
        return -1;
    }

    // calculate number of blocks in data region
    data_block_count = (block_size * fat_block_count / 2) - 1;

    // memory-map the FAT region
    fat = mmap(NULL, fat_block_count * block_size, PROT_READ | PROT_WRITE, MAP_SHARED, filesystem_fd, 0);
    if (fat == MAP_FAILED)
    {
        ERRNO = MOUNT;
        f_perror("Failed to memory-map FAT");
        close(filesystem_fd);
        return -1;
    }

    // initialize root directory entry
    root = (Dir_entry){"root", 0, 1, REGULAR_FILE, 7, 0};
    return 0;
}

int fs_unmount()
{
    if (munmap(fat, fat_block_count * block_size) == -1)
    {
        ERRNO = UNMOUNT;
        f_perror("Failed to unmap FAT");
        return -1;
    }

    if (close(filesystem_fd) == -1)
    {
        ERRNO = UNMOUNT;
        f_perror("Failed to close filesystem");
        return -1;
    }

    return 0;
}

Dir_entry get_directory(void)
{
    return root;
}

int lookup_directory_offset(char *name, int block)
{
    block = 1; // always start from root directory block

    int dir_block = block;
    Dir_entry ent;
    int entries_per_block = block_size / sizeof(Dir_entry);
    int fat_size = fat_block_count * block_size;

    // iterate through all directory blocks
    while (dir_block != LAST_BLOCK)
    {
        // search through entries in current block
        for (int i = 0; i < entries_per_block; ++i)
        {
            int offset = fat_size + (block_size * (dir_block - 1) + (i * sizeof(Dir_entry)));

            lseek(filesystem_fd, offset, SEEK_SET);

            if (read(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
            {
                continue;
            }

            if (strcmp(ent.name, name) == 0)
            {
                return offset;
            }
            else if (ent.name[0] == 0)
            {
                break; // end of directory entries
            }
        }
        dir_block = fat[dir_block]; // move to next directory block
    }
    return -1;
}

Dir_entry offset_to_directory(int offset)
{
    Dir_entry ent;
    lseek(filesystem_fd, offset, SEEK_SET);
    if (read(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
    {
        memset(&ent, 0, sizeof(Dir_entry));
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to read directory entry");
    }
    return ent;
}

int update_directory(Dir_entry ent, int offset)
{
    lseek(filesystem_fd, offset, SEEK_SET);
    if (write(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to update directory entry");
        return -1;
    }
    return 1;
}

Dir_entry name_to_directory(char *name)
{
    int file_pointer = lookup_directory_offset(name, 1);
    if (file_pointer < 0)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("File not found");
        Dir_entry empty;
        memset(&empty, 0, sizeof(Dir_entry));
        return empty;
    }
    return offset_to_directory(file_pointer);
}

Dir_entry index_to_directory(int index)
{
    Dir_entry empty;
    memset(&empty, 0, sizeof(Dir_entry));

    int fat_size = fat_block_count * block_size;
    int entries_per_block = block_size / sizeof(Dir_entry);
    int dir_block = 1;

    int current_index = 0;
    Dir_entry entry;

    // iterate through all directory blocks
    while (dir_block != LAST_BLOCK)
    {
        for (int i = 0; i < entries_per_block; i++)
        {
            int offset = fat_size + (block_size * (dir_block - 1) + (i * sizeof(Dir_entry)));

            lseek(filesystem_fd, offset, SEEK_SET);
            if (read(filesystem_fd, &entry, sizeof(Dir_entry)) != sizeof(Dir_entry))
            {
                continue;
            }

            if (entry.name[0] == 0)
            {
                return empty; // end of directory entries
            }

            if (current_index == index)
            {
                return entry;
            }

            current_index++;
        }

        dir_block = fat[dir_block]; // move to next directory block
    }

    return empty; // index out of range
}

int get_file_permission(char *name)
{
    int offset = lookup_directory_offset(name, 1);
    if (offset == -1)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("File not found");
        return -1;
    }
    Dir_entry ent = offset_to_directory(offset);
    return ent.perm;
}

void perm_to_rwx(int perm, char *permission_str)
{
    permission_str[0] = (perm & 4) ? 'r' : '-';
    permission_str[1] = (perm & 2) ? 'w' : '-';
    permission_str[2] = (perm & 1) ? 'x' : '-';
    permission_str[3] = '\0';
}

// Helper function to format file info for ls output
void format_file_info(Dir_entry entry, char *buffer)
{
    char *time_str = &(ctime(&entry.mtime)[4]);
    time_str[12] = 0; // truncate time string
    char perm_str[4];
    perm_to_rwx(entry.perm, perm_str);
    if (entry.size == 0)
    {
        sprintf(buffer, "%s %u %s %s\n",
                perm_str, entry.size, time_str, entry.name);
    }
    else
    {
        sprintf(buffer, "%hu %s %u %s %s\n",
                entry.first_block, perm_str, entry.size, time_str, entry.name);
    }
}

// Shared file listing function for both kernel and userland
void fs_list_files(const char *filename, file_info_callback_t callback, void *user_data)
{
    if (!callback)
        return;
    if (!filename)
    {
        // List all files
        int num_files = 0;
        while (1)
        {
            Dir_entry entry = index_to_directory(num_files);
            if (entry.name[0] == 0)
                break; // end of directory entries
            if (entry.name[0] == 1 || entry.name[0] == 2)
            {
                num_files++;
                continue; // skip deleted entries
            }
            callback(&entry, user_data);
            num_files++;
        }
    }
    else
    {
        Dir_entry entry = name_to_directory((char *)filename);
        if (entry.name[0] == 0)
        {
            // Not found: do not call callback
            return;
        }
        callback(&entry, user_data);
    }
}

// helper function to find an empty directory entry slot
static int find_empty_dir_slot(void)
{
    int dir_block = 1;
    int entries_per_block = block_size / sizeof(Dir_entry);
    int fat_size = fat_block_count * block_size;
    Dir_entry temp;

    // look for an empty slot in existing directory blocks
    while (dir_block != LAST_BLOCK)
    {
        for (int i = 0; i < entries_per_block; ++i)
        {
            int pos = fat_size + (block_size * (dir_block - 1) + (i * sizeof(Dir_entry)));

            lseek(filesystem_fd, pos, SEEK_SET);
            if (read(filesystem_fd, &temp, sizeof(Dir_entry)) != sizeof(Dir_entry))
            {
                ERRNO = FILE_SYSTEM;
                f_perror("Failed to read directory entry");
                return -1;
            }

            // found empty or deleted entry slot
            if (temp.name[0] == 0 || temp.name[0] == 1)
            {
                return pos;
            }
        }

        dir_block = fat[dir_block];
    }

    // no empty slots found, allocate new directory block
    int new_block_ind = get_free_block();
    if (new_block_ind == -1)
    {
        ERRNO = NO_SPACE;
        f_perror("No free blocks available");
        return -1;
    }

    int last_dir_block = get_last_block(1);

    // update FAT to link new block
    fat[last_dir_block] = new_block_ind;
    fat[new_block_ind] = LAST_BLOCK;

    // initialize new directory block with zeros
    char zeros[block_size];
    memset(zeros, 0, block_size);
    lseek(filesystem_fd, fat_size + (block_size * (new_block_ind - 1)), SEEK_SET);
    if (write(filesystem_fd, zeros, block_size) != block_size)
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to initialize new directory block");
        return -1;
    }

    // return position of first entry in new block
    return fat_size + (block_size * (new_block_ind - 1));
}

int create_file(char *filename, uint8_t type)
{
    if (type != REGULAR_FILE && type != UNKNOWN_FILE)
    {
        ERRNO = INVALID_OPERATION;
        f_perror("Only regular files supported in core functionality");
        return -1;
    }

    // initialize new directory entry
    Dir_entry ent;
    memset(&ent, 0, sizeof(Dir_entry));

    strncpy(ent.name, filename, 31);
    ent.name[31] = '\0';

    ent.first_block = 0; // no blocks allocated yet
    ent.size = 0;
    ent.type = type;
    ent.perm = 6; // default to read/write
    ent.mtime = time(NULL);

    // find a location for the new directory entry
    int pos = find_empty_dir_slot();
    if (pos == -1)
    {
        return -1;
    }

    // write the directory entry
    lseek(filesystem_fd, pos, SEEK_SET);
    if (write(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to write directory entry");
        return -1;
    }

    return 1;
}

int fs_touch(char *file_name)
{
    int dir_block = 1;
    int entries_per_block = block_size / sizeof(Dir_entry);
    int fat_size = fat_block_count * block_size;
    Dir_entry ent;

    // try to find existing file to update timestamp
    while (dir_block != LAST_BLOCK)
    {
        for (int i = 0; i < entries_per_block; ++i)
        {
            int pos = fat_size + (block_size * (dir_block - 1) + (i * sizeof(Dir_entry)));

            lseek(filesystem_fd, pos, SEEK_SET);
            if (read(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
            {
                continue;
            }

            if (strcmp(ent.name, file_name) == 0)
            {
                ent.mtime = time(NULL);
                lseek(filesystem_fd, pos, SEEK_SET);
                write(filesystem_fd, &ent, sizeof(Dir_entry));
                return 1;
            }
            else if (ent.name[0] == 0)
            {
                break; // end of directory entries
            }
        }
        dir_block = fat[dir_block];
    }

    // file not found, create it
    return create_file(file_name, REGULAR_FILE);
}

int fs_rm(char *file_name)
{
    int dir_block = 1;

    int entry_location = lookup_directory_offset(file_name, dir_block);
    if (entry_location == -1)
    {
        return -1;
    }

    // read directory entry
    Dir_entry ent;
    lseek(filesystem_fd, entry_location, SEEK_SET);
    if (read(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to read directory entry");
        return -1;
    }

    // mark entry as deleted
    ent.name[0] = 1;
    lseek(filesystem_fd, entry_location, SEEK_SET);
    if (write(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to update directory entry");
        return -1;
    }

    // free all blocks used by the file
    if (ent.first_block != 0)
    {
        free_block_chain(ent.first_block);
    }

    return 1;
}

int fs_mv(char *source, char *dest)
{
    // find source
    int entry_location = lookup_directory_offset(source, 1);
    if (entry_location == -1)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("Source file not found");
        return -1;
    }

    Dir_entry src_ent = offset_to_directory(entry_location);

    int dest_location = lookup_directory_offset(dest, 1);
    if (dest_location != -1)
    {
        // destination exists, update it with source's data
        Dir_entry dest_ent = offset_to_directory(dest_location);

        // free blocks used by destination file
        int cur = dest_ent.first_block;
        if (cur != 0 && cur != LAST_BLOCK)
        {
            free_block_chain(cur);
        }

        // copy source file details to destination location
        strncpy(dest_ent.name, dest, 31);
        dest_ent.name[31] = '\0';
        dest_ent.size = src_ent.size;
        dest_ent.first_block = src_ent.first_block;
        dest_ent.type = src_ent.type;
        dest_ent.perm = src_ent.perm;
        dest_ent.mtime = time(NULL);

        if (update_directory(dest_ent, dest_location) == -1)
        {
            return -1;
        }

        // mark source as deleted
        src_ent.name[0] = 1;
        update_directory(src_ent, entry_location);

        return 1;
    }
    else
    {
        // dest doesn't exist, rename source
        strncpy(src_ent.name, dest, 31);
        src_ent.name[31] = '\0';
        src_ent.mtime = time(NULL);

        // update entry
        if (update_directory(src_ent, entry_location) == -1)
        {
            return -1;
        }

        return 1;
    }
}

int read_file(Dir_entry ent, uint8_t *arr, int num_bytes, int buff_pos, int file_pos)
{
    if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("Invalid file entry");
        return -1;
    }

    if (ent.size == 0)
    {
        return 0; // empty file
    }

    if (file_pos >= ent.size)
    {
        return 0; // reading beyond EOF
    }

    int fat_size = fat_block_count * block_size;
    int block_num = ent.first_block;
    int total_bytes_read = 0;

    // skip to the block containing the starting position
    while (file_pos >= block_size)
    {
        block_num = fat[block_num];
        file_pos -= block_size;
    }

    // read data from each block
    while (block_num != LAST_BLOCK && total_bytes_read < num_bytes)
    {
        int bytes_left_in_block = block_size - file_pos;
        int bytes_to_read = num_bytes - total_bytes_read;

        // can read all remaining bytes from current block
        if (bytes_to_read <= bytes_left_in_block)
        {
            lseek(filesystem_fd, fat_size + (block_size * (block_num - 1)) + file_pos, SEEK_SET);
            int bytes = read(filesystem_fd, &arr[buff_pos + total_bytes_read], bytes_to_read);

            if (bytes == -1)
            {
                ERRNO = FILE_SYSTEM;
                f_perror("Read error");
                return -1;
            }

            return total_bytes_read + bytes;
        }

        // read remaining bytes in current block
        lseek(filesystem_fd, fat_size + (block_size * (block_num - 1)) + file_pos, SEEK_SET);
        int bytes = read(filesystem_fd, &arr[buff_pos + total_bytes_read], bytes_left_in_block);

        if (bytes == -1)
        {
            ERRNO = FILE_SYSTEM;
            f_perror("Read error");
            return -1;
        }

        total_bytes_read += bytes;
        file_pos = 0;               // reset position for next block
        block_num = fat[block_num]; // move to next block
    }

    return total_bytes_read;
}

int write_file(Dir_entry ent, uint8_t *arr, int num_bytes, int start)
{
    if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("Invalid file entry");
        return -1;
    }

    int fat_size = fat_block_count * block_size;
    int first_block = ent.first_block;

    // complete file overwrite (starting from position 0)
    if (start == 0 && ent.size > 0)
    {
        int blocks_needed = (num_bytes + block_size - 1) / block_size;
        int blocks_available = 0;
        int cur_block = first_block;

        while (cur_block != LAST_BLOCK)
        {
            blocks_available++;
            cur_block = fat[cur_block];
        }

        // if we need fewer blocks than are available, free extras
        if (blocks_needed < blocks_available)
        {
            cur_block = first_block;
            for (int i = 0; i < blocks_needed - 1; i++)
            {
                cur_block = fat[cur_block];
            }

            // cur_block is now the last block we need
            int next_block = fat[cur_block];
            fat[cur_block] = LAST_BLOCK;
            free_block_chain(next_block);
        }
    }

    // create new file if needed
    if (ent.size == 0)
    {
        first_block = get_free_block();
        if (first_block == -1)
        {
            ERRNO = NO_SPACE;
            f_perror("No free blocks available");
            return -1;
        }

        fat[first_block] = LAST_BLOCK;
        ent.first_block = first_block;
    }

    first_block = ent.first_block;

    // update file size if necessary
    if (start + num_bytes > ent.size)
    {
        ent.size = start + num_bytes;
    }

    ent.mtime = time(NULL);

    // update directory entry
    int offset = lookup_directory_offset(ent.name, 1);
    if (offset == -1)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("File not found in directory");
        return -1;
    }

    lseek(filesystem_fd, offset, SEEK_SET);
    if (write(filesystem_fd, &ent, sizeof(Dir_entry)) != sizeof(Dir_entry))
    {
        ERRNO = FILE_SYSTEM;
        f_perror("Failed to update directory entry");
        return -1;
    }

    int cur_block = first_block;
    int file_position = 0;

    // navigate to the correct block for starting position
    while (file_position + block_size <= start)
    {
        if (fat[cur_block] == LAST_BLOCK)
        {
            // need to allocate new block
            int new_block = get_free_block();
            if (new_block == -1)
            {
                ERRNO = NO_SPACE;
                f_perror("No free blocks available");
                return -1;
            }

            fat[cur_block] = new_block;
            fat[new_block] = LAST_BLOCK;
            cur_block = new_block;
        }
        else
        {
            cur_block = fat[cur_block];
        }

        file_position += block_size;
    }

    int block_offset = start - file_position;
    int bytes_written = 0;

    // write data across blocks as needed
    while (bytes_written < num_bytes)
    {
        int bytes_left_in_block = block_size - block_offset;
        int bytes_to_write = num_bytes - bytes_written;

        // can write all remaining bytes to current block
        if (bytes_to_write <= bytes_left_in_block)
        {
            lseek(filesystem_fd, fat_size + (block_size * (cur_block - 1)) + block_offset, SEEK_SET);
            int result = write(filesystem_fd, &arr[bytes_written], bytes_to_write);

            if (result == -1)
            {
                ERRNO = FILE_SYSTEM;
                f_perror("Write error");
                return -1;
            }

            return num_bytes;
        }

        // write as much as possible to current block
        lseek(filesystem_fd, fat_size + (block_size * (cur_block - 1)) + block_offset, SEEK_SET);
        int result = write(filesystem_fd, &arr[bytes_written], bytes_left_in_block);

        if (result == -1)
        {
            ERRNO = FILE_SYSTEM;
            f_perror("Write error");
            return -1;
        }

        bytes_written += bytes_left_in_block;
        block_offset = 0; // reset offset for next block

        // allocate new block if needed
        if (fat[cur_block] == LAST_BLOCK)
        {
            int new_block = get_free_block();
            if (new_block == -1)
            {
                ERRNO = NO_SPACE;
                f_perror("No free blocks available");
                return bytes_written;
            }

            fat[cur_block] = new_block;
            fat[new_block] = LAST_BLOCK;
            cur_block = new_block;
        }
        else
        {
            cur_block = fat[cur_block];
        }
    }

    return num_bytes;
}

int k_read_at(Dir_entry ent, char *buf, int n, int offset)
{
    if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("Invalid file entry");
        return -1;
    }

    if (ent.size == 0)
    {
        return 0;
    }

    if (offset >= ent.size)
    {
        return 0;
    }

    return read_file(ent, (uint8_t *)buf, n, 0, offset);
}

int k_write_at(Dir_entry ent, const char *str, int n, int offset)
{
    if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2)
    {
        ERRNO = FILE_NOT_FOUND;
        f_perror("Invalid file entry");
        return -1;
    }

    return write_file(ent, (uint8_t *)str, n, offset);
}

int fs_chmod(char *filename, uint8_t new_perm)
{
    int offset = lookup_directory_offset(filename, 1); // Assuming root dir block is 1
    if (offset == -1)
    {
        ERRNO = FILE_NOT_FOUND; // Set FAT-specific errno
        // f_perror("chmod: File not found"); // Optional: internal logging/perror
        return -1;
    }

    Dir_entry ent = offset_to_directory(offset);
    if (ent.name[0] == 0 || ent.name[0] == 1 || ent.name[0] == 2)
    {
        ERRNO = FILE_NOT_FOUND; // Should not happen if lookup succeeded, but check anyway
        return -1;
    }

    ent.perm = new_perm;
    ent.mtime = time(NULL); // Update modification time

    if (update_directory(ent, offset) == -1)
    {
        // update_directory should set ERRNO (e.g., FILE_SYSTEM)
        return -1;
    }

    return 0; // Success
}