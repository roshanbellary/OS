#include "err.h"
#include "fd_table.h"
#include "fat_core.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void initialize_fd_table(FD_Table* fd_table) {
    fd_table->head = NULL;
}

FD_Node* lookup_add_position(FD_Table* fd_table) {
    FD_Node* cur = fd_table->head;
    int expected_fd = 3;
    if (!cur || cur->fd != expected_fd) {
        return NULL; 
    }
    while (cur->next) {
        if (cur->next->fd != expected_fd + 1) {
            return cur;
        }
        cur = cur->next;
        expected_fd++;
    }
    return cur;
}

FD_Node* add_fd(FD_Table* fd_table, char* name, int mode) {
    FD_Node* cur = fd_table->head;
    while (cur) {
        if (strcmp(cur->name, name) == 0) {
            if (cur->mode != 0 && mode != 0) {
                // Write-write conflict
                ERRNO = FILE_SYSTEM;
                f_perror("Write-write conflict");
                return NULL;
            }
            break;
        }
        cur = cur->next;
    }
    FD_Node* node = malloc(sizeof(FD_Node));
    if (!node) {
        ERRNO = MEMORY_ERROR;
        f_perror("Memory allocation failed");
        return NULL;
    }

    node->mode = mode;
    node->name = name;
    int entry_offset = lookup_directory_offset(name, 1);
    Dir_entry entry = offset_to_directory(entry_offset);

    if (mode == 0) {
        node->size = entry.size;
        node->offset = 0;
        if (entry.name[0] == 0) {
            free(node);
            return NULL;
        }
    } else if (mode == 1) {
        node->size = 0;
        node->offset = 0;
        if (entry.name[0] == 0) {
            create_file(name, REGULAR_FILE);
        }
    } else if (mode == 2) {
        node->size = entry.size;
        node->offset = entry.size;
        if (entry.name[0] == 0) {
            free(node);
            return NULL;
        }
    } else {
        free(node);
        return NULL;
    }
    FD_Node* prev = lookup_add_position(fd_table);

    if (!prev) {
        if (!fd_table->head) {
            node->fd = 3;
            node->next = NULL;
            fd_table->head = node;
        } else {
            node->fd = 3;
            node->next = fd_table->head;
            fd_table->head = node;
        }
    } else {
        if (prev->next) {
            node->fd = prev->fd + 1;
            node->next = prev->next;
        } else {
            node->fd = prev->fd + 1;
            node->next = NULL;
        }
        prev->next = node;
    }
    return node;
}

FD_Node* remove_fd(FD_Table* fd_table, int fd) {
    FD_Node* prev = NULL;
    FD_Node* node = fd_table->head;
    while (node && node->fd != fd) {
        prev = node;
        node = node->next;
    }
    if (!node) {
        return NULL;
    }
    if (node == fd_table->head) {
        fd_table->head = node->next;
    } else if (prev) {
        prev->next = node->next;
    }
    return node;
}

FD_Node* lookup_fd(FD_Table* fd_table, int fd) {
    FD_Node* cur = fd_table->head;
    while (cur && cur->fd != fd) {
        cur = cur->next;
    }
    return cur;
}