# Directories
SRC_DIR = src
BIN_DIR = bin
TEST_DIR = test
LOG_DIR = log

# Compiler and flags
CC = clang-15
CFLAGS = -g3 -gdwarf-4 -pthread -Wall -Werror -Wno-gnu -O0 -g --std=gnu2x
INCLUDES = -I$(SRC_DIR) -I$(SRC_DIR)/fat -I$(SRC_DIR)/kernel -I$(SRC_DIR)/penn_os \
           -I$(SRC_DIR)/penn-shell -I$(SRC_DIR)/util -I$(SRC_DIR)/util/logger -I$(SRC_DIR)/util/types
LDFLAGS = -lm -pthread

# Create necessary directories
$(shell mkdir -p $(BIN_DIR) $(LOG_DIR))

# Source files for each component
FAT_SRC = $(wildcard $(SRC_DIR)/fat/*.c)
KERNEL_SRC = $(wildcard $(SRC_DIR)/kernel/*.c) $(wildcard $(SRC_DIR)/kernel/calls/*.c)
PENNOS_SRC = $(wildcard $(SRC_DIR)/penn_os/*.c)
SHELL_SRC = $(wildcard $(SRC_DIR)/penn-shell/*.c)
UTIL_SRC = $(wildcard $(SRC_DIR)/util/*.c) $(wildcard $(SRC_DIR)/util/logger/*.c)

# Main source files
PENNOS_MAIN = $(SRC_DIR)/penn_os/pennos.c
PENNFAT_MAIN = $(SRC_DIR)/fat/pennfat.c

# Object files (excluding main files)
FAT_OBJ_NO_MAIN = $(filter-out $(PENNFAT_MAIN:.c=.o), $(FAT_SRC:.c=.o))
KERNEL_OBJ = $(KERNEL_SRC:.c=.o)
PENNOS_OBJ = $(PENNOS_SRC:.c=.o)
SHELL_OBJ = $(SHELL_SRC:.c=.o)
UTIL_OBJ = $(UTIL_SRC:.c=.o)

# All objects for PennOS (excluding pennfat.o)
PENNOS_ALL_OBJ = $(FAT_OBJ_NO_MAIN) $(KERNEL_OBJ) $(PENNOS_OBJ) $(SHELL_OBJ) $(UTIL_OBJ)

# All objects for PennFAT (just fat components)
PENNFAT_OBJ = $(PENNFAT_MAIN:.c=.o) $(FAT_OBJ_NO_MAIN)

# Test files
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRC))

# Targets
.PHONY: all clean pennos pennfat tests rebuild

all: pennfat pennos

# Force a complete rebuild
rebuild: clean all

# PennOS executable
pennos: $(BIN_DIR)/pennos

# Build PennOS executable
$(BIN_DIR)/pennos: $(PENNOS_ALL_OBJ)
	@echo "Linking PennOS..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# PennFAT executable 
pennfat: $(BIN_DIR)/pennfat

# Build PennFAT executable
$(BIN_DIR)/pennfat: $(PENNFAT_OBJ)
	@echo "Linking PennFAT..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Test executables
tests: $(TEST_BIN)

$(BIN_DIR)/%: $(TEST_DIR)/%.c $(SRC_DIR)/util/spthread.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(SRC_DIR)/util/spthread.o $(LDFLAGS)

# Rule to compile C files individually
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean target
clean:
	@echo "Cleaning..."
	rm -f $(shell find $(SRC_DIR) -name "*.o")
	rm -f $(BIN_DIR)/*