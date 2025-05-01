PROG = pennfat

CC = clang-15
CFLAGS = -Wall -Werror -g
CPPFLAGS = -DNDEBUG

BIN_DIR = bin

CORE_SRCS = fat_core.c fd_table.c fat_kernel.c pennfat.c err.c
HEADERS = fat_core.h fd_table.h fat_kernel.h pennfat.h err.h

OBJS = $(patsubst %.c,$(BIN_DIR)/%.o,$(CORE_SRCS))

# Create bin directory if it doesn't exist
$(shell mkdir -p $(BIN_DIR))

.PHONY: all clean rebuild

all: $(BIN_DIR)/$(PROG)

# Main program target
$(BIN_DIR)/$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Pattern rule for object files
$(BIN_DIR)/%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	$(RM) -r $(BIN_DIR)

# Rebuild from scratch
rebuild: clean all

# Debug info
debug:
	@echo "Program: $(PROG)"
	@echo "Sources: $(CORE_SRCS)"
	@echo "Headers: $(HEADERS)"
	@echo "Objects: $(OBJS)"

# Run the program (if needed)
run: all
	./$(BIN_DIR)/$(PROG)

.PRECIOUS: $(BIN_DIR)/%.o