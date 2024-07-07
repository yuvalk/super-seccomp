CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -D_GNU_SOURCE
LDFLAGS = 

TARGET = seccomp_unotify
SRCS = seccomp_unotify.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
