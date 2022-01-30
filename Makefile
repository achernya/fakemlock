CC=gcc
CFLAGS=-Wall -Wextra -Werror
OBJECTS=$(patsubst %.c, %.o, $(wildcard *.c))
HEADERS=$(wildcard *.h)
TARGET= demo

all: $(TARGET)
.PHONY: all

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

clean:
	rm -rf $(TARGET) $(OBJECTS)
