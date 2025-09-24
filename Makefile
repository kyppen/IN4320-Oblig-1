CC = gcc
CFLAGS = -std=c23 -Wall -Wextra -g

SRC = src/mipd.c \
      src/common.c \
      src/mip.c \
      src/ping_client.c \
      src/ping_sever.c \
      src/mip_arp.c \
      src/linked_list.c \
      src/pdu.c

OBJ = $(SRC:.c=.o)

TARGET = MIP_DAEMON

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
