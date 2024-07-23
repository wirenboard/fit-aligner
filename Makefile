PREFIX=/usr

TARGET=fit-aligner

OBJS=fit-aligner.o

CFLAGS=-Wall -Werror -Os
LDFLAGS=-lfdt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

install:
	install -Dm0755 $(TARGET) -t $(DESTDIR)$(PREFIX)/bin

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean install
