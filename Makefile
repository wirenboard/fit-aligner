TARGET=fit-aligner

OBJS=fit-aligner.o

CFLAGS=-Wall -Werror -Os
LDFLAGS=-lfdt

all: $(TARGET)

$(TARGET): $(OBJS)

install:
	mkdir -p $(DESTDIR)/usr/bin

	install -m 0755 $(TARGET) $(DESTDIR)/usr/bin/fit-aligner

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean install
