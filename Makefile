TARGET=fit_aligner

OBJS=fit_aligner.o

CFLAGS=-Wall -Werror -Os
LDFLAGS=-lfdt

all: $(TARGET)

$(TARGET): $(OBJS)

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
