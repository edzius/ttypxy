
CFLAGS = -DHAVE_CONFIG_H -I. -g -O2 -Wall
LDFLAGS = -g -O2 -Wall
LDLIBS = -lutil

TARGET = ttypxy

all: $(TARGET)

clean:
	rm *.o $(TARGET)

$(TARGET): ttypxy.o
	$(CC) $(LDFLAGS) -o $@ $^ ${LDLIBS}

ttypxy.o: ttypxy.c
