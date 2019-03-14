# Set compiler to use
CC=gcc
CFLAGS=-g -I/usr/include/libxml2 -I. #-fpermissive
LDFLAGS=-L/usr/lib/x86_64-linux-gnu -lxml2 -lpthread
DEPS=
OBJS=
DEBUG=0

all:: vbd

vbd: vbd.o vcpu.o vmem.o elf.o xml.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean: 
	rm -f *.exe *.o *~ *.log *.stackdump vbd dbcfs

