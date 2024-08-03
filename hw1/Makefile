CC = gcc
CFLAGS =  -Wall -g -D_GNU_SOURCE -fPIC
LDFLAGS = -shared -lunwind -lunwind-x86_64 -ldl
TARGET = sandbox
%.o: %.c
	$(CC) -c $(CFLAGS) $<
sandbox.so: sandbox.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET).o $(TARGET).so *.log *.html 
	