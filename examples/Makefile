CC=gcc
CFLAGS=-I.

program: program.o
	$(CC) -o $@ program.o $(CFLAGS)

program.o: program.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm program *.o
