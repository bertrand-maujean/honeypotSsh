all: honeypotSsh replay

honeypotSsh: honeypotSsh.c
	gcc -g -o honeypotSsh honeypotSsh.c

replay: replay.c
	gcc -g -o replay replay.c

clean:
	rm replay
	rm honeypotSsh
	
