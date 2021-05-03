SRC = main.c

nooopster: $(SRC)
	$(CC) -o $@ -O2 -pthread -Wall -pedantic -U_FORTIFY_SOURCE $^
	strip $@
