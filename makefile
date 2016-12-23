INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) serv.c -o serv -lssl -lcrypto -ldl
	gcc -I$(INC) -L$(LIB) cli.c -o cli -lssl -lcrypto -ldl
clean:
	rm -rf *~ serv cli
