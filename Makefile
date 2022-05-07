

application : application.o crypto.o error.o init.o input.o phase.o printText.o security.o
	gcc -o application application.o crypto.o error.o init.o input.o phase.o printText.o security.o -lssl -lcrypto 

application.o :
	gcc -c -o application.o application.c -lssl -lcrypto

crypto.o :
	gcc -c -o crypto.o ./src/security/crypto.c

error.o :
	gcc -c -o error.o ./src/error/error.c

init.o :
	gcc -c -o init.o ./src/sock/init.c -lssl -lcrypto 

input.o :
	gcc -c -o input.o ./src/ui/input.c

phase.o :
	gcc -c -o phase.o ./src/ui/phase.c

printText.o :
	gcc -c -o printText.o ./src/util/printText.c

security.o : 
	gcc -c -o security.o ./src/security/security.c

clean :
	rm *.o application