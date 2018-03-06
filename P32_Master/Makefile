CC=g++
CFLAGS=-g -std=gnu++11

all: master master_ssed_op master_sbd master_smin_k master_smp

master: master.o socket_utility.o paillier.o
	$(CC) master.o socket_utility.o paillier.o -o master -lgmp

master_ssed_op: master_ssed_op.o socket_utility.o paillier.o
	$(CC) master_ssed_op.o socket_utility.o paillier.o -o master_ssed_op -lgmp

master_sbd: master_sbd.o socket_utility.o paillier.o
	$(CC) master_sbd.o socket_utility.o paillier.o -o master_sbd -lgmp

master_smin_k: master_smin_k.o socket_utility.o paillier.o
	$(CC) master_smin_k.o socket_utility.o paillier.o -o master_smin_k -lgmp

master_smp: master_smp.o socket_utility.o paillier.o
	$(CC) master_smp.o socket_utility.o paillier.o -o master_smp -lgmp

master.o: master.cpp
	$(CC) $(CFLAGS) -c master.cpp

master_ssed_op.o: master_ssed_op.cpp
	$(CC) $(CFLAGS) -c master_ssed_op.cpp

master_sbd.o: master_sbd.cpp
	$(CC) $(CFLAGS) -c master_sbd.cpp

master_smin_k.o: master_smin_k.cpp
	$(CC) $(CFLAGS) -c master_smin_k.cpp

master_smp.o: master_smp.cpp
	$(CC) $(CFLAGS) -c master_smp.cpp

socket_utility.o: socket_utility.cpp
	$(CC) $(CFLAGS) -c socket_utility.cpp

paillier.o: paillier.c
	$(CC) $(CFLAGS) -c paillier.c

clean:
	rm -f *o master master_ssed_op master_sbd master_smin_k master_smp
