CC=g++
CFLAGS=-g -std=gnu++11

all: C_1 C_1_ssed_op C_1_sbd C_1_smin_k C_1_smp C_1_smp_precomputed_randomness C_1_ssp_precomputed_randomness C_1_ssed_op_precomputed_randomness C_1_sbd_precomputed_randomness C_1_smin_k_precomputed_randomness C_1_smp_pipelined C_1_ssed_op_pipelined C_1_smin_k_pipelined C_1_sbd_pipelined

C_1: C_1.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1 -lgmp

C_1_ssed_op: C_1_ssed_op.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_ssed_op.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_ssed_op -lgmp

C_1_ssed_op_precomputed_randomness: C_1_ssed_op_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_ssed_op_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_ssed_op_precomputed_randomness -lgmp

C_1_ssed_op_pipelined: C_1_ssed_op_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_ssed_op_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_ssed_op_pipelined -lgmp

C_1_sbd: C_1_sbd.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_sbd.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_sbd -lgmp

C_1_sbd_precomputed_randomness: C_1_sbd_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_sbd_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_sbd_precomputed_randomness -lgmp

C_1_sbd_pipelined: C_1_sbd_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_sbd_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_sbd_pipelined -lgmp

C_1_smin_k: C_1_smin_k.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) -g C_1_smin_k.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_smin_k -lgmp

C_1_smin_k_precomputed_randomness: C_1_smin_k_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) $(CFLAGS) C_1_smin_k_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_smin_k_precomputed_randomness -lgmp

C_1_smin_k_pipelined: C_1_smin_k_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) $(CFLAGS) C_1_smin_k_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_smin_k_pipelined -lgmp

C_1_smp: C_1_smp.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) $(CFLAGS) C_1_smp.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_smp -lgmp

C_1_smp_precomputed_randomness: C_1_smp_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) $(CFLAGS) C_1_smp_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_smp_precomputed_randomness -lgmp

C_1_smp_pipelined: C_1_smp_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) $(CFLAGS) C_1_smp_pipelined.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_smp_pipelined -lgmp

C_1_ssp_precomputed_randomness: C_1_ssp_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o
	$(CC) $(CFLAGS) C_1_ssp_precomputed_randomness.o secure_primitives_C_1.o socket_utility.o paillier.o -o C_1_ssp_precomputed_randomness -lgmp

C_1.o: C_1.cpp
	$(CC) $(CFLAGS) -c C_1.cpp

C_1_ssed_op.o: C_1_ssed_op.cpp
	$(CC) $(CFLAGS) -c C_1_ssed_op.cpp

C_1_ssed_op_precomputed_randomness.o: C_1_ssed_op_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_1_ssed_op_precomputed_randomness.cpp

C_1_ssed_op_pipelined.o: C_1_ssed_op_pipelined.cpp
	$(CC) $(CFLAGS) -c C_1_ssed_op_pipelined.cpp

C_1_sbd.o: C_1_sbd.cpp
	$(CC) $(CFLAGS) -c C_1_sbd.cpp

C_1_sbd_precomputed_randomness.o: C_1_sbd_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_1_sbd_precomputed_randomness.cpp

C_1_sbd_pipelined.o: C_1_sbd_pipelined.cpp
	$(CC) $(CFLAGS) -c C_1_sbd_pipelined.cpp

C_1_smin_k.o: C_1_smin_k.cpp
	$(CC) $(CFLAGS) -c C_1_smin_k.cpp

C_1_smin_k_precomputed_randomness.o: C_1_smin_k_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_1_smin_k_precomputed_randomness.cpp

C_1_smin_k_pipelined.o: C_1_smin_k_pipelined.cpp
	$(CC) $(CFLAGS) -c C_1_smin_k_pipelined.cpp

C_1_smp.o: C_1_smp.cpp
	$(CC) $(CFLAGS) -c C_1_smp.cpp

C_1_smp_precomputed_randomness.o: C_1_smp_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_1_smp_precomputed_randomness.cpp

C_1_smp_pipelined.o: C_1_smp_pipelined.cpp
	$(CC) $(CFLAGS) -c C_1_smp_pipelined.cpp


C_1_ssp_precomputed_randomness.o: C_1_ssp_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_1_ssp_precomputed_randomness.cpp

secure_primitives_C_1.o: secure_primitives_C_1.cpp
	$(CC) $(CFLAGS) -c secure_primitives_C_1.cpp

socket_utility.o: socket_utility.cpp
	$(CC) $(CFLAGS) -c socket_utility.cpp

paillier.o: paillier.c
	$(CC) $(CFLAGS) -c paillier.c

clean:
	rm -f *o C_1 C_1_ssed_op C_1_sbd C_1_smin_k C_1_smp C_1_smp_precomputed_randomness C_1_ssp_precomputed_randomness C_1_ssed_op_precomputed_randomness C_1_sbd_precomputed_randomness C_1_smin_k_precomputed_randomness C_1_smp_pipelined C_1_ssed_op_pipelined C_1_smin_k_pipelined C_1_sbd_pipelined
