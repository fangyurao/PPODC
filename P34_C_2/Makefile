CC=g++
CFLAGS=-g -std=gnu++11

all: C_2 C_2_ssed_op C_2_sbd C_2_smin_k C_2_smp C_2_smp_precomputed_randomness C_2_ssp_precomputed_randomness C_2_ssed_op_precomputed_randomness C_2_sbd_precomputed_randomness C_2_smin_k_precomputed_randomness C_2_smp_pipelined C_2_ssed_op_pipelined C_2_smin_k_pipelined C_2_sbd_pipelined

C_2: C_2.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2 -lgmp

C_2_ssed_op: C_2_ssed_op.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_ssed_op.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_ssed_op -lgmp

C_2_ssed_op_precomputed_randomness: C_2_ssed_op_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_ssed_op_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_ssed_op_precomputed_randomness -lgmp

C_2_ssed_op_pipelined: C_2_ssed_op_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_ssed_op_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_ssed_op_pipelined -lgmp

C_2_sbd: C_2_sbd.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_sbd.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_sbd -lgmp

C_2_sbd_precomputed_randomness: C_2_sbd_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_sbd_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_sbd_precomputed_randomness -lgmp

C_2_sbd_pipelined: C_2_sbd_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_sbd_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_sbd_pipelined -lgmp

C_2_smin_k: C_2_smin_k.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_smin_k.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_smin_k -lgmp

C_2_smin_k_precomputed_randomness: C_2_smin_k_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_smin_k_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_smin_k_precomputed_randomness -lgmp

C_2_smin_k_pipelined: C_2_smin_k_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_smin_k_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_smin_k_pipelined -lgmp

C_2_smp: C_2_smp.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_smp.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_smp -lgmp

C_2_smp_precomputed_randomness: C_2_smp_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_smp_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_smp_precomputed_randomness -lgmp

C_2_smp_pipelined: C_2_smp_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_smp_pipelined.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_smp_pipelined -lgmp

C_2_ssp_precomputed_randomness: C_2_ssp_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o
	$(CC) -g C_2_ssp_precomputed_randomness.o secure_primitives_C_2.o socket_utility.o paillier.o -o C_2_ssp_precomputed_randomness -lgmp

C_2.o: C_2.cpp
	$(CC) $(CFLAGS) -c C_2.cpp

C_2_ssed_op.o: C_2_ssed_op.cpp
	$(CC) $(CFLAGS) -c C_2_ssed_op.cpp

C_2_ssed_op_precomputed_randomness.o: C_2_ssed_op_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_2_ssed_op_precomputed_randomness.cpp

C_2_ssed_op_pipelined.o: C_2_ssed_op_pipelined.cpp
	$(CC) $(CFLAGS) -c C_2_ssed_op_pipelined.cpp

C_2_sbd.o: C_2_sbd.cpp
	$(CC) $(CFLAGS) -c C_2_sbd.cpp

C_2_sbd_precomputed_randomness.o: C_2_sbd_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_2_sbd_precomputed_randomness.cpp

C_2_sbd_pipelined.o: C_2_sbd_pipelined.cpp
	$(CC) $(CFLAGS) -c C_2_sbd_pipelined.cpp

C_2_smin_k.o: C_2_smin_k.cpp
	$(CC) $(CFLAGS) -c C_2_smin_k.cpp

C_2_smin_k_precomputed_randomness.o: C_2_smin_k_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_2_smin_k_precomputed_randomness.cpp

C_2_smin_k_pipelined.o: C_2_smin_k_pipelined.cpp
	$(CC) $(CFLAGS) -c C_2_smin_k_pipelined.cpp

C_2_smp.o: C_2_smp.cpp
	$(CC) $(CFLAGS) -c C_2_smp.cpp

C_2_smp_precomputed_randomness.o: C_2_smp_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_2_smp_precomputed_randomness.cpp

C_2_smp_pipelined.o: C_2_smp_pipelined.cpp
	$(CC) $(CFLAGS) -c C_2_smp_pipelined.cpp

C_2_ssp_precomputed_randomness.o: C_2_ssp_precomputed_randomness.cpp
	$(CC) $(CFLAGS) -c C_2_ssp_precomputed_randomness.cpp

secure_primitives_C_2.o: secure_primitives_C_2.cpp
	$(CC) $(CFLAGS) -c secure_primitives_C_2.cpp

socket_utility.o: socket_utility.cpp
	$(CC) $(CFLAGS) -c socket_utility.cpp

paillier.o: paillier.c
	$(CC) $(CFLAGS) -c paillier.c

clean:
	rm -f *o C_2 C_2_ssed_op C_2_sbd C_2_smin_k C_2_smp C_2_smp_precomputed_randomness C_2_ssp_precomputed_randomness C_2_ssed_op_precomputed_randomness C_2_sbd_precomputed_randomness C_2_smin_k_precomputed_randomness C_2_smp_pipelined C_2_ssed_op_pipelined C_2_smin_k_pipelined C_2_sbd_pipelined
