all: start start_ssed_op start_sbd start_smin_k start_smp start_ssed_op_precomputed_randomness start_sbd_precomputed_randomness start_smin_k_precomputed_randomness start_smp_precomputed_randomness start_ssed_op_pipelined start_smin_k_pipelined start_smp_pipelined start_sbd_pipelined

start: start.c
	gcc start.c -o start -lssh

start_ssed_op: start_ssed_op.c
	gcc start_ssed_op.c -o start_ssed_op -lssh

start_ssed_op_precomputed_randomness: start_ssed_op_precomputed_randomness.c
	gcc start_ssed_op_precomputed_randomness.c -o start_ssed_op_precomputed_randomness -lssh

start_ssed_op_pipelined: start_ssed_op_pipelined.c
	gcc start_ssed_op_pipelined.c -o start_ssed_op_pipelined -lssh

start_sbd: start_sbd.c
	gcc start_sbd.c -o start_sbd -lssh

start_sbd_precomputed_randomness: start_sbd_precomputed_randomness.c
	gcc start_sbd_precomputed_randomness.c -o start_sbd_precomputed_randomness -lssh

start_sbd_pipelined: start_sbd_pipelined.c
	gcc start_sbd_pipelined.c -o start_sbd_pipelined -lssh

start_smin_k: start_smin_k.c
	gcc start_smin_k.c -o start_smin_k -lssh

start_smin_k_precomputed_randomness: start_smin_k_precomputed_randomness.c
	gcc start_smin_k_precomputed_randomness.c -o start_smin_k_precomputed_randomness -lssh

start_smin_k_pipelined: start_smin_k_pipelined.c
	gcc start_smin_k_pipelined.c -o start_smin_k_pipelined -lssh

start_smp: start_smp.c
	gcc start_smp.c -o start_smp -lssh

start_smp_precomputed_randomness: start_smp_precomputed_randomness.c
	gcc start_smp_precomputed_randomness.c -o start_smp_precomputed_randomness -lssh

start_smp_pipelined: start_smp_pipelined.c
	gcc start_smp_pipelined.c -o start_smp_pipelined -lssh

clean:
	rm -f start start_ssed_op start_sbd start_smin_k start_smp start_ssed_op_precomputed_randomness start_sbd_precomputed_randomness start_smin_k_precomputed_randomness start_smp_precomputed_randomness start_ssed_op_pipelined start_smin_k_pipelined start_smp_pipelined start_sbd_pipelined
