#include <iostream>

#include <stdio.h>//perror
#include <string.h>//memset
#include <unistd.h>//close

#include <sys/socket.h>//socketlen_t
#include <netinet/in.h>//socketaddr_in
#include <stdlib.h>//exit,

#include <sys/types.h>//addrinfo
#include <netdb.h>//addrinfo
#include <arpa/inet.h>//inet_ntop

#include <sys/time.h>//gettimeofday

#include <gmp.h>
#include "paillier.h"
#include "socket_utility.h"
#include "secure_primitives_C_1.h"

#define BACKLOG 10

//#define DEBUG_PREPARE_PAILLIER_PLAINTEXTS_1_D
//#define DEBUG_ENCRYPT_PAILLIER_PLAINTEXTS_1_D
//#define DEBUG_PREPARE_PAILLIER_PLAINTEXT_VECTORS
//#define DEBUG_ENCRYPT_PAILLIER_PLAINTEXT_VECTORS

#define DEBUG_SMP

//requests related
#define REQUEST_FOR_TASK 0
#define TASK_IS_DONE 1

//command (to C_2) related
#define PERMISSION_TO_DISCONNECT 0
#define WAIT_FOR_FURTHER_INSTRUCTION 1
#define SSED_OP 2
#define PERM 3
#define SMP 4
#define DUMMY_TASK 5
#define SSED 6
#define SLSB 7
#define SBD 8
#define GT 9
#define SMIN 10
#define SMIN_K 11
#define SINV 12
#define SPCI 13
#define SETC 14
#define RECEIVE_CLUSTER_INFO 15
#define RECEIVE_SETC_INFO 16

//client status related
#define WAITING 0
#define DOING_SSED_OP 1
#define DOING_PERM 2
#define DOING_SMP 3
#define DOING_DUMMY_TASK 4
#define DOING_SSED 5
#define DOING_SLSB 6
#define DOING_SBD 7
#define DOING_GT 8
#define DOING_SMIN 9
#define DOING_SMIN_K 10
#define DOING_SINV 11
#define DOING_SPCI 12
#define DOING_SETC 13

using namespace std;

//functions to initialize/encrypt plaintexts for testing SMP
void prepare_paillier_plaintexts_1_d(paillier_plaintext_t **out_plaintexts,
                                     int in_num_plaintexts, int in_starting_value);



paillier_ciphertext_t** encrypt_paillier_plaintexts_1_d(int in_num_plaintexts,
                                                        paillier_plaintext_t **in_plaintexts,
                                                        paillier_pubkey_t *in_pk);

//functions for initialize/encrypt vectors for testing SSED
void prepare_paillier_plaintext_vectors(paillier_plaintext_t ***in_vectors,
                                        int in_num_vectors, int in_num_dimensions);
paillier_ciphertext_t*** encrypt_paillier_plaintext_vectors(int in_num_vectors, int in_num_dimensions,
                                                            paillier_plaintext_t ***in_vectors,
                                                            paillier_pubkey_t *in_pk);



int main(int argc, char *argv[]) {

    cout << "C_1_smp_precomputed_randomness starts" << endl;

    if (argc != 6) {
        fprintf(stderr, "usage: %s <master_hostname> <master_port> <client_id> <C_1_port> <num_smp>\n", argv[0]);
        exit(0);
    }

    int client_id;
    client_id = atoi(argv[3]);

    //(1) listen for incoming connection request from the corresponding C_2 with pk/sk
    int sockfd_with_C_2;

    sockfd_with_C_2 = create_socket_and_listen(argv[4]);

    gmp_randstate_t state;
    init_rand_for_permutation(state, sizeof(long));

    //now try to receive pk information from the corresponding C_2
    paillier_pubkey_t *pk = 0;
    socket_receive_paillier_pubkey_t(sockfd_with_C_2, &pk);

    //the following statements are for debugging purpose
    printf("pk->bits: %d\n", pk->bits);
    gmp_printf("pk->n: %Zd\n", pk->n);
    gmp_printf("pk->n_plusone: %Zd\n", pk->n_plusone);
    gmp_printf("pk->n_squared: %Zd\n", pk->n_squared);
    //the above statements are for debugging purpose

    long i, j;

    //in the following, we create an array of plaintexts and the corresponding ciphertexts
    int num_smp = atoi(argv[5]);//20

    paillier_plaintext_t *a = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(a->m);
    mpz_set_ui(a->m, 22);

    paillier_plaintext_t *b = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(b->m);
    mpz_set_ui(b->m, 22);

    paillier_ciphertext_t *enc_a = paillier_create_enc_zero();
    paillier_ciphertext_t *enc_b = paillier_create_enc_zero();

    paillier_enc(enc_a, pk, a, paillier_get_rand_devurandom);
    paillier_enc(enc_b, pk, b, paillier_get_rand_devurandom);
    //in the above, we create an array of plaintexts and the corresponding ciphertexts

    //in the following, we create some precomputed randomness to test smp_precomputed
    paillier_plaintext_t *r_a = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));
    paillier_plaintext_t *r_b = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));
    paillier_plaintext_t *r_a_times_r_b = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));

    paillier_plaintext_t *negative_r_a = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));
    paillier_plaintext_t *negative_r_b = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));
    paillier_plaintext_t *negative_r_a_times_r_b = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));

    paillier_ciphertext_t *enc_r_a = paillier_create_enc_zero();
    paillier_ciphertext_t *enc_r_b = paillier_create_enc_zero();
    paillier_ciphertext_t *enc_negative_r_a_times_r_b = paillier_create_enc_zero();

    mpz_init(r_a->m);
    mpz_init(r_b->m);
    mpz_init(r_a_times_r_b->m);

    mpz_init(negative_r_a->m);
    mpz_init(negative_r_b->m);
    mpz_init(negative_r_a_times_r_b->m);

    generate_random_plaintext(r_a, pk, paillier_get_rand_devurandom);
    generate_random_plaintext(r_b, pk, paillier_get_rand_devurandom);

    mpz_mul(r_a_times_r_b->m, r_a->m, r_b->m);
    mpz_mod(r_a_times_r_b->m, r_a_times_r_b->m, pk->n);

    mpz_sub(negative_r_a->m, pk->n, r_a->m);
    mpz_sub(negative_r_b->m, pk->n, r_b->m);
    mpz_sub(negative_r_a_times_r_b->m, pk->n, r_a_times_r_b->m);

    paillier_enc(enc_r_a, pk, r_a, paillier_get_rand_devurandom);
    paillier_enc(enc_r_b, pk, r_b, paillier_get_rand_devurandom);
    paillier_enc(enc_negative_r_a_times_r_b, pk, negative_r_a_times_r_b, paillier_get_rand_devurandom);
    //in the above, we create some precomputed randomness to test smp_precomputed

    //initialize enc_a_times_b for smp protocol
    paillier_ciphertext_t *enc_a_times_b = paillier_create_enc_zero();

    //tell C_2 to wait for further instruction for now
    socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

    //(2) connect to the master node
    int sockfd_with_master;
    sockfd_with_master = create_socket_and_connect(argv[1], argv[2]);
    //(2).a send the id to the master node
    socket_send_int(sockfd_with_master, (unsigned int)client_id);

    //(3) perform the clustering task until it is done
    //send a request for a job to be assigned by the master node
    unsigned int command_to_receive;
    socket_send_request_C_1_to_master(sockfd_with_master, REQUEST_FOR_TASK);

    while (1) {

        //try to recv a task assigned by the master node
        socket_receive_command_master_to_C_1(sockfd_with_master, &command_to_receive);
        printf("command_to_receive: %d\n", command_to_receive);

        if (command_to_receive == SMP) {
            //tell the corresponding C_2 it is time to perform SMP together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SMP);

            for (i = 0; i < num_smp; i = i + 1) {

                execute_smp_precomputed_randomness_C_1(enc_a_times_b, enc_a, enc_b, pk, sockfd_with_C_2, negative_r_a, negative_r_b, enc_r_a, enc_r_b, enc_negative_r_a_times_r_b);

#ifdef DEBUG_SMP
                //send enc_a_times_b to C_2 and let C_2 check if the result is correct
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_a_times_b);
#endif

            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);

            continue;
        }

        if (command_to_receive == PERMISSION_TO_DISCONNECT) {
            printf("master node allows disconnection\n");

            //do we need to send to C_2 the permission to disconnect?
            close(sockfd_with_C_2); //to see if we need further steps

            close(sockfd_with_master);
            break;
        }

        if (command_to_receive == WAIT_FOR_FURTHER_INSTRUCTION) {
            printf("need to wait for further instruction\n");
            continue;
        }

    }

    //clean-up for SMP
    paillier_freeciphertext(enc_a_times_b);

    paillier_freeplaintext(a);
    paillier_freeplaintext(b);
    paillier_freeciphertext(enc_a);
    paillier_freeciphertext(enc_b);

    paillier_freeplaintext(r_a);
    paillier_freeplaintext(r_b);
    paillier_freeplaintext(r_a_times_r_b);

    paillier_freeplaintext(negative_r_a);
    paillier_freeplaintext(negative_r_b);
    paillier_freeplaintext(negative_r_a_times_r_b);

    paillier_freeciphertext(enc_r_a);
    paillier_freeciphertext(enc_r_b);
    paillier_freeciphertext(enc_negative_r_a_times_r_b);
    printf("client node, after while-loop\n");

    return (0);
}

void prepare_paillier_plaintexts_1_d(paillier_plaintext_t **out_plaintexts,
                                     int in_num_plaintexts, int in_starting_value) {

    int i;
    for (i = 0; i < in_num_plaintexts; i = i + 1) {
        mpz_set_ui(out_plaintexts[i]->m, (i + in_starting_value));
    }

}

void prepare_paillier_plaintext_vectors(paillier_plaintext_t ***in_vectors,
                                        int in_num_vectors, int in_num_dimensions) {
    int i;
    int j;
    for (i = 0; i < in_num_vectors; i = i + 1) {
        for (j = 0; j < in_num_dimensions; j = j + 1) {
            mpz_set_ui(in_vectors[i][j]->m, (i * in_num_vectors + j));
        }
    }
}

paillier_ciphertext_t*** encrypt_paillier_plaintext_vectors(int in_num_vectors, int in_num_dimensions,
                                                            paillier_plaintext_t ***in_vectors,
                                                            paillier_pubkey_t *in_pk) {
    paillier_ciphertext_t ***enc_vectors;

    enc_vectors = (paillier_ciphertext_t ***)malloc(sizeof(paillier_ciphertext_t **) * in_num_vectors);

    int i;
    int j;
    for (i = 0; i < in_num_vectors; i = i + 1) {
        enc_vectors[i] = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
        for (j = 0; j < in_num_dimensions; j = j + 1) {
            enc_vectors[i][j] = paillier_create_enc_zero();
        }
    }

    for (i = 0; i < in_num_vectors; i = i + 1) {
        for (j = 0; j < in_num_dimensions; j = j + 1) {
            paillier_enc(enc_vectors[i][j], in_pk, in_vectors[i][j], paillier_get_rand_devurandom);
        }
    }

    return enc_vectors;
}

paillier_ciphertext_t** encrypt_paillier_plaintexts_1_d(int in_num_plaintexts,
                                                        paillier_plaintext_t **in_plaintexts,
                                                        paillier_pubkey_t *in_pk) {
    paillier_ciphertext_t **ciphertexts;
    ciphertexts = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_plaintexts);

    int i;
    for (i = 0; i < in_num_plaintexts; i = i + 1) {
        ciphertexts[i] = paillier_create_enc_zero();
    }

    for (i = 0; i < in_num_plaintexts; i = i + 1) {
        paillier_enc(ciphertexts[i], in_pk, in_plaintexts[i], paillier_get_rand_devurandom);
    }

    return ciphertexts;
}

