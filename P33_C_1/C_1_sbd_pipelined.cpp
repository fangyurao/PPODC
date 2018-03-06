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

#include <gmp.h>
#include "paillier.h"
#include "socket_utility.h"
#include "secure_primitives_C_1.h"

#define BACKLOG 10

//#define DEBUG_PREPARE_PAILLIER_PLAINTEXTS_1_D
//#define DEBUG_ENCRYPT_PAILLIER_PLAINTEXTS_1_D
//#define DEBUG_PREPARE_PAILLIER_PLAINTEXT_VECTORS
//#define DEBUG_ENCRYPT_PAILLIER_PLAINTEXT_VECTORS

#define DEBUG_SBD

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

extern long long time_spent_on_C_1_global;

int main(int argc, char *argv[]) {

    cout << "C_1_sbd_precomputed_randomness starts" << endl;

    if (argc != 7) {
        fprintf(stderr, "usage: %s <master_hostname> <master_port> <client_id> <C_1_port> <num_sbd> <bit_length>\n", argv[0]);
        exit(0);
    }

    time_spent_on_C_1_global = 0;

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

    //one_half is used in sbd
    paillier_plaintext_t *one_half;
    one_half = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(one_half->m);
    mpz_divexact_ui(one_half->m, pk->n_plusone, 2);

    //the following statements are for debugging purpose
    printf("pk->bits: %d\n", pk->bits);
    gmp_printf("pk->n: %Zd\n", pk->n);
    gmp_printf("pk->n_plusone: %Zd\n", pk->n_plusone);
    gmp_printf("pk->n_squared: %Zd\n", pk->n_squared);
    gmp_printf("one_half->m: %Zd\n", one_half->m);
    //the above statements are for debugging purpose

    int num_sbd = atoi(argv[5]); //20
    int bit_length = atoi(argv[6]); //7

    long i, j;

    //in the following, we prepare some necessary plaintexts and ciphertexts to test sbd_pipelined
    paillier_ciphertext_t ***enc_a_s_bits = initialize_paillier_ciphertexts_2_d(num_sbd, bit_length);

    paillier_plaintext_t *a = (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));
    mpz_init(a->m);
    mpz_set_ui(a->m, 34);

    paillier_ciphertext_t *enc_a = paillier_create_enc_zero();
    paillier_enc(enc_a, pk, a, paillier_get_rand_devurandom);

    paillier_ciphertext_t **enc_a_s = initialize_paillier_ciphertexts_1_d(num_sbd);
    for (i = 0; i < num_sbd; i = i + 1) {
        mpz_set(enc_a_s[i]->c, enc_a->c);
    }

    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(bit_length);
    paillier_ciphertext_t **enc_r_s = initialize_paillier_ciphertexts_1_d(bit_length);
    for (i = 0; i < bit_length; i = i + 1) {
        generate_random_plaintext(r_s[i], pk, paillier_get_rand_devurandom);
        paillier_enc(enc_r_s[i], pk, r_s[i], paillier_get_rand_devurandom);
    }

    paillier_plaintext_t ***r_s_sbd = initialize_paillier_plaintexts_2_d(num_sbd, bit_length);
    paillier_ciphertext_t ***enc_r_s_sbd = initialize_paillier_ciphertexts_2_d(num_sbd, bit_length);
    for (i = 0; i < num_sbd; i = i + 1) {
        for (j = 0; j < bit_length; j = j + 1) {
            mpz_set(r_s_sbd[i][j]->m, r_s[j]->m);
            mpz_set(enc_r_s_sbd[i][j]->c, enc_r_s[j]->c);
        }
    }
    //in the above, we prepare some necessary plaintexts and ciphertexts to test sbd_pipelined

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

        if (command_to_receive == SBD) {

            //tell the corresponding C_2 it is time to perform SLSB together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SBD);

            execute_sbd_pipelined_C_1(enc_a_s_bits,
                                      enc_a_s,
                                      pk, one_half,
                                      bit_length, sockfd_with_C_2,
                                      r_s_sbd,
                                      enc_r_s_sbd,
                                      num_sbd);

            printf("time_spent_on_C_1_global (ms): %lld\n", time_spent_on_C_1_global / 1000);
            time_spent_on_C_1_global = 0;

#ifdef DEBUG_SBD
            for (i = 0; i < num_sbd; i = i + 1) {
                for (j = bit_length - 1; j >= 0; j = j - 1) {
                    socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_a_s_bits[i][j]);
                }
            }
#endif

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

    //clean-up
    free_paillier_ciphertexts_2_d(num_sbd, bit_length, enc_a_s_bits);
    paillier_freeplaintext(a);
    paillier_freeciphertext(enc_a);
    free_paillier_ciphertexts_1_d(num_sbd, enc_a_s);
    free_paillier_plaintexts_1_d(bit_length, r_s);
    free_paillier_ciphertexts_1_d(bit_length, enc_r_s);
    free_paillier_plaintexts_2_d(num_sbd, bit_length, r_s_sbd);
    free_paillier_ciphertexts_2_d(num_sbd, bit_length, enc_r_s_sbd);
    paillier_freeplaintext(one_half);

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

