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

#include "socket_utility.h"
#include "secure_primitives_C_2.h"

#define BACKLOG 10

#define DEBUG_SBD

//requests related
#define REQUEST_FOR_TASK 0

//command related
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

using namespace std;

extern long long time_spent_on_C_2_global;

int main(int argc, char *argv[]) {
    cout << "C_2_sbd_precomputed_randomness starts" << endl;

    if (argc != 6) {
        fprintf(stderr, "usage: %s <C_1_hostname> <port> <factorization_file_name> <num_sbd> <bit_length>\n", argv[0]);
        exit(0);
    }

    time_spent_on_C_2_global = 0;

    long i, j;

    int num_sbd = atoi(argv[4]); //20
    int bit_length = atoi(argv[5]); //7



    //after the connection is established,
    //(1) read pk/sk from "factorization.txt" and then
    //(2) send pk to the corresponding C_1
    paillier_pubkey_t *pk = (paillier_pubkey_t *)malloc(sizeof(paillier_pubkey_t));
    paillier_prvkey_t *sk = (paillier_prvkey_t *)malloc(sizeof(paillier_prvkey_t));
    paillier_keygen_from_file(&pk, &sk, argv[3]);

    //declare bit for later use
    paillier_plaintext_t *bit = 0;
    paillier_ciphertext_t *enc_bit = 0;

    //in the following, prepare enc_zero_s needed in sbd_precom_rand
    paillier_plaintext_t *zero = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(zero->m);
    mpz_set_ui(zero->m, 0);

    paillier_ciphertext_t **enc_zero_s = initialize_paillier_ciphertexts_1_d(bit_length);
    for (i = 0; i < bit_length; i = i + 1) {
        paillier_enc(enc_zero_s[i], pk, zero, paillier_get_rand_devurandom);
    }


    paillier_ciphertext_t ***enc_zero_s_sbd = initialize_paillier_ciphertexts_2_d(num_sbd, bit_length);
    for (i = 0; i < num_sbd; i = i + 1) {
        for (j = 0; j < bit_length; j = j + 1) {
            mpz_set(enc_zero_s_sbd[i][j]->c, enc_zero_s[j]->c);
        }
    }
    //in the above, prepare enc_zero_s needed in sbd_precom_rand

    int sockfd_with_C_1;
    sockfd_with_C_1 = create_socket_and_connect(argv[1], argv[2]);
    socket_send_paillier_pubkey_t(sockfd_with_C_1, pk);

    int num_bytes_received;
    unsigned int command_to_receive;

    num_bytes_received = socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
    if (num_bytes_received == 0) {
        printf("server hung up\n");
    } else if (num_bytes_received < 0) {
        perror("before main while-loop: ");
    }

    while (1) {
        //we might not need this case
        if (command_to_receive == PERMISSION_TO_DISCONNECT) {
            printf("C_1 allows to disconnect\n");
            close(sockfd_with_C_1);
            break;
        }

        if (command_to_receive == SBD) {

            execute_sbd_pipelined_C_2(sockfd_with_C_1, pk,
                                      sk, bit_length,
                                      enc_zero_s_sbd,
                                      num_sbd);

            printf("time_spent_on_C_2_global (ms): %lld\n", time_spent_on_C_2_global / 1000);
            time_spent_on_C_2_global = 0;

#ifdef DEBUG_SBD
            for (i = 0; i < num_sbd; i = i + 1) {
                printf("a_s[%ld]: ", i);
                for (j = bit_length - 1; j >= 0; j = j - 1) {
                    socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_bit);
                    bit = paillier_dec(bit, pk, sk, enc_bit);
                    gmp_printf("%Zd", bit->m);
                }
                printf("\n");
            }
#endif

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == WAIT_FOR_FURTHER_INSTRUCTION) {
            num_bytes_received =
                socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            if (num_bytes_received == 0) {
                printf("C_1 hung up\n");
                break;
            } else if (num_bytes_received < 0) {
                perror("in main while-loop: ");
            }
        }
    }

    printf("C_2 after while-loop\n");

    //clean-up
#ifdef DEBUG_SBD
    paillier_freeplaintext(bit);
    paillier_freeciphertext(enc_bit);
#endif

    paillier_freeplaintext(zero);
    //free_paillier_ciphertexts_1_d(bit_length, enc_zero_s);

    return (0);
}
