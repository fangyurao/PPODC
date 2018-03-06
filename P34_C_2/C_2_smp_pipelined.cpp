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

//#define DEBUG_SMP

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
    cout << "C_2_smp_pipelined starts" << endl;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <C_1_hostname> <port> <factorization_file_name> <num_smp>\n", argv[0]);
        exit(0);
    }

    time_spent_on_C_2_global = 0;

    int sockfd_with_C_1;
    sockfd_with_C_1 = create_socket_and_connect(argv[1], argv[2]);

    //after the connection is established,
    //(1) read pk/sk from "factorization.txt" and then
    //(2) send pk to the corresponding C_1
    paillier_pubkey_t *pk = (paillier_pubkey_t *)malloc(sizeof(paillier_pubkey_t));
    paillier_prvkey_t *sk = (paillier_prvkey_t *)malloc(sizeof(paillier_prvkey_t));
    paillier_keygen_from_file(&pk, &sk, argv[3]);

    int num_smp = atoi(argv[4]); //20

    socket_send_paillier_pubkey_t(sockfd_with_C_1, pk);

    long i, j;

    int num_bytes_received;
    unsigned int command_to_receive;

    num_bytes_received = socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
    if (num_bytes_received == 0) {
        printf("server hung up\n");
    } else if (num_bytes_received < 0) {
        perror("before main while-loop: ");
    }

    //declare a_times_b for later use
    paillier_plaintext_t *a_times_b = 0;
    paillier_ciphertext_t *enc_a_times_b = 0;

    paillier_plaintext_t **a_times_b_s = initialize_paillier_plaintexts_1_d(num_smp);
    paillier_ciphertext_t **enc_a_times_b_s = initialize_paillier_ciphertexts_1_d(num_smp);

    

    //create an encryption of zero to test smp_pipelined
    paillier_plaintext_t *zero = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(zero->m);
    mpz_set_ui(zero->m, 0);

    paillier_ciphertext_t **enc_zero_s = initialize_paillier_ciphertexts_1_d(num_smp);

    paillier_ciphertext_t *enc_zero = paillier_create_enc_zero(); //might not be useful later
    paillier_enc(enc_zero, pk, zero, paillier_get_rand_devurandom); //might not be useful later

    for (i = 0; i < num_smp; i = i + 1) {
        paillier_enc(enc_zero_s[i], pk, zero, paillier_get_rand_devurandom);
    }

    while (1) {
        //we might not need this case
        if (command_to_receive == PERMISSION_TO_DISCONNECT) {
            printf("C_1 allows to disconnect\n");
            close(sockfd_with_C_1);
            break;
        }

        if (command_to_receive == SMP) {

//            for (i = 0; i < num_smp; i = i + 1) {
//                //perform SMP with the corresponding C_1
//                execute_smp_precomputed_randomness_C_2(sockfd_with_C_1, pk, sk, enc_zero);
//
//#ifdef DEBUG_SMP
//                //try to receive the result from the corresponding C_1 to check if the result is correct
//                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_a_times_b);
//
//
//                a_times_b = paillier_dec(a_times_b, pk, sk, enc_a_times_b);
//                gmp_printf("a_times_b[%d]: %Zd\n", i, a_times_b->m);
//#endif
//
//                printf("%ld-th smp done\n", i);
//            }

            execute_smp_pipelined_C_2(sockfd_with_C_1, pk, sk, enc_zero_s, num_smp);

            printf("time_spent_on_C_2_global (ms): %lld\n", time_spent_on_C_2_global / 1000);
            time_spent_on_C_2_global = 0;

#ifdef  DEBUG_SMP
            for (i = 0; i < num_smp; i = i + 1) {

                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &(enc_a_times_b_s[i]));

                a_times_b_s[i] = paillier_dec(a_times_b_s[i], pk, sk, enc_a_times_b_s[i]);

                gmp_printf("a_times_b[%ld]: %Zd\n", i, a_times_b_s[i]->m);

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
#ifdef DEBUG_SMP
    //paillier_freeplaintext(a_times_b);
    //paillier_freeciphertext(enc_a_times_b);
#endif

    paillier_freeplaintext(zero);
    paillier_freeciphertext(enc_zero);

    return (0);
}
