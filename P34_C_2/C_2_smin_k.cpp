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

#define DEBUG_SMIN_K

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

int main(int argc, char *argv[]) {
    cout << "C_2_smin_k starts" << endl;

    if (argc != 7) {
        fprintf(stderr, "usage: %s <C_1_hostname> <port> <factorization_file_name> <num_smin_k> <k> <bit_length>\n", argv[0]);
        exit(0);
    }

    int sockfd_with_C_1;
    sockfd_with_C_1 = create_socket_and_connect(argv[1], argv[2]);

    //after the connection is established,
    //(1) read pk/sk from "factorization.txt" and then
    //(2) send pk to the corresponding C_1
    paillier_pubkey_t *pk = (paillier_pubkey_t *)malloc(sizeof(paillier_pubkey_t));
    paillier_prvkey_t *sk = (paillier_prvkey_t *)malloc(sizeof(paillier_prvkey_t));
    paillier_keygen_from_file(&pk, &sk, argv[3]);

    socket_send_paillier_pubkey_t(sockfd_with_C_1, pk);

    int num_bytes_received;
    unsigned int command_to_receive;

    num_bytes_received = socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
    if (num_bytes_received == 0) {
        printf("server hung up\n");
    } else if (num_bytes_received < 0) {
        perror("before main while-loop: ");
    }

    //in the following, we declare Gamma_i and decrypted_Gamma_i for testing smin_k
#ifdef DEBUG_SMIN_K
    paillier_ciphertext_t *Gamma_i = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_Gamma_i = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(decrypted_Gamma_i->m);
#endif
    //in the above, we declare Gamma_i and decrypted_Gamma_i for testing smin_k

    long i, j, s;

    int num_smin_k = atoi(argv[4]);//2

    long k = atoi(argv[5]);//8
    int bit_length = atoi(argv[6]);//10

    while (1) {
        //we might not need this case
        if (command_to_receive == PERMISSION_TO_DISCONNECT) {
            printf("C_1 allows to disconnect\n");
            close(sockfd_with_C_1);
            break;
        }

        if (command_to_receive == SMIN_K) {

            for (s = 0; s < num_smin_k; s = s + 1) {

                //perform smin_k with the corresponding C_1
                execute_smin_k_C_2(sockfd_with_C_1, pk, sk, k, bit_length);

#ifdef DEBUG_SMIN_K
                //to test if smin_k protocol is correct
                for (i = 0; i < k; i = i + 1) {

                    socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &Gamma_i);
                    decrypted_Gamma_i = paillier_dec(decrypted_Gamma_i, pk, sk, Gamma_i);
                    gmp_printf("decrypted_Gamma[%ld]: %Zd\n", i, decrypted_Gamma_i);

                }
#endif

                printf("%ld-th smin_k done\n", s);

            }

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
#ifdef DEBUG_SMIN_K
    paillier_freeciphertext(Gamma_i);
    paillier_freeplaintext(decrypted_Gamma_i);
#endif


    return (0);
}
