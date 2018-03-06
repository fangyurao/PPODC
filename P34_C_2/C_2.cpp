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
    cout << "hello world" << endl;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <C_1_hostname> <port> <factorization_file_name>\n", argv[0]);
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

    //do not forget to free the following variables later.

    //declare a_times_b for later use
    paillier_plaintext_t *a_times_b = 0;

    //declare squared_distance for later use
    paillier_plaintext_t *squared_distance = 0;

    //declare lsb for later use
    paillier_plaintext_t *lsb = 0;

    //declare enc_bit for testing smin
    paillier_ciphertext_t *enc_bit = paillier_create_enc_zero();
    paillier_ciphertext_t *enc_s_min = paillier_create_enc_zero();

    //paillier_plaintext_t *s_min = 0;
    paillier_plaintext_t *s_min = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(s_min->m);

    //declare bit for later use
    paillier_plaintext_t *bit = 0;

    //declare x_gt_y for later use
    paillier_plaintext_t *x_gt_y = 0;

    //declare enc_s_min and s_min for testing smin

    //declare Gamma_i and decrypted_Gamma_i for testing smin_k
    paillier_ciphertext_t *Gamma_i = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_Gamma_i = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(decrypted_Gamma_i->m);

    //declare u_leq_v for later use
    paillier_plaintext_t *u_leq_v = 0;

    //while (1)
    // if command_to_receive_from_C_1 == PERMISSION_TO_DISCONNECT
    //  close(sockfd_with_C_1);
    //  break;
    //
    // if command_to_receive_from_C_1 == WAIT_FOR_FURTHER_INSTRUCTION
    //  command_to_receive_from_C_1 <= socket_receive_command_C_1_to_C_2()
    //
    // if command_to_receive_from_C_1 == SSED_OP
    //  exec SSED_OP
    //  command_to_receive_from_C_1 <= socket_receive_command_C_1_to_C_2()
    //
    // if command_to_receive_from_C_1 == SMIN
    //  exec SMIN
    //  command_to_receive_from_C_1 <= socket_receive_command_C_1_to_C_2()
    //
    // if command_to_receive_from_C_1 == SMP
    //  exec SMP
    //  command_to_receive_from_C_1 <= socket_receive_command_C_1_to_C_2()
    long i;
    long j;
    int num_smp = 20;
    int num_vectors = 100;
    int num_dimensions = 5;
    int num_slsb = 100;

    int num_sbd = 20;
    int bit_length = 7;

    int num_gt = 100;

    int num_smin = 20;

    int num_dimensions_ssed_op = 5;

    int num_sinv = 20;

    int num_clusters = 4;
    int num_attributes = 10;

    long k = 10;

    paillier_ciphertext_t *enc_negative_one = paillier_create_enc_zero();
    mpz_sub(enc_negative_one->c, pk->n_squared, pk->n);
    mpz_add_ui(enc_negative_one->c, enc_negative_one->c, 1);

    paillier_plaintext_t *negative_one = 0;
    negative_one = paillier_dec(negative_one, pk, sk, enc_negative_one);
    gmp_printf("negative_one: %Zd\n", negative_one);

    while (1) {
        //we might not need this case
        if (command_to_receive == PERMISSION_TO_DISCONNECT) {
            printf("C_1 allows to disconnect\n");
            close(sockfd_with_C_1);
            break;
        }

        if (command_to_receive == SMP) {

            for (i = 0; i < num_smp; i = i + 1) {
                //perform SMP with the corresponding C_1
                execute_smp_C_2(sockfd_with_C_1, pk, sk);

                //try to receive the result from the corresponding C_1 to check if the result is correct
                paillier_ciphertext_t *enc_a_times_b = 0;
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_a_times_b);

                a_times_b = paillier_dec(a_times_b, pk, sk, enc_a_times_b);
                gmp_printf("a_times_b[%d]: %Zd\n", i, a_times_b->m);
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;
        }

        if (command_to_receive == SSED) {

            for (i = 0; i < num_vectors; i = i + 1) {
                //perform SSED with the corresponding C_1
                execute_ssed_C_2(sockfd_with_C_1, pk, sk, num_dimensions);

                //try to receive the result from the corresponding C_1 to check if the result is correct
                paillier_ciphertext_t *enc_squared_distance = 0;
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_squared_distance);

                squared_distance = paillier_dec(squared_distance, pk, sk, enc_squared_distance);
                gmp_printf("squared_distance[%d]: %Zd\n", i, squared_distance->m);
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;
        }

        if (command_to_receive == SSED_OP) {

            execute_ssed_op_C_2(sockfd_with_C_1, pk, sk, num_dimensions_ssed_op);

            //check if the result is correct with C_1
            paillier_ciphertext_t *enc_squared_distance = 0;
            socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_squared_distance);

            squared_distance = paillier_dec(squared_distance, pk, sk, enc_squared_distance);
            gmp_printf("squared_distance: %Zd\n", squared_distance->m);

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == SLSB) {

            for (i = 0; i < num_slsb; i = i + 1) {
                //perform SLSB with the corresponding C_1
                execute_slsb_C_2(sockfd_with_C_1, pk, sk);

                //try to receive the result from the corresponding C_1 to check if the result is correct
                paillier_ciphertext_t *enc_lsb = 0;
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_lsb);

                lsb = paillier_dec(lsb, pk, sk, enc_lsb);
                gmp_printf("lsb[%d]: %Zd\n", i, lsb->m);
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == SBD) {

            for (i = 0; i < num_sbd; i = i + 1) {
                //perform SBD with the corresponding C_1
                execute_sbd_C_2(sockfd_with_C_1, pk, sk, bit_length);

                //the code for testing the correctness of the protocol
                paillier_ciphertext_t *enc_bit = 0;

                printf("a_s[%ld]: ", i);
                for (j = bit_length - 1; j >= 0; j = j - 1) {
                    socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_bit);
                    bit = paillier_dec(bit, pk, sk, enc_bit);
                    gmp_printf("%Zd", bit);
                }
                printf("\n");
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == GT) {

            for (i = 0; i < num_gt; i = i + 1) {

                //perform SBD with the corresponding C_1
                execute_sbd_C_2(sockfd_with_C_1, pk, sk, bit_length);
                execute_sbd_C_2(sockfd_with_C_1, pk, sk, bit_length);

                execute_gt_C_2(sockfd_with_C_1, pk, sk, bit_length);

                //the code for testing the correctness of the protocol
                paillier_ciphertext_t *enc_x_gt_y = 0;
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_x_gt_y);
                x_gt_y = paillier_dec(x_gt_y, pk, sk, enc_x_gt_y);
                gmp_printf("x_gt_y: %Zd\n", x_gt_y);
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;
        }

        if (command_to_receive == PERM) {

            //test the functionality of permutation/inverse permutation first
            int num_plaintexts = 5;
            paillier_ciphertext_t *permuted_enc_x = 0;

            paillier_ciphertext_t **permuted_enc_x_s = initialize_paillier_ciphertexts_1_d(num_plaintexts);

            for (i = 0; i < num_plaintexts; i = i + 1) {
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &(permuted_enc_x_s[i]));
                gmp_printf("permuted_enc_x_s[%ld]: %Zd\n\n", i, permuted_enc_x_s[i]->c);
            }

            for (i = 0; i < num_plaintexts; i = i + 1) {
                socket_send_paillier_ciphertext_t(sockfd_with_C_1, permuted_enc_x_s[i]);
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;
        }

        if (command_to_receive == SMIN) {

            //perform SBD followed by SMIN with the corresponding C_1
            for (i = 0; i < num_smin; i = i + 1) {
                execute_sbd_C_2(sockfd_with_C_1, pk, sk, bit_length);
                execute_sbd_C_2(sockfd_with_C_1, pk, sk, bit_length);
                printf("%ld-th sbd done\n", i);

                execute_smin_C_2(sockfd_with_C_1, pk, sk, bit_length);

                //to test if smin protocol is correct
                printf("min(u, v): ");
                for (j = bit_length - 1; j >= 0; j = j - 1) {

                    socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_bit);
                    bit = paillier_dec(bit, pk, sk, enc_bit);
                    gmp_printf("%Zd", bit);

                }
                printf("\n");

                printf("s_min(u,v): ");
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_s_min);

                s_min = paillier_dec(s_min, pk, sk, enc_s_min);
                gmp_printf("%Zd\n", s_min->m);

                printf("%ld-th smin done\n\n", i);
            }

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == SMIN_K) {

            //perform SBD "k" times with the corresponding C_1
            //to produce "k" encrypted and bit-decomposed distances
            for (i = 0; i < k; i = i + 1) {

                execute_sbd_C_2(sockfd_with_C_1, pk, sk, bit_length);

                //test if the result of sbd is correct
                printf("\n");
                printf("d[%ld]: ", i);
                for (j = bit_length - 1; j >= 0; j = j - 1) {

                    socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_bit);
                    bit = paillier_dec(bit, pk, sk, enc_bit);
                    gmp_printf("%Zd", bit);

                }
                printf("\n");

                printf("%ld-th sbd done\n", i);
            }

            //perform smin_k with the corresponding C_1
            execute_smin_k_C_2(sockfd_with_C_1, pk, sk, k, bit_length);

            //to test if smin_k protocol is correct
            for (i = 0; i < k; i = i + 1) {

                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &Gamma_i);
                decrypted_Gamma_i = paillier_dec(decrypted_Gamma_i, pk, sk, Gamma_i);
                gmp_printf("decrypted_Gamma[%ld]: %Zd\n", i, decrypted_Gamma_i);

            }

            printf("smin_k is done\n");

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == SINV) {

            for (i = 0; i < num_sinv; i = i + 1) {

                //perform sinv with the corresponding C_1
                execute_sinv_C_2(sockfd_with_C_1, pk, sk);

                //check if the result of sinv is correct
                paillier_ciphertext_t *enc_x = paillier_create_enc_zero();
                paillier_ciphertext_t *enc_x_inv = paillier_create_enc_zero();

                paillier_plaintext_t *x = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
                mpz_init(x->m);
                paillier_plaintext_t *x_inv = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
                mpz_init(x_inv->m);
                paillier_plaintext_t *x_times_x_inv = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
                mpz_init(x_times_x_inv->m);

                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_x);
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &enc_x_inv);

                x = paillier_dec(x, pk, sk, enc_x);
                x_inv = paillier_dec(x_inv, pk, sk, enc_x_inv);
                mpz_mul(x_times_x_inv->m, x->m, x_inv->m);
                mpz_mod(x_times_x_inv->m, x_times_x_inv->m, pk->n);
                gmp_printf("x: %Zd\n", x->m);
                gmp_printf("x_inv: %Zd\n", x_inv->m);
                gmp_printf("x_times_x_inv: %Zd\n\n", x_times_x_inv->m);

            }

            printf("sinv is done\n");

            //try to receive the next command, then continue
            socket_receive_command_C_1_to_C_2(sockfd_with_C_1, &command_to_receive);
            continue;

        }

        if (command_to_receive == SPCI) {

            //perform spci with the corresponding C_1
            execute_spci_C_2(sockfd_with_C_1, pk, sk, num_clusters, num_attributes);

            //check if the results of spic are correct
            paillier_ciphertext_t *b_prime_spci = paillier_create_enc_zero();
            paillier_plaintext_t *product_cluster_cardinalities = 
                (paillier_plaintext_t *) malloc(sizeof(paillier_plaintext_t));
            mpz_init(product_cluster_cardinalities->m);

            socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &b_prime_spci);
            product_cluster_cardinalities = paillier_dec(product_cluster_cardinalities, 
                                                         pk, sk, b_prime_spci);
            gmp_printf("decrypted_b_prime: %Zd\n", product_cluster_cardinalities->m);

            paillier_ciphertext_t **b_h_s_spci = initialize_paillier_ciphertexts_1_d(num_clusters);
            paillier_plaintext_t **decrypted_b_h_s_spci = initialize_paillier_plaintexts_1_d(num_clusters);
            for (i = 0; i < num_clusters; i = i + 1) {
                socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &(b_h_s_spci[i]));
                decrypted_b_h_s_spci[i] = paillier_dec(decrypted_b_h_s_spci[i], pk, sk, b_h_s_spci[i]);
                gmp_printf("decrypted_b_h_s[%ld]: %Zd\n", i, decrypted_b_h_s_spci[i]->m);
            }
            
            paillier_ciphertext_t ***a_prime_h_s = initialize_paillier_ciphertexts_2_d(num_clusters, 
                                                                                        num_attributes);
            paillier_plaintext_t ***decrypted_a_prime_h_s = initialize_paillier_plaintexts_2_d(num_clusters, 
                                                                                    num_attributes);
            for (i = 0; i < num_clusters; i = i + 1) {
                for (j = 0; j < num_attributes; j = j + 1) {
                    socket_receive_paillier_ciphertext_t(sockfd_with_C_1, &(a_prime_h_s[i][j]));
                    decrypted_a_prime_h_s[i][j] = 
                        paillier_dec(decrypted_a_prime_h_s[i][j], pk, sk, a_prime_h_s[i][j]);
                    gmp_printf("decrypted_a_prime_h_s[%ld][%ld]: %Zd\n", i, j, decrypted_a_prime_h_s[i][j]->m);
                }
            }

            printf("spci is done\n");

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

    return (0);
}

//paillier_plaintext_t*** initialize_paillier_plaintexts_2_d(int in_num_rows, int in_num_columns) {
//
//    paillier_plaintext_t ***plaintexts;
//    plaintexts = (paillier_plaintext_t ***)malloc(sizeof(paillier_plaintext_t **) * in_num_rows);
//
//    int i;
//    for (i = 0; i < in_num_rows; i = i + 1) {
//        plaintexts[i] = initialize_paillier_plaintexts_1_d(in_num_columns);
//    }
//
//    return plaintexts;
//}
//
//paillier_ciphertext_t*** initialize_paillier_ciphertexts_2_d(int in_num_rows, int in_num_columns) {
//
//    paillier_ciphertext_t ***ciphertexts;
//    ciphertexts = (paillier_ciphertext_t ***)malloc(sizeof(paillier_ciphertext_t **) * in_num_rows);
//
//    int i;
//    for (i = 0; i < in_num_rows; i = i + 1) {
//        ciphertexts[i] = initialize_paillier_ciphertexts_1_d(in_num_columns);
//    }
//
//    return ciphertexts;
//
//}
