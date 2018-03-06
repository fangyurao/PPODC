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

//  mpz_t even;
//  mpz_t odd;
//  mpz_init(even);
//  mpz_init(odd);
//  //mpz_set_str(even, "16", 10);
//  mpz_set_str(odd, "34", 10);
//
//  //gmp_printf("mpz_tstbit(%Zd, 0): %d\n", even, mpz_tstbit(even, 0));
//  gmp_printf("mpz_tstbit(%Zd, 0): %d\n", odd, mpz_tstbit(odd, 0));
//  gmp_printf("mpz_tstbit(%Zd, 1): %d\n", odd, mpz_tstbit(odd, 1));
//  gmp_printf("mpz_tstbit(%Zd, 2): %d\n", odd, mpz_tstbit(odd, 2));
//  gmp_printf("mpz_tstbit(%Zd, 3): %d\n", odd, mpz_tstbit(odd, 3));
//  gmp_printf("mpz_tstbit(%Zd, 4): %d\n", odd, mpz_tstbit(odd, 4));
//  gmp_printf("mpz_tstbit(%Zd, 5): %d\n", odd, mpz_tstbit(odd, 5));
//
//  return 0;

    cout << "hello world" << endl;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <master_hostname> <master_port> <client_id> <C_1_port>\n", argv[0]);
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

    //one_half is used in sbd
    paillier_plaintext_t *one_half;
    one_half = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(one_half->m);
    mpz_divexact_ui(one_half->m, pk->n_plusone, 2);

    //enc_negative_one is used in smin
    paillier_ciphertext_t *enc_negative_one = paillier_create_enc_zero();
    mpz_sub(enc_negative_one->c, pk->n_squared, pk->n);
    mpz_add_ui(enc_negative_one->c, enc_negative_one->c, 1);

    //the following statements are for debugging purpose
    printf("pk->bits: %d\n", pk->bits);
    gmp_printf("pk->n: %Zd\n", pk->n);
    gmp_printf("pk->n_plusone: %Zd\n", pk->n_plusone);
    gmp_printf("pk->n_squared: %Zd\n", pk->n_squared);
    gmp_printf("one_half->m: %Zd\n", one_half->m);
    //the above statements are for debugging purpose

    //in the following, we create an array of plaintexts and the corresponding ciphertexts
    int num_smp;
    num_smp = 20;

    paillier_plaintext_t **a_s;
    paillier_plaintext_t **b_s;

    a_s = initialize_paillier_plaintexts_1_d(num_smp);
    b_s = initialize_paillier_plaintexts_1_d(num_smp);
    prepare_paillier_plaintexts_1_d(a_s, num_smp, 3);
    prepare_paillier_plaintexts_1_d(b_s, num_smp, 0);

    long i, j;

#ifdef DEBUG_PREPARE_PAILLIER_PLAINTEXTS_1_D
    for (i = 0; i < num_smp; i = i + 1) {
        gmp_printf("a_s[%d]: %Zd\n", i, a_s[i]->m);
    }
    for (i = 0; i < num_smp; i = i + 1) {
        gmp_printf("b_s[%d]: %Zd\n", i, b_s[i]->m);
    }
#endif

    paillier_ciphertext_t **enc_a_s;
    paillier_ciphertext_t **enc_b_s;

    enc_a_s = encrypt_paillier_plaintexts_1_d(num_smp, a_s, pk);
    enc_b_s = encrypt_paillier_plaintexts_1_d(num_smp, b_s, pk);

#ifdef DEBUG_ENCRYPT_PAILLIER_PLAINTEXTS_1_D
    for (i = 0; i < num_smp; i = i + 1) {
        gmp_printf("enc_a_s[%d]: %Zd\n", i, enc_a_s[i]->c);
    }
    for (i = 0; i < num_smp; i = i + 1) {
        gmp_printf("enc_b_s[%d]: %Zd\n", i, enc_b_s[i]->c);
    }
#endif
    //in the above, we create an array of plaintexts and the corresponding ciphertexts

    //in the following, we create an array of vectors and the corresponding ciphertexts
    int num_vectors = 100;

    int num_dimensions = 5;

    paillier_plaintext_t ***vector_x_s;
    paillier_plaintext_t ***vector_y_s;

    vector_x_s = initialize_paillier_plaintexts_2_d(num_vectors, num_dimensions);
    vector_y_s = initialize_paillier_plaintexts_2_d(num_vectors, num_dimensions);

    printf("after initialize_paillier_plaintext_vectors\n");

    prepare_paillier_plaintext_vectors(vector_x_s, num_vectors, num_dimensions);

    printf("after prepare_paillier_plaintext_vectors\n");

    paillier_ciphertext_t ***enc_vector_x_s;
    paillier_ciphertext_t ***enc_vector_y_s;

    enc_vector_x_s = encrypt_paillier_plaintext_vectors(num_vectors, num_dimensions, vector_x_s, pk);
    enc_vector_y_s = encrypt_paillier_plaintext_vectors(num_vectors, num_dimensions, vector_y_s, pk);

#ifdef DEBUG_PREPARE_PAILLIER_PLAINTEXT_VECTORS
    for (i = 0; i < num_vectors; i = i + 1) {
        for (j = 0; j < num_dimensions; j = j + 1) {
            gmp_printf("vector_x_s[%d][%d]: %Zd\n", i, j, vector_x_s[i][j]->m);
        }
    }
#endif

#ifdef DEBUG_ENCRYPT_PAILLIER_PLAINTEXT_VECTORS
    for (i = 0; i < num_vectors; i = i + 1) {
        for (j = 0; j < num_dimensions; j = j + 1) {
            gmp_printf("enc_vector_x_s[%d][%d]: %Zd\n", i, j, enc_vector_x_s[i][j]->c);
        }
    }
#endif
    //in the above, we create an array of vectors and the corresponding ciphertexts

    //in the following, we declare and define variables needed in testing slsb
    //we reuse a_s, enc_a_s created previously to test the correctness of our slsb protocol
    int num_slsb = 100;
    //in the above, we declare and define variables needed in testing slsb

    //in the following, we declare and define variables needed in testing sbd
    //we reuse enc_a_s created previously to test the correctness of our sbd protocol
    int num_sbd = 20;
    int bit_length = 7;

    //paillier_ciphertext_t **enc_bit_s;
    paillier_ciphertext_t **enc_a_bits;
    paillier_ciphertext_t **enc_b_bits;
    enc_a_bits = initialize_paillier_ciphertexts_1_d(bit_length);
    enc_b_bits = initialize_paillier_ciphertexts_1_d(bit_length);
    //in the above, we declare and define variables needed in testing sbd

    //in the following, we declare and define variables needed in testing gt
    int num_gt = 100;

    paillier_plaintext_t **x_bits = initialize_paillier_plaintexts_1_d(3);
    paillier_plaintext_t **y_bits = initialize_paillier_plaintexts_1_d(3);

    mpz_init_set_ui(x_bits[2]->m, 1);
    mpz_init_set_ui(x_bits[1]->m, 0);
    mpz_init_set_ui(x_bits[0]->m, 1);

    mpz_init_set_ui(y_bits[2]->m, 0);
    mpz_init_set_ui(y_bits[1]->m, 0);
    mpz_init_set_ui(y_bits[0]->m, 0);

    paillier_ciphertext_t **enc_x_bits = initialize_paillier_ciphertexts_1_d(3);
    paillier_ciphertext_t **enc_y_bits = initialize_paillier_ciphertexts_1_d(3);

    for (i = 2; i >= 0; i = i - 1) {
        paillier_enc(enc_x_bits[i], pk, x_bits[i], paillier_get_rand_devurandom);
        paillier_enc(enc_y_bits[i], pk, y_bits[i], paillier_get_rand_devurandom);
    }
    //in the above, we declare and define variables needed in testing gt

    //in the following, we declare and define variables needed in testing smin
    int num_smin = 20;

    paillier_ciphertext_t **enc_min_bits = initialize_paillier_ciphertexts_1_d(bit_length);
    //in the above, we declare and define variables needed in testing smin

    //in the following, we declare and define variables needed in testing smin_k
    long k = 10;

    paillier_ciphertext_t ***enc_d_s_bits = initialize_paillier_ciphertexts_2_d(k, bit_length);

    paillier_ciphertext_t **Gamma_s = initialize_paillier_ciphertexts_1_d(k);
    //in the above, we declare and define variables needed in testing smin_k

    //in the following, we declare and define variables needed in testing ssed_op
    int num_dimensions_ssed_op = 5;
    paillier_plaintext_t **t_i = initialize_paillier_plaintexts_1_d(num_dimensions_ssed_op);
    mpz_set_ui(t_i[0]->m, 10);
    mpz_set_ui(t_i[1]->m, 20);
    mpz_set_ui(t_i[2]->m, 30);
    mpz_set_ui(t_i[3]->m, 40);
    mpz_set_ui(t_i[4]->m, 50);

    paillier_ciphertext_t **enc_t_i = initialize_paillier_ciphertexts_1_d(num_dimensions_ssed_op);
    for (i = 0; i < num_dimensions_ssed_op; i = i + 1) {
        paillier_enc(enc_t_i[i], pk, t_i[i], paillier_get_rand_devurandom);
    }

    paillier_plaintext_t *product_cluster_cardinalities =
        (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(product_cluster_cardinalities->m);
    mpz_set_ui(product_cluster_cardinalities->m, 2000);

    paillier_ciphertext_t *b_prime = paillier_create_enc_zero();
    paillier_enc(b_prime, pk, product_cluster_cardinalities, paillier_get_rand_devurandom);

    paillier_plaintext_t **decrypted_a_prime_h = initialize_paillier_plaintexts_1_d(num_dimensions_ssed_op);
    mpz_set_ui(decrypted_a_prime_h[0]->m, 10);
    mpz_set_ui(decrypted_a_prime_h[1]->m, 10);
    mpz_set_ui(decrypted_a_prime_h[2]->m, 10);
    mpz_set_ui(decrypted_a_prime_h[3]->m, 10);
    mpz_set_ui(decrypted_a_prime_h[4]->m, 10);

    paillier_ciphertext_t **a_prime_h = initialize_paillier_ciphertexts_1_d(num_dimensions_ssed_op);
    for (i = 0; i < num_dimensions_ssed_op; i = i + 1) {
        paillier_enc(a_prime_h[i], pk, decrypted_a_prime_h[i], paillier_get_rand_devurandom);
    }
    //in the above, we declare and define variables needed in testing ssed_op

    //in the following, we declare and define variables needed in testing generate_random_nonzero_plaintext
    paillier_plaintext_t **nonzero_r_s = initialize_paillier_plaintexts_1_d(20);
    for (i = 0; i < 20; i = i + 1) {
        generate_random_nonzero_plaintext(nonzero_r_s[i], pk, paillier_get_rand_devurandom);
        //gmp_printf("nonzero_r_s[%ld]: %Zd\n", i, nonzero_r_s[i]->m);
    }
    //in the above, we declare and define variables needed in testing generate_random_nonzero_plaintext

    //in the following, we declare and define variables needed in testing sinv protocol
    //we resue enc_a_s generated previously.
    int num_sinv = 20;

    paillier_ciphertext_t **enc_a_inv_s = initialize_paillier_ciphertexts_1_d(num_sinv);
    //in the above, we declare and define variables needed in testing sinv protocol

    //in the following, we declare and define variables needed in testing spci protocol
    int num_clusters = 4;
    int num_attributes = 10;

    paillier_plaintext_t **cluster_cardinalities = initialize_paillier_plaintexts_1_d(num_clusters);
    paillier_ciphertext_t **enc_cluster_cardinalities = initialize_paillier_ciphertexts_1_d(num_clusters);

    mpz_set_ui(cluster_cardinalities[0]->m, 10);
    mpz_set_ui(cluster_cardinalities[1]->m, 20);
    mpz_set_ui(cluster_cardinalities[2]->m, 30);
    mpz_set_ui(cluster_cardinalities[3]->m, 40);

    for (i = 0; i < num_clusters; i = i + 1) {

        paillier_enc(enc_cluster_cardinalities[i], pk, cluster_cardinalities[i], paillier_get_rand_devurandom);

    }

    paillier_plaintext_t ***lambda_s = initialize_paillier_plaintexts_2_d(num_clusters, num_attributes);
    paillier_ciphertext_t ***enc_lambda_s = initialize_paillier_ciphertexts_2_d(num_clusters, num_attributes);

    for (i = 0; i < num_clusters; i = i + 1) {

        for (j = 0; j < num_attributes; j = j + 1) {

            mpz_set_ui(lambda_s[i][j]->m, 3);
            paillier_enc(enc_lambda_s[i][j], pk, lambda_s[i][j], paillier_get_rand_devurandom);

        }

    }

    paillier_ciphertext_t *b_prime_spci = paillier_create_enc_zero();
    paillier_ciphertext_t **b_s_spci = initialize_paillier_ciphertexts_1_d(num_clusters);
    paillier_ciphertext_t ***a_prime_s_spci = initialize_paillier_ciphertexts_2_d(num_clusters, num_attributes);
    //in the above, we declare and define variables needed in testing spci protocol

    //in the following, we declare and define variables needed for sending cluster information to master (as pair 0)
    int num_dummy_cluster_elements = 100;

    paillier_plaintext_t **dummy_sent_cluster_element_s = initialize_paillier_plaintexts_1_d(num_dummy_cluster_elements);
    paillier_ciphertext_t **enc_sent_dummy_cluster_element_s = initialize_paillier_ciphertexts_1_d(num_dummy_cluster_elements);

    for (i = 0; i < num_dummy_cluster_elements; i = i + 1) {
        mpz_set_ui(dummy_sent_cluster_element_s[i]->m, i);
        paillier_enc(enc_sent_dummy_cluster_element_s[i], pk, dummy_sent_cluster_element_s[i], paillier_get_rand_devurandom);
    }

    paillier_ciphertext_t **enc_received_dummy_cluster_element_s = 
        initialize_paillier_ciphertexts_1_d(num_dummy_cluster_elements);
    //in the above, we declare and define variables needed for sending cluster information to master (as pair 0)


    //in the following, we declare and define variables needed for sending setc information to master (as other pairs)
    int num_dummy_setc_elements = 100;

    paillier_plaintext_t **dummy_sent_setc_element_s = initialize_paillier_plaintexts_1_d(num_dummy_setc_elements);
    paillier_ciphertext_t **enc_dummy_sent_setc_element_s = initialize_paillier_ciphertexts_1_d(num_dummy_setc_elements);

    for (i = 0; i < num_dummy_setc_elements; i = i + 1) {
        mpz_set_ui(dummy_sent_setc_element_s[i]->m, i);
        paillier_enc(enc_dummy_sent_setc_element_s[i], pk, dummy_sent_setc_element_s[i], paillier_get_rand_devurandom);
    }

    paillier_ciphertext_t **enc_received_dummy_setc_element_s = 
        initialize_paillier_ciphertexts_1_d(num_dummy_setc_elements);
    //in the above, we declare and define variables needed for sending setc information to master (as other pairs)

    //initialize enc_a_times_b for smp protocol
    paillier_ciphertext_t *enc_a_times_b = paillier_create_enc_zero();

    //initialize enc_squared_distance for ssed protocol
    paillier_ciphertext_t *enc_squared_distance = paillier_create_enc_zero();

    //initialize enc_lsb for slsb protocol
    paillier_ciphertext_t *enc_lsb = paillier_create_enc_zero();

    //initialize enc_x_gt_y for gt protocol
    paillier_ciphertext_t *enc_x_gt_y = paillier_create_enc_zero();

    //initialize enc_s_min for smin protocol
    paillier_ciphertext_t *enc_s_min = paillier_create_enc_zero();

    //initialize enc_u_leq_v for sc protocol
    paillier_ciphertext_t *enc_u_leq_v = paillier_create_enc_zero();

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
    //int i;
    int sum = 0;
    socket_send_request_C_1_to_master(sockfd_with_master, REQUEST_FOR_TASK);

    while (1) {

        //try to recv a task assigned by the master node
        socket_receive_command_master_to_C_1(sockfd_with_master, &command_to_receive);
        printf("command_to_receive: %d\n", command_to_receive);

//      if (command_to_receive == SSED_OP) {
//          //peform the task according to the instruction
//          for (i = 0; i < 1000000000; i = i + 1) {
//              sum = sum + i;
//          }
//
//          socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
//          continue;
//      }

        if (command_to_receive == SMP) {
            //tell the corresponding C_2 it is time to perform SMP together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SMP);

            //try to perform smp 1 time and see if the result is correct
            for (i = 0; i < num_smp; i = i + 1) {
                execute_smp_C_1(enc_a_times_b, enc_a_s[i], enc_b_s[i], pk, sockfd_with_C_2);

                //send enc_a_times_b to C_2 and let C_2 check if the result is correct
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_a_times_b);
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);

            //send SETC related information back to the master node if not pair 0
            //...
            if (client_id != 0) {
                for (i = 0; i < num_dummy_setc_elements; i = i + 1) {
                    socket_send_paillier_ciphertext_t(sockfd_with_master, enc_dummy_sent_setc_element_s[i]);
                }
                printf("done with sending enc dummy setc elements to master\n");
            }
            

            continue;
        }

        if (command_to_receive == SSED) {
            //tell the corresponding C_2 it is time to perform SSED together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SSED);

            //try to perform smp 1 time and see if the result is correct
            for (i = 0; i < num_vectors; i = i + 1) {
                mpz_set_ui(enc_squared_distance->c, 1);
                execute_ssed_C_1(enc_squared_distance, enc_vector_x_s[i], enc_vector_y_s[i],
                                 num_dimensions, pk, sockfd_with_C_2);

                //send enc_squared_distance to C_2 and let C_2 check if the result is correct
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_squared_distance);
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;

        }

        if (command_to_receive == SSED_OP) {

            //tell the corresponding C_2 it is time to perform SSED_OP together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SSED_OP);

            execute_ssed_op_C_1(enc_squared_distance, enc_t_i, b_prime, a_prime_h, num_dimensions_ssed_op,
                                pk, sockfd_with_C_2);

            //check if the result is correct with C_2
            socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_squared_distance);

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;
        }

        if (command_to_receive == SLSB) {

            //tell the corresponding C_2 it is time to perform SLSB together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SLSB);

            //try to perform slsb num_slsb times and see if the result is correct
            for (i = 0; i < num_slsb; i = i + 1) {
                mpz_set_ui(enc_lsb->c, 1);
                execute_slsb_C_1(enc_lsb, enc_a_s[i], pk, sockfd_with_C_2);

                //send enc_lsb to C_2 and let C_2 check if the result is correct
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_lsb);
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;

        }

        if (command_to_receive == SBD) {

            //tell the corresponding C_2 it is time to perform SLSB together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SBD);

            //try to perform slsb num_slsb times and see if the result is correct
            for (i = 0; i < num_sbd; i = i + 1) {

                execute_sbd_C_1(enc_a_bits, enc_a_s[i], pk, one_half, bit_length, sockfd_with_C_2);

                //the code for testing the correctness of the protocol
                for (j = bit_length - 1; j >= 0; j = j - 1) {
                    socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_a_bits[j]);
                }
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;
        }

        if (command_to_receive == GT) {

            //tell the corresponding C_2 it is time to perform GT together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, GT);

            //perform sbd num_gt times to get enc_a_bits
            for (i = 0; i < num_gt; i = i + 1) {

                execute_sbd_C_1(enc_a_bits, enc_a_s[i], pk, one_half, bit_length, sockfd_with_C_2);
                execute_sbd_C_1(enc_b_bits, enc_b_s[i], pk, one_half, bit_length, sockfd_with_C_2);

                execute_gt_C_1(enc_x_gt_y, enc_a_bits, enc_b_bits, pk, bit_length, sockfd_with_C_2);

                //the code for testing the correctness of the protocol
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_x_gt_y);
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;
        }

        if (command_to_receive == PERM) {

            //test the functionality of permutation/inverse permutation first
            //tell the corresponding C_2 it is time to perform PERM together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, PERM);

            int num_plaintexts = 5;
            paillier_plaintext_t **x_s = initialize_paillier_plaintexts_1_d(num_plaintexts);
            for (i = 0; i < num_plaintexts; i = i + 1) {
                mpz_set_ui(x_s[i]->m, i + 5);
            }

            paillier_ciphertext_t **enc_x_s = encrypt_paillier_plaintexts_1_d(num_plaintexts, x_s, pk);

            for (i = 0; i < num_plaintexts; i = i + 1) {
                gmp_printf("enc_x_s[%ld]: %Zd\n\n", i, enc_x_s[i]->c);
            }

            long *pi = generate_random_permutation(state, num_plaintexts);
            long *inverse_pi = invert_permutation(pi, num_plaintexts);

            paillier_ciphertext_t **permuted_enc_x_s =
                shuffle_paillier_ciphertexts(permuted_enc_x_s, enc_x_s, num_plaintexts, pi);

            for (i = 0; i < num_plaintexts; i = i + 1) {
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, permuted_enc_x_s[i]);
            }

            //to receive the permuted enc x s from C_2
            paillier_ciphertext_t **permuted_enc_x_s_from_C_2 =
                initialize_paillier_ciphertexts_1_d(num_plaintexts);
            for (i = 0; i < num_plaintexts; i = i + 1) {
                socket_receive_paillier_ciphertext_t(sockfd_with_C_2, &(permuted_enc_x_s_from_C_2[i]));
            }

            for (i = 0; i < num_plaintexts; i = i + 1) {
                gmp_printf("permuted_enc_x_s_from_C_2[%ld]: %Zd\n\n", i, permuted_enc_x_s_from_C_2[i]->c);
            }

            //recover the permuted enc x s from C_2
            paillier_ciphertext_t **recovered_enc_x_s =
                shuffle_paillier_ciphertexts(recovered_enc_x_s, permuted_enc_x_s_from_C_2,
                                             num_plaintexts, inverse_pi);

            for (i = 0; i < num_plaintexts; i = i + 1) {
                gmp_printf("recovered_enc_x_s[%ld]: %Zd\n\n", i, recovered_enc_x_s[i]->c);
            }

            //test if enc_x_s are exactly equal to recovered_x_s
            for (i = 0; i < num_plaintexts; i = i + 1) {
                if (mpz_cmp(enc_x_s[i]->c, recovered_enc_x_s[i]->c) == 0) {
                    printf("enc_x_s[%ld] == recovered_enc_x_s[%ld]\n", i, i);
                } else {
                    printf("enc_x_s[%ld] != recovered_enc_x_s[%ld]\n", i, i);
                }
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;
        }

        if (command_to_receive == SMIN) {

            //tell the corresponding C_2 it is time to perform SMIN together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SMIN);

            //perform sbd followed by smin "num_smin" times
            for (i = 0; i < num_smin; i = i + 1) {
                execute_sbd_C_1(enc_a_bits, enc_a_s[i], pk, one_half, bit_length, sockfd_with_C_2);
                execute_sbd_C_1(enc_b_bits, enc_b_s[i], pk, one_half, bit_length, sockfd_with_C_2);

                execute_smin_C_1(enc_min_bits, enc_s_min,
                                 state, enc_a_bits, enc_b_bits,
                                 enc_a_s[i], enc_b_s[i],
                                 enc_negative_one, pk, bit_length, sockfd_with_C_2);

                //to test if the smin protocol is correct
                for (j = bit_length - 1; j >= 0; j = j - 1) {

                    socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_min_bits[j]);

                }

                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_s_min);
            }


            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;

        }

        if (command_to_receive == SMIN_K) {

            //tell the corresponding C_2 it is time to perform SMIN_K together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SMIN_K);

            //perform sbd k times to produce enc of k bit-decomposed distances
            for (i = 0; i < k; i = i + 1) {

                execute_sbd_C_1(enc_d_s_bits[i], enc_a_s[i], pk, one_half, bit_length, sockfd_with_C_2);

                //the code for testing the correctness of the sbd protocol
                for (j = bit_length - 1; j >= 0; j = j - 1) {
                    socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_d_s_bits[i][j]);
                }

            }

            //perform smin_k with the corresponding C_2
            execute_smin_k_C_1(Gamma_s, state, enc_d_s_bits, enc_negative_one, pk, k,
                               bit_length, sockfd_with_C_2);

            //to test if smin_k protocol is correct
            for (i = 0; i < k; i = i + 1) {
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, Gamma_s[i]);
            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;

        }

        if (command_to_receive == SINV) {

            //tell the corresponding C_2 it is time to perform SINV together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SINV);

            for (i = 0; i < num_sinv; i = i + 1) {

                //peform sinv with the corresponding C_2
                execute_sinv_C_1(enc_a_inv_s[i], enc_a_s[i], pk, sockfd_with_C_2);

                //check if the result of sinv is correct
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_a_s[i]);
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, enc_a_inv_s[i]);

            }

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;

        }

        if (command_to_receive == SPCI) {

            printf("to execute spci\n");

            //tell the corresponding C_2 it is time to perform SPIC together
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, SPCI);

            printf("before execute_spci_C_1\n");

            //perform spci with the corresponding C_2
            execute_spci_C_1(b_prime_spci, b_s_spci, a_prime_s_spci,
                             enc_cluster_cardinalities, enc_lambda_s,
                             num_clusters, num_attributes, pk, sockfd_with_C_2);

            printf("after execute_spci_C_1\n");

            //check if the results of spci are correct
            socket_send_paillier_ciphertext_t(sockfd_with_C_2, b_prime_spci);

            for (i = 0; i < num_clusters; i = i + 1) {
                socket_send_paillier_ciphertext_t(sockfd_with_C_2, b_s_spci[i]);
            }

            for (i = 0; i < num_clusters; i = i + 1) {
                for (j = 0; j < num_attributes; j = j + 1) {
                    socket_send_paillier_ciphertext_t(sockfd_with_C_2, a_prime_s_spci[i][j]);
                }
            }

            //Note by Fang-Yu: do not clean up here on 2015/02/10
            //clean-up
            //free_paillier_plaintexts_2_d(num_clusters, num_attributes, lambda_s);
            //free_paillier_ciphertexts_2_d(num_clusters, num_attributes, enc_lambda_s);

            //then tell the corresponding C_2 to wait for further instruction
            socket_send_command_C_1_to_C_2(sockfd_with_C_2, WAIT_FOR_FURTHER_INSTRUCTION);

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);

            //send back the necessary cluster information back to the master node for broadcast
            //...
            for (i = 0; i < num_dummy_cluster_elements; i = i + 1) {
                socket_send_paillier_ciphertext_t(sockfd_with_master, enc_sent_dummy_cluster_element_s[i]);
            }
            printf("done sending enc dummy cluster elements back to the master\n");

            continue;
        }

        if (command_to_receive == RECEIVE_CLUSTER_INFO) {

            //to recevie necessary cluster information from the master node
            //...
            for (i = 0; i < num_dummy_cluster_elements; i = i + 1) {
                socket_receive_paillier_ciphertext_t(sockfd_with_master, &(enc_received_dummy_cluster_element_s[i]));
            }
            printf("done with receiving enc dummy cluster elements from master\n");

            continue; 

        }

        if (command_to_receive == SETC) {

            //peform the task according to the instruction
            for (i = 0; i < 1000000000; i = i + 1) {
                sum = sum + i;
            }

            socket_send_request_C_1_to_master(sockfd_with_master, TASK_IS_DONE);
            continue;

        }

        if (command_to_receive == RECEIVE_SETC_INFO) {

            //to receive setc information from the master node
            
            for (i = 0; i < num_dummy_setc_elements; i = i + 1) {
                socket_receive_paillier_ciphertext_t(sockfd_with_master, &(enc_received_dummy_setc_element_s[i]));
            }
            printf("done with receiving enc dummy setc elements from master\n");

            continue;
        }

        if (command_to_receive == DUMMY_TASK) {
            //peform the task according to the instruction
            for (i = 0; i < 1000000000; i = i + 1) {
                sum = sum + i;
            }

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
    free_paillier_plaintexts_1_d(num_smp, a_s);
    free_paillier_plaintexts_1_d(num_smp, b_s);
    free_paillier_ciphertexts_1_d(num_smp, enc_a_s);
    free_paillier_ciphertexts_1_d(num_smp, enc_b_s);
    paillier_freeciphertext(enc_a_times_b);

    //clean-up for SSED
    free_paillier_plaintexts_2_d(num_vectors, num_dimensions, vector_x_s);
    free_paillier_plaintexts_2_d(num_vectors, num_dimensions, vector_y_s);

    free_paillier_ciphertexts_2_d(num_vectors, num_dimensions, enc_vector_x_s);
    free_paillier_ciphertexts_2_d(num_vectors, num_dimensions, enc_vector_y_s);

    paillier_freeciphertext(enc_squared_distance);

    //clean-up for SLSB
    paillier_freeciphertext(enc_lsb);

    //clean-up for SBD
    paillier_freeplaintext(one_half);

    //clean-up for GT
    paillier_freeciphertext(enc_x_gt_y);

    free_paillier_plaintexts_1_d(3, x_bits);
    free_paillier_plaintexts_1_d(3, y_bits);
    free_paillier_ciphertexts_1_d(3, enc_x_bits);
    free_paillier_ciphertexts_1_d(3, enc_y_bits);

    //clean-up for SMIN
    //do not forget to free the 2d array: enc_min_s_bits
    paillier_freeciphertext(enc_negative_one);

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

