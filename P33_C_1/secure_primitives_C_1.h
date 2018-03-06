#include <gmp.h>
#include "paillier.h"

#ifndef SECURE_PRIMITIVES_C_1_H
#define	SECURE_PRIMITIVES_C_1_H

//utility functions
void get_rand_file(void *buf, int len, char *file);
void init_rand_for_permutation(gmp_randstate_t rand, int bytes);
unsigned long generate_random_number(gmp_randstate_t in_state,
                                     unsigned long in_lower_bound, unsigned long in_upper_bound);
long* generate_random_permutation(gmp_randstate_t rand, long in_num_elements);
long* invert_permutation(long *in_permutation, long in_num_elements);
void display_permutation(long *in_permutation, long in_num_elements);
long** shuffle(long **in_elements, long in_num_elements, long *in_permutation);
paillier_ciphertext_t** shuffle_paillier_ciphertexts(paillier_ciphertext_t **out_ciphertexts, 
                                                     paillier_ciphertext_t **in_ciphertexts, 
                                                     long in_num_elements, long *in_permutation);
void display_array(long **in_elements, long in_num_elements);


//secure primitives/protocols
void execute_smp_C_1(paillier_ciphertext_t *out_enc_a_times_b,
        paillier_ciphertext_t *in_enc_a, paillier_ciphertext_t *in_enc_b,
        paillier_pubkey_t *in_pk, int in_sock_fd);

void execute_smp_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_a_times_b,
        paillier_ciphertext_t *in_enc_a, paillier_ciphertext_t *in_enc_b,
        paillier_pubkey_t *in_pk, int in_sock_fd, 
        paillier_plaintext_t *in_negative_r_a, paillier_plaintext_t *in_negative_r_b, 
        paillier_ciphertext_t *in_enc_r_a, paillier_ciphertext_t *in_enc_r_b, 
        paillier_ciphertext_t *in_enc_negative_r_a_times_r_b);

void execute_smp_pipelined_C_1(paillier_ciphertext_t **out_enc_a_times_b_s,
                                            paillier_ciphertext_t **in_enc_a_s, paillier_ciphertext_t **in_enc_b_s,
                                            paillier_pubkey_t *in_pk, int in_sock_fd,
                                            paillier_plaintext_t **in_negative_r_a_s, paillier_plaintext_t **in_negative_r_b_s,
                                            paillier_ciphertext_t **in_enc_r_a_s, paillier_ciphertext_t **in_enc_r_b_s,
                                            paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s, 
                                            int in_num_smp);

void execute_ssp_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_a_squared,
                                            paillier_ciphertext_t *in_enc_a,
                                            paillier_pubkey_t *in_pk, int in_sock_fd,
                                            paillier_plaintext_t *in_negative_two_times_r_a, 
                                            paillier_ciphertext_t *in_enc_r_a,
                                            paillier_ciphertext_t *in_enc_negative_r_a_squared);

void execute_ssp_pipelined_C_1(paillier_ciphertext_t **out_enc_a_squared_s,
                               paillier_ciphertext_t **in_enc_a_s,
                               paillier_pubkey_t *in_pk, int in_sock_fd,
                               paillier_plaintext_t **in_negative_two_times_r_a_s,
                               paillier_ciphertext_t **in_enc_r_a_s,
                               paillier_ciphertext_t **in_enc_negative_r_a_squared_s, 
                               int in_num_ssp);

void execute_ssed_C_1(paillier_ciphertext_t *out_squared_distance, 
                      paillier_ciphertext_t **in_vector_x, paillier_ciphertext_t **in_vector_y,
                      int in_num_dimensions, 
                      paillier_pubkey_t *in_pk, int in_sock_fd);

void execute_ssed_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_squared_distance,
                      paillier_ciphertext_t **in_vector_x, paillier_ciphertext_t **in_vector_y,
                      int in_num_dimensions,
                      paillier_pubkey_t *in_pk, int in_sock_fd, 
                      paillier_ciphertext_t **in_enc_r_a_s_ssp, 
                      paillier_ciphertext_t **in_enc_negative_r_a_squared_s_ssp, 
                      paillier_plaintext_t **in_negative_two_times_r_a_s_ssp);

void execute_ssed_pipelined_C_1(paillier_ciphertext_t *out_enc_squared_distance,
                                paillier_ciphertext_t **in_vector_x, paillier_ciphertext_t **in_vector_y,
                                int in_num_dimensions,
                                paillier_pubkey_t *in_pk, int in_sock_fd,
                                paillier_ciphertext_t **in_enc_r_a_s_ssp,
                                paillier_ciphertext_t **in_enc_negative_r_a_squared_s_ssp,
                                paillier_plaintext_t **in_negative_two_times_r_a_s_ssp);

void execute_ssed_op_C_1(paillier_ciphertext_t *out_enc_squared_distance, 
                         paillier_ciphertext_t **in_enc_t_i, 
                         paillier_ciphertext_t *in_b_prime,
                         paillier_ciphertext_t **in_a_prime_h,  
                         int in_num_dimensions, 
                         paillier_pubkey_t *in_pk, int in_sock_fd);

void execute_ssed_op_precomputed_randomness_C_1(paillier_ciphertext_t *out_squared_distance,
                         paillier_ciphertext_t **in_enc_t_i,
                         paillier_ciphertext_t *in_b_prime,
                         paillier_ciphertext_t **in_a_prime_h,
                         int in_num_dimensions,
                         paillier_pubkey_t *in_pk, int in_sock_fd, 
                         paillier_ciphertext_t **in_enc_r_a_s_smp, 
                         paillier_ciphertext_t **in_enc_r_b_s_smp,
                         paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s_smp, 
                         paillier_plaintext_t **in_negative_r_a_s_smp, 
                         paillier_plaintext_t **in_negative_r_b_s_smp, 
                         paillier_ciphertext_t **in_enc_r_a_s_ssp, 
                         paillier_ciphertext_t **in_enc_negative_r_a_squared_s_ssp, 
                         paillier_plaintext_t **in_negative_two_times_r_a_s_ssp);

void execute_ssed_op_pipelined_C_1(paillier_ciphertext_t *out_squared_distance,
                         paillier_ciphertext_t **in_enc_t_i,
                         paillier_ciphertext_t *in_b_prime,
                         paillier_ciphertext_t **in_a_prime_h,
                         int in_num_dimensions,
                         paillier_pubkey_t *in_pk, int in_sock_fd, 
                         paillier_ciphertext_t **in_enc_r_a_s_smp, 
                         paillier_ciphertext_t **in_enc_r_b_s_smp,
                         paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s_smp, 
                         paillier_plaintext_t **in_negative_r_a_s_smp, 
                         paillier_plaintext_t **in_negative_r_b_s_smp, 
                         paillier_ciphertext_t **in_enc_r_a_s_ssp, 
                         paillier_ciphertext_t **in_enc_negative_r_a_squared_s_ssp, 
                         paillier_plaintext_t **in_negative_two_times_r_a_s_ssp);

void execute_slsb_C_1(paillier_ciphertext_t *out_enc_lsb, 
                      paillier_ciphertext_t *in_T, 
                      paillier_pubkey_t *in_pk, int in_sock_fd);

void execute_slsb_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_lsb,
                      paillier_ciphertext_t *in_T,
                      paillier_pubkey_t *in_pk, int in_sock_fd,
                      paillier_plaintext_t *in_r,  
                      paillier_ciphertext_t *in_enc_r);

void execute_sbd_C_1(paillier_ciphertext_t **out_enc_bits,
                     paillier_ciphertext_t *in_enc_x,
                     paillier_pubkey_t *in_pk, paillier_plaintext_t *in_one_half, 
                     int in_bit_length, int in_sock_fd);

void execute_sbd_precomputed_randomness_C_1(paillier_ciphertext_t **out_enc_bits,
                     paillier_ciphertext_t *in_enc_x,
                     paillier_pubkey_t *in_pk, paillier_plaintext_t *in_one_half,
                     int in_bit_length, int in_sock_fd,
                     paillier_plaintext_t **in_r_s,  
                     paillier_ciphertext_t **in_enc_r_s);

void execute_sbd_pipelined_C_1(paillier_ciphertext_t ***out_enc_bits,
                               paillier_ciphertext_t **in_enc_x_s,
                               paillier_pubkey_t *in_pk, paillier_plaintext_t *in_one_half,
                               int in_bit_length, int in_sock_fd,
                               paillier_plaintext_t ***in_r_s,
                               paillier_ciphertext_t ***in_enc_r_s,
                               int in_num_sbd);

void execute_gt_C_1(paillier_ciphertext_t *out_enc_x_gt_y, 
                    paillier_ciphertext_t **in_enc_x_bits, 
                    paillier_ciphertext_t **in_enc_y_bits, 
                    paillier_pubkey_t *in_pk, int in_bit_length, int in_sock_fd);

void execute_smin_C_1(paillier_ciphertext_t **out_enc_min_bits, paillier_ciphertext_t *out_enc_s_min, 
                      gmp_randstate_t in_state,
                      paillier_ciphertext_t **in_enc_u_bits, paillier_ciphertext_t **in_enc_v_bits,
                      paillier_ciphertext_t *in_enc_s_u, paillier_ciphertext_t *in_enc_s_v, 
                      paillier_ciphertext_t *in_enc_negative_one,
                      paillier_pubkey_t *in_pk, int in_bit_length, int in_sock_fd);

void execute_smin_precomputed_randomness_C_1(paillier_ciphertext_t **out_enc_min_bits, paillier_ciphertext_t *out_enc_s_min,
                      gmp_randstate_t in_state,
                      paillier_ciphertext_t **in_enc_u_bits, paillier_ciphertext_t **in_enc_v_bits,
                      paillier_ciphertext_t *in_enc_s_u, paillier_ciphertext_t *in_enc_s_v,
                      paillier_ciphertext_t *in_enc_negative_one,
                      paillier_pubkey_t *in_pk, int in_bit_length, int in_sock_fd, 
                      paillier_plaintext_t **in_negative_r_hat_s, paillier_ciphertext_t **in_enc_r_hat_s, 
                      paillier_plaintext_t *in_negative_r_bar, paillier_ciphertext_t *in_enc_r_bar, 
                      paillier_plaintext_t **in_negative_r_a_s_smp, paillier_ciphertext_t **in_enc_r_a_s_smp, 
                      paillier_plaintext_t **in_negative_r_b_s_smp, paillier_ciphertext_t **in_enc_r_b_s_smp, 
                      paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s_smp);

void execute_smin_pipelined_C_1(paillier_ciphertext_t **out_enc_min_bits, paillier_ciphertext_t *out_enc_s_min,
                      gmp_randstate_t in_state,
                      paillier_ciphertext_t **in_enc_u_bits, paillier_ciphertext_t **in_enc_v_bits,
                      paillier_ciphertext_t *in_enc_s_u, paillier_ciphertext_t *in_enc_s_v,
                      paillier_ciphertext_t *in_enc_negative_one,
                      paillier_pubkey_t *in_pk, int in_bit_length, int in_sock_fd, 
                      paillier_plaintext_t **in_negative_r_hat_s, paillier_ciphertext_t **in_enc_r_hat_s, 
                      paillier_plaintext_t *in_negative_r_bar, paillier_ciphertext_t *in_enc_r_bar, 
                      paillier_plaintext_t **in_negative_r_a_s_smp, paillier_ciphertext_t **in_enc_r_a_s_smp, 
                      paillier_plaintext_t **in_negative_r_b_s_smp, paillier_ciphertext_t **in_enc_r_b_s_smp, 
                      paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s_smp);

void execute_smin_k_C_1(paillier_ciphertext_t **out_Gamma_s, 
                        gmp_randstate_t in_state, 
                        paillier_ciphertext_t ***in_enc_d_s_bits, 
                        paillier_ciphertext_t *in_enc_negative_one, 
                        paillier_pubkey_t *in_pk, 
                        long in_k, int in_bit_length, int in_sock_fd);

void execute_smin_k_precomputed_randomness_C_1(paillier_ciphertext_t **out_Gamma_s,
                        gmp_randstate_t in_state,
                        paillier_ciphertext_t ***in_enc_d_s_bits,
                        paillier_ciphertext_t *in_enc_negative_one,
                        paillier_pubkey_t *in_pk,
                        long in_k, int in_bit_length, int in_sock_fd, 
                        paillier_plaintext_t ***in_negative_r_hat_s, paillier_ciphertext_t ***in_enc_r_hat_s, 
                        paillier_plaintext_t **in_negative_r_bar_s_delta, 
                        paillier_ciphertext_t **in_enc_r_bar_s_delta, 
                        paillier_plaintext_t ***in_negative_r_a_s_smp, 
                        paillier_ciphertext_t ***in_enc_r_a_s_smp, 
                        paillier_plaintext_t ***in_negative_r_b_s_smp, 
                        paillier_ciphertext_t ***in_enc_r_b_s_smp, 
                        paillier_ciphertext_t ***in_enc_negative_r_a_times_r_b_s_smp, 
                        paillier_ciphertext_t **in_enc_cluster_indices);

void execute_smin_k_pipelined_C_1(paillier_ciphertext_t **out_Gamma_s,
                        gmp_randstate_t in_state,
                        paillier_ciphertext_t ***in_enc_d_s_bits,
                        paillier_ciphertext_t *in_enc_negative_one,
                        paillier_pubkey_t *in_pk,
                        long in_k, int in_bit_length, int in_sock_fd, 
                        paillier_plaintext_t ***in_negative_r_hat_s, paillier_ciphertext_t ***in_enc_r_hat_s, 
                        paillier_plaintext_t **in_negative_r_bar_s_delta, 
                        paillier_ciphertext_t **in_enc_r_bar_s_delta, 
                        paillier_plaintext_t ***in_negative_r_a_s_smp, 
                        paillier_ciphertext_t ***in_enc_r_a_s_smp, 
                        paillier_plaintext_t ***in_negative_r_b_s_smp, 
                        paillier_ciphertext_t ***in_enc_r_b_s_smp, 
                        paillier_ciphertext_t ***in_enc_negative_r_a_times_r_b_s_smp, 
                        paillier_ciphertext_t **in_enc_cluster_indices);

void execute_sinv_C_1(paillier_ciphertext_t *out_inv_enc_a, 
                      paillier_ciphertext_t *in_enc_a, 
                      paillier_pubkey_t *in_pk, int in_sock_fd);

void execute_spci_C_1(paillier_ciphertext_t *out_b_prime, paillier_ciphertext_t **out_b_s,
                      paillier_ciphertext_t ***out_a_prime_s, 
                      paillier_ciphertext_t **in_enc_cardinalities, 
                      paillier_ciphertext_t ***in_enc_lambda_s, 
                      int in_k, int in_num_dimensions, 
                      paillier_pubkey_t *in_pk, int in_sock_fd);

#endif
