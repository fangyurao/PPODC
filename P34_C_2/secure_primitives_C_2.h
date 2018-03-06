
#include <gmp.h>
#include "paillier.h"

#ifndef SECURE_PRIMITIVES_C_2_H
#define	SECURE_PRIMITIVES_C_2_H

//secure primitives/protocols
void execute_smp_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                       paillier_prvkey_t *in_sk);

void execute_smp_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                       paillier_prvkey_t *in_sk, paillier_ciphertext_t *in_enc_zero);

void execute_smp_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                       paillier_prvkey_t *in_sk, paillier_ciphertext_t **in_enc_zero_s, 
                       int in_num_smp);

void execute_ssp_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                       paillier_prvkey_t *in_sk, paillier_ciphertext_t *in_enc_zero);

void execute_ssp_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                               paillier_prvkey_t *in_sk, paillier_ciphertext_t **in_enc_zero_s, 
                               int in_num_ssp);

void execute_ssed_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                      paillier_prvkey_t *in_sk, int in_num_dimensions);

void execute_ssed_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, int in_num_dimensions, 
                      paillier_ciphertext_t **in_enc_zero_s_ssp);

void execute_ssed_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                paillier_prvkey_t *in_sk, int in_num_dimensions,
                                paillier_ciphertext_t **in_enc_zero_s_ssp);

void execute_ssed_op_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                         paillier_prvkey_t *in_sk, int in_num_dimensions);

void execute_ssed_op_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                         paillier_prvkey_t *in_sk, int in_num_dimensions, 
                         paillier_ciphertext_t **in_enc_zero_s_smp, 
                         paillier_ciphertext_t **in_enc_zero_s_ssp);

void execute_ssed_op_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                         paillier_prvkey_t *in_sk, int in_num_dimensions, 
                         paillier_ciphertext_t **in_enc_zero_s_smp, 
                         paillier_ciphertext_t **in_enc_zero_s_ssp);

void execute_slsb_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                      paillier_prvkey_t *in_sk);

void execute_slsb_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, 
                      paillier_ciphertext_t *in_enc_zero);

void execute_sbd_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                     paillier_prvkey_t *in_sk, int in_bit_length);

void execute_sbd_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                     paillier_prvkey_t *in_sk, int in_bit_length, 
                     paillier_ciphertext_t **in_enc_zero_s);

void execute_sbd_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                               paillier_prvkey_t *in_sk, int in_bit_length,
                               paillier_ciphertext_t ***in_enc_zero_s,
                               int in_num_sbd);

void execute_gt_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                    paillier_prvkey_t *in_sk, int in_bit_length);

void execute_smin_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                      paillier_prvkey_t *in_sk, int in_bit_length);

void execute_smin_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, int in_bit_length, 
                      paillier_ciphertext_t **in_enc_zero_s_M_prime, 
                      paillier_ciphertext_t *in_enc_zero_delta_prime, 
                      paillier_ciphertext_t *in_enc_zero_alpha, 
                      paillier_ciphertext_t **in_enc_zero_s_smp);

void execute_smin_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, int in_bit_length, 
                      paillier_ciphertext_t **in_enc_zero_s_M_prime, 
                      paillier_ciphertext_t *in_enc_zero_delta_prime, 
                      paillier_ciphertext_t *in_enc_zero_alpha, 
                      paillier_ciphertext_t **in_enc_zero_s_smp);

void execute_smin_k_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                        paillier_prvkey_t *in_sk, long in_k, int in_bit_length);

void execute_smin_k_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                        paillier_prvkey_t *in_sk, long in_k, int in_bit_length, 
                        paillier_ciphertext_t ***in_enc_zero_s_M_prime, 
                        paillier_ciphertext_t **in_enc_zero_s_delta_prime, 
                        paillier_ciphertext_t **in_enc_zero_s_alpha, 
                        paillier_ciphertext_t ***in_enc_zero_s_smp, 
                        paillier_ciphertext_t **in_enc_zero_s_U);

void execute_smin_k_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                        paillier_prvkey_t *in_sk, long in_k, int in_bit_length, 
                        paillier_ciphertext_t ***in_enc_zero_s_M_prime, 
                        paillier_ciphertext_t **in_enc_zero_s_delta_prime, 
                        paillier_ciphertext_t **in_enc_zero_s_alpha, 
                        paillier_ciphertext_t ***in_enc_zero_s_smp, 
                        paillier_ciphertext_t **in_enc_zero_s_U);

void execute_sinv_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                      paillier_prvkey_t *in_sk);

void execute_spci_C_2(int in_sock_fd, paillier_pubkey_t *in_pk, 
                      paillier_prvkey_t *in_sk, int in_k, int in_num_dimensions);

#endif
