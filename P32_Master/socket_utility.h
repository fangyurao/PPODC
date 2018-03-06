/* 
 * File:   socket.h
 * Author: raof
 *
 * Created on February 22, 2014, 8:56 PM
 */

#include <gmp.h>
#include "paillier.h"
#include <stdint.h>

#ifndef SOCKET_UTILITY_H
#define	SOCKET_UTILITY_H

int create_socket_and_listen(char *service);
int create_socket_and_connect(char inHostname[], char *port);

void *get_in_addr(struct sockaddr *sa);

int socket_send_mpz_t(int sockid, mpz_t nb);
int socket_receive_mpz_t(int sockid, mpz_t *nb);

int socket_send_int(int sockid, uint32_t nb);
int socket_receive_int(int sockid, uint32_t *nb);

int socket_send_paillier_pubkey_t(int sockid, paillier_pubkey_t *pk);
int socket_receive_paillier_pubkey_t(int sockid, paillier_pubkey_t **pub);

int socket_send_paillier_ciphertext_t(int sockid, paillier_ciphertext_t *ct);
int socket_send_paillier_ciphertexts(int sockid, paillier_ciphertext_t **in_ct_s, int in_num_ciphertexts);
int socket_receive_paillier_ciphertext_t(int sockid, paillier_ciphertext_t **ct);
int socket_receive_paillier_ciphertexts(paillier_ciphertext_t ***out_ct_s, int in_num_ciphertexts, int sockid);

int socket_send_bytes(int sockid, char *bytes, int totalBytesToSend);
int socket_receive_bytes(int sockid, char *bytes, int totalBytesToReceive);

//below coming from C_1.cpp
int socket_receive_command_master_to_C_1(int sockid, uint32_t *value_to_receive);
int socket_send_request_C_1_to_master(int sockid, uint32_t value_to_send);

int socket_send_command_C_1_to_C_2(int sockid, uint32_t value_to_send);
int socket_receive_request_C_2_to_C_1(int sockid, uint32_t *value_to_receive);

//below coming from C_2.cpp
int socket_receive_command_C_1_to_C_2(int sockid, uint32_t *value_to_receive);
int socket_send_request_C_2_to_C_1(int sockid, uint32_t value_to_send);

//below coming from master.cpp
int socket_send_command_master_to_C_1(int sockid, uint32_t value_to_send);
int socket_receive_request_C_1_to_master(int sockid, uint32_t *value_to_receive);

#endif	/* SOCKET_UTILITY_H */

