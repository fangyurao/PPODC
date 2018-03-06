#include <stdlib.h>
#include <gmp.h>
#include "paillier.h"
#include "socket_utility.h"
#include <stdio.h>

#include <sys/time.h>

//#define DEBUG_SMIN_PROTOCOL
//#define DEBUG_SMIN_K_PROTOCOL

//#define DEBUG_SMP_PIPELINED_PROTOCOL

#define TIME_C_2

long long time_spent_on_C_2_global;

void execute_smp_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                     paillier_prvkey_t *in_sk) {

    //receive E(a), E(b) from the server
    paillier_ciphertext_t *a_prime = 0;
    paillier_ciphertext_t *b_prime = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &a_prime);
    socket_receive_paillier_ciphertext_t(in_sock_fd, &b_prime);

    paillier_plaintext_t *h_a = 0;
    paillier_plaintext_t *h_b = 0;
    h_a = paillier_dec(h_a, in_pk, in_sk, a_prime);
    h_b = paillier_dec(h_b, in_pk, in_sk, b_prime);

#ifdef DEBUG_SMP_PROTOCOL
    gmp_printf("h_a->m: %Zd\n", h_a->m);
    gmp_printf("h_b->m: %Zd\n", h_b->m);
#endif

    //compute h = h_a * h_b
    mpz_t raw_h;
    mpz_init(raw_h);
    mpz_mul(raw_h, h_a->m, h_b->m);
    mpz_mod(raw_h, raw_h, in_pk->n);
    paillier_plaintext_t *h = 0;
    h = paillier_plaintext_from_mpz_t(&raw_h);
#ifdef DEBUG_SMP_PROTOCOL
    gmp_printf("h->m: %Zd\n", h->m);
#endif

    //compute E(h)
    paillier_ciphertext_t *h_prime = 0;
    h_prime = paillier_enc(h_prime, in_pk, h, paillier_get_rand_devurandom);
#ifdef DEBUG_SMP_PROTOCOL
    gmp_printf("h_prime->c: %Zd\n", h_prime->c);
#endif

    //send h_prime to the server
    socket_send_paillier_ciphertext_t(in_sock_fd, h_prime);

    //clean-up
    paillier_freeciphertext(a_prime);
    paillier_freeciphertext(b_prime);

    paillier_freeplaintext(h_a);
    paillier_freeplaintext(h_b);

    mpz_clear(raw_h);
    paillier_freeplaintext(h);

    paillier_freeciphertext(h_prime);


}

void execute_smp_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                            paillier_prvkey_t *in_sk, paillier_ciphertext_t *in_enc_zero) {

    //receive E(a), E(b) from the server
    paillier_ciphertext_t *a_prime = 0;
    paillier_ciphertext_t *b_prime = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &a_prime);
    socket_receive_paillier_ciphertext_t(in_sock_fd, &b_prime);

    paillier_plaintext_t *h_a = 0;
    paillier_plaintext_t *h_b = 0;
    h_a = paillier_dec(h_a, in_pk, in_sk, a_prime);
    h_b = paillier_dec(h_b, in_pk, in_sk, b_prime);

    //compute h = h_a * h_b
    paillier_plaintext_t *h = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(h->m);
    mpz_mul(h->m, h_a->m, h_b->m);
    mpz_mod(h->m, h->m, in_pk->n);

    //compute E(h) with the precomputed E(0)
    paillier_ciphertext_t *h_prime = paillier_create_enc_zero();
    mpz_mul(h_prime->c, in_pk->n, h->m);
    mpz_add_ui(h_prime->c, h_prime->c, 1);
    paillier_mul(in_pk, h_prime, h_prime, in_enc_zero);

    //send h_prime to the server
    socket_send_paillier_ciphertext_t(in_sock_fd, h_prime);

    //clean-up
    paillier_freeciphertext(a_prime);
    paillier_freeciphertext(b_prime);

    paillier_freeplaintext(h_a);
    paillier_freeplaintext(h_b);

    //mpz_clear(raw_h);
    paillier_freeplaintext(h);

    paillier_freeciphertext(h_prime);

}

void execute_smp_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                               paillier_prvkey_t *in_sk, paillier_ciphertext_t **in_enc_zero_s,
                               int in_num_smp) {

    //below are added on 2015/03/11
#ifdef TIME_C_2
    long long time_spent_in_step_2 = 0;
    timeval before_step_2;
    timeval after_step_2;
#endif
    //above are added on 2015/03/11

    paillier_ciphertext_t **a_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);
    paillier_ciphertext_t **b_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);

    paillier_plaintext_t **h_a_s = initialize_paillier_plaintexts_1_d(in_num_smp);
    paillier_plaintext_t **h_b_s = initialize_paillier_plaintexts_1_d(in_num_smp);
    paillier_plaintext_t **h_s = initialize_paillier_plaintexts_1_d(in_num_smp);
    paillier_ciphertext_t **h_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);

    int i;

    socket_receive_paillier_ciphertexts(&a_prime_s, in_num_smp, in_sock_fd);
    socket_receive_paillier_ciphertexts(&b_prime_s, in_num_smp, in_sock_fd);

    for (i = 0; i < in_num_smp; i = i + 1) {

        //below are added on 2015/03/11
#ifdef TIME_C_2
        gettimeofday(&before_step_2, NULL);
#endif
        //above are added on 2015/03/11

        h_a_s[i] = paillier_dec(h_a_s[i], in_pk, in_sk, a_prime_s[i]);
        h_b_s[i] = paillier_dec(h_b_s[i], in_pk, in_sk, b_prime_s[i]);

        mpz_mul(h_s[i]->m, h_a_s[i]->m, h_b_s[i]->m);
        mpz_mod(h_s[i]->m, h_s[i]->m, in_pk->n);

        mpz_mul(h_prime_s[i]->c, in_pk->n, h_s[i]->m);
        mpz_add_ui(h_prime_s[i]->c, h_prime_s[i]->c, 1);
        paillier_mul(in_pk, h_prime_s[i], h_prime_s[i], in_enc_zero_s[i]);

        //below are added on 2015/03/11
#ifdef TIME_C_2
        gettimeofday(&after_step_2, NULL);
        time_spent_in_step_2 = ((after_step_2.tv_sec * 1000000 + after_step_2.tv_usec) -
                                (before_step_2.tv_sec * 1000000 + before_step_2.tv_usec));
        time_spent_on_C_2_global = time_spent_on_C_2_global + time_spent_in_step_2;
#endif
        //above are added on 2015/03/11

        socket_send_paillier_ciphertext_t(in_sock_fd, h_prime_s[i]);

    }


    //clean-up
    free_paillier_ciphertexts_1_d(in_num_smp, a_prime_s);
    free_paillier_ciphertexts_1_d(in_num_smp, b_prime_s);

    free_paillier_plaintexts_1_d(in_num_smp, h_a_s);
    free_paillier_plaintexts_1_d(in_num_smp, h_b_s);
    free_paillier_plaintexts_1_d(in_num_smp, h_s);
    free_paillier_ciphertexts_1_d(in_num_smp, h_prime_s);

}

void execute_ssp_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                            paillier_prvkey_t *in_sk, paillier_ciphertext_t *in_enc_zero) {

    //receive E(a + r_a) from the corresponding C_1
    paillier_ciphertext_t *a_prime = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &a_prime);

    paillier_plaintext_t *h_a = 0;
    h_a = paillier_dec(h_a, in_pk, in_sk, a_prime);

    //compute h = h_a * h_a
    paillier_plaintext_t *h = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(h->m);
    mpz_mul(h->m, h_a->m, h_a->m);
    mpz_mod(h->m, h->m, in_pk->n);

    //compute E(h) with the precomputed E(0)
    paillier_ciphertext_t *h_prime = paillier_create_enc_zero();
    mpz_mul(h_prime->c, in_pk->n, h->m);
    mpz_add_ui(h_prime->c, h_prime->c, 1);
    paillier_mul(in_pk, h_prime, h_prime, in_enc_zero);

    //send h_prime to the server
    socket_send_paillier_ciphertext_t(in_sock_fd, h_prime);

    //clean-up
    paillier_freeciphertext(a_prime);
    paillier_freeplaintext(h_a);
    paillier_freeplaintext(h);
    paillier_freeciphertext(h_prime);

}

void execute_ssp_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                               paillier_prvkey_t *in_sk, paillier_ciphertext_t **in_enc_zero_s,
                               int in_num_ssp) {

#ifdef TIME_C_2
    timeval before_step_2;
    timeval after_step_2;
    long long time_spent_in_step_2 = 0;
#endif

    //receive E(a + r_a) from the corresponding C_1
    //paillier_ciphertext_t *a_prime = 0;
    //socket_receive_paillier_ciphertext_t(in_sock_fd, &a_prime);

    paillier_ciphertext_t **a_prime_s = initialize_paillier_ciphertexts_1_d(in_num_ssp);
    socket_receive_paillier_ciphertexts(&a_prime_s, in_num_ssp, in_sock_fd);

    //paillier_plaintext_t *h_a = 0;
    //h_a = paillier_dec(h_a, in_pk, in_sk, a_prime);

    paillier_plaintext_t **h_a_s = initialize_paillier_plaintexts_1_d(in_num_ssp);
    paillier_plaintext_t **h_s = initialize_paillier_plaintexts_1_d(in_num_ssp);
    paillier_ciphertext_t **h_prime_s = initialize_paillier_ciphertexts_1_d(in_num_ssp);
    int i;
    for (i = 0; i < in_num_ssp; i = i + 1) {

#ifdef TIME_C_2
        gettimeofday(&before_step_2, NULL);
#endif

        //compute h = h_a * h_a
        h_a_s[i] = paillier_dec(h_a_s[i], in_pk, in_sk, a_prime_s[i]);
        mpz_mul(h_s[i]->m, h_a_s[i]->m, h_a_s[i]->m);
        mpz_mod(h_s[i]->m, h_s[i]->m, in_pk->n);

        //compute E(h) with the precomputed E(0)
        mpz_mul(h_prime_s[i]->c, in_pk->n, h_s[i]->m);
        mpz_add_ui(h_prime_s[i]->c, h_prime_s[i]->c, 1);
        paillier_mul(in_pk, h_prime_s[i], h_prime_s[i], in_enc_zero_s[i]);

#ifdef TIME_C_2
        gettimeofday(&after_step_2, NULL);
        time_spent_in_step_2 = ((after_step_2.tv_sec * 1000000 + after_step_2.tv_usec) -
                                (before_step_2.tv_sec * 1000000 + before_step_2.tv_usec));
        time_spent_on_C_2_global = time_spent_on_C_2_global + time_spent_in_step_2;
#endif

        //send h_prime to the server
        socket_send_paillier_ciphertext_t(in_sock_fd, h_prime_s[i]);
    }

    //compute h = h_a * h_a
    //paillier_plaintext_t *h = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    //mpz_init(h->m);
    //mpz_mul(h->m, h_a->m, h_a->m);
    //mpz_mod(h->m, h->m, in_pk->n);

    //compute E(h) with the precomputed E(0)
    //paillier_ciphertext_t *h_prime = paillier_create_enc_zero();
    //mpz_mul(h_prime->c, in_pk->n, h->m);
    //mpz_add_ui(h_prime->c, h_prime->c, 1);
    //paillier_mul(in_pk, h_prime, h_prime, in_enc_zero);

    //send h_prime to the server
    //socket_send_paillier_ciphertext_t(in_sock_fd, h_prime);

    //clean-up
    //paillier_freeciphertext(a_prime);
    //paillier_freeplaintext(h_a);
    //paillier_freeplaintext(h);
    //paillier_freeciphertext(h_prime);

    free_paillier_ciphertexts_1_d(in_num_ssp, a_prime_s);
    free_paillier_plaintexts_1_d(in_num_ssp, h_a_s);
    free_paillier_plaintexts_1_d(in_num_ssp, h_s);
    free_paillier_ciphertexts_1_d(in_num_ssp, h_prime_s);
}

void execute_ssed_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, int in_num_dimensions) {

    int i;
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        execute_smp_C_2(in_sock_fd, in_pk, in_sk);
    }

}

void execute_ssed_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                             paillier_prvkey_t *in_sk, int in_num_dimensions,
                                             paillier_ciphertext_t **in_enc_zero_s_ssp) {

    int i;
    for (i = 0; i < in_num_dimensions; i = i + 1) {

        execute_ssp_precomputed_randomness_C_2(in_sock_fd, in_pk,
                                               in_sk, in_enc_zero_s_ssp[i]);

    }

}

void execute_ssed_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                paillier_prvkey_t *in_sk, int in_num_dimensions,
                                paillier_ciphertext_t **in_enc_zero_s_ssp) {

    execute_ssp_pipelined_C_2(in_sock_fd, in_pk,
                              in_sk, in_enc_zero_s_ssp,
                              in_num_dimensions);

}

void execute_ssed_op_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                         paillier_prvkey_t *in_sk, int in_num_dimensions) {

    int s;
    for (s = 0; s < in_num_dimensions; s = s + 1) {

        execute_smp_C_2(in_sock_fd, in_pk, in_sk);

    }

    execute_ssed_C_2(in_sock_fd, in_pk, in_sk, in_num_dimensions);

}

void execute_ssed_op_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                                paillier_prvkey_t *in_sk, int in_num_dimensions,
                                                paillier_ciphertext_t **in_enc_zero_s_smp,
                                                paillier_ciphertext_t **in_enc_zero_s_ssp) {

    int s;
    for (s = 0; s < in_num_dimensions; s = s + 1) {

        execute_smp_precomputed_randomness_C_2(in_sock_fd, in_pk,
                                               in_sk, in_enc_zero_s_smp[s]);

    }



    execute_ssed_precomputed_randomness_C_2(in_sock_fd, in_pk,
                                            in_sk, in_num_dimensions,
                                            in_enc_zero_s_ssp);

}

void execute_ssed_op_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                   paillier_prvkey_t *in_sk, int in_num_dimensions,
                                   paillier_ciphertext_t **in_enc_zero_s_smp,
                                   paillier_ciphertext_t **in_enc_zero_s_ssp) {

    execute_smp_pipelined_C_2(in_sock_fd, in_pk,
                              in_sk, in_enc_zero_s_smp,
                              in_num_dimensions);

    execute_ssed_pipelined_C_2(in_sock_fd, in_pk,
                               in_sk, in_num_dimensions,
                               in_enc_zero_s_ssp);

}

void execute_slsb_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk) {

    paillier_ciphertext_t *Y = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &Y);

    paillier_plaintext_t *y = 0;
    y = paillier_dec(y, in_pk, in_sk, Y);

#ifdef DEBUG_SLSB_PROTOCOL
    gmp_printf("y: %Zd\n", y->m);
#endif

    paillier_ciphertext_t *alpha = 0;
    paillier_plaintext_t *y_is_odd = 0;

    if (mpz_tstbit(y->m, 0) == 0) {
        //when y is even, alpha <- E(0)
        y_is_odd = paillier_plaintext_from_ui(0);

    } else {
        //when y is odd, alpha <- E(1)
        y_is_odd = paillier_plaintext_from_ui(1);
    }
    alpha = paillier_enc(alpha, in_pk, y_is_odd, paillier_get_rand_devurandom);

    //Step 2(d) of SLSB
    socket_send_paillier_ciphertext_t(in_sock_fd, alpha);

    //clean-up
    paillier_freeciphertext(Y);
    paillier_freeplaintext(y);
    paillier_freeciphertext(alpha);
    paillier_freeplaintext(y_is_odd);
}

void execute_slsb_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                             paillier_prvkey_t *in_sk,
                                             paillier_ciphertext_t *in_enc_zero) {

    paillier_ciphertext_t *Y = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &Y);

    paillier_plaintext_t *y = 0;
    y = paillier_dec(y, in_pk, in_sk, Y);

    paillier_ciphertext_t *alpha = paillier_create_enc_zero();

    if (mpz_tstbit(y->m, 0) == 0) {
        //when y is even, alpha <- E(0)
        paillier_mul(in_pk, alpha, alpha, in_enc_zero);
    } else {
        //when y is odd, alpha <- E(1)
        paillier_mul(in_pk, alpha, alpha, in_enc_zero);
        mpz_mul(alpha->c, alpha->c, in_pk->n_plusone); //(1 + n) is an encryption of 1
        mpz_mod(alpha->c, alpha->c, in_pk->n_squared);
    }

    //Step 2(d) of SLSB
    socket_send_paillier_ciphertext_t(in_sock_fd, alpha);

    //clean-up
    paillier_freeciphertext(Y);
    paillier_freeplaintext(y);
    paillier_freeciphertext(alpha);

}

void execute_sbd_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                     paillier_prvkey_t *in_sk, int in_bit_length) {

    int i;
    for (i = 0; i < in_bit_length; i = i + 1) {
        execute_slsb_C_2(in_sock_fd, in_pk, in_sk);
    }

}

void execute_sbd_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                            paillier_prvkey_t *in_sk, int in_bit_length,
                                            paillier_ciphertext_t **in_enc_zero_s) {

    int i;
    for (i = 0; i < in_bit_length; i = i + 1) {

        execute_slsb_precomputed_randomness_C_2(in_sock_fd, in_pk,
                                                in_sk,
                                                in_enc_zero_s[i]);
    }

}

void execute_sbd_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                               paillier_prvkey_t *in_sk, int in_bit_length,
                               paillier_ciphertext_t ***in_enc_zero_s,
                               int in_num_sbd) {

#ifdef TIME_C_2
    timeval before_step_2;
    timeval after_step_2;
    long long time_spent_in_step_2 = 0;
#endif

    int i, j;

    paillier_ciphertext_t *Y = paillier_create_enc_zero();

    paillier_plaintext_t *y = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(y->m);

    paillier_ciphertext_t *alpha = paillier_create_enc_zero();

    for (i = 0; i < in_bit_length; i = i + 1) {

        for (j = 0; j < in_num_sbd; j = j + 1) {

            socket_receive_paillier_ciphertext_t(in_sock_fd, &(Y));

#ifdef TIME_C_2
            gettimeofday(&before_step_2, NULL);
#endif

            paillier_dec(y, in_pk, in_sk, Y);

            if (mpz_tstbit(y->m, 0) == 0) {
                //when y is even, alpha <- E(0)
                paillier_mul(in_pk, alpha, alpha, in_enc_zero_s[j][i]);
            } else {
                //when y is odd, alpha <- E(1)
                paillier_mul(in_pk, alpha, alpha, in_enc_zero_s[j][i]);
                mpz_mul(alpha->c, alpha->c, in_pk->n_plusone); //(1 + n) is an encryption of 1
                mpz_mod(alpha->c, alpha->c, in_pk->n_squared);

            }

#ifdef TIME_C_2
            gettimeofday(&after_step_2, NULL);
            time_spent_in_step_2 = ((after_step_2.tv_sec * 1000000 + after_step_2.tv_usec) -
                                    (before_step_2.tv_sec * 1000000 + before_step_2.tv_usec));
            time_spent_on_C_2_global = time_spent_on_C_2_global + time_spent_in_step_2;
#endif

            socket_send_paillier_ciphertext_t(in_sock_fd, alpha);

            //clean up the content of alpha
            mpz_set_ui(alpha->c, 1);

        }

    }

    //clean-up
    paillier_freeciphertext(Y);
    paillier_freeplaintext(y);
    paillier_freeciphertext(alpha);
}

void execute_gt_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                    paillier_prvkey_t *in_sk, int in_bit_length) {

    int i;

    //the code below is for debugging purpose
    paillier_plaintext_t *bit = 0;
    paillier_ciphertext_t *enc_bit = 0;

    //to receive bit-decomposed x
    printf("x: ");
    for (i = in_bit_length - 1; i >= 1; i = i - 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
        bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
        gmp_printf("%Zd", bit);
    }
    socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
    bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
    gmp_printf("%Zd\n", bit);

    //to receive bit-decomposed y
    printf("y: ");
    for (i = in_bit_length - 1; i >= 1; i = i - 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
        bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
        gmp_printf("%Zd", bit);
    }
    socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
    bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
    gmp_printf("%Zd\n", bit);

    //the code above is for debugging purpose

    execute_smp_C_2(in_sock_fd, in_pk, in_sk);

    for (i = 1; i <= in_bit_length - 2; i = i + 1) {

        //for the computation of E(y_i * t_i)
        execute_smp_C_2(in_sock_fd, in_pk, in_sk);

        //for the computation of E(x_i * w_i)
        execute_smp_C_2(in_sock_fd, in_pk, in_sk);
    }

    //for the computation of E(y_{m - 1} * t_{m - 1})
    execute_smp_C_2(in_sock_fd, in_pk, in_sk);

    //for the computation of E(x_{m - 1} * w_{m - 1})
    execute_smp_C_2(in_sock_fd, in_pk, in_sk);

}

void execute_smin_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, int in_bit_length) {

    paillier_plaintext_t *zero = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(zero->m);

    paillier_ciphertext_t *enc_zero = paillier_create_enc_zero();

    unsigned long alpha; //indicating whether or not F is a right guess
    paillier_ciphertext_t *enc_alpha = paillier_create_enc_zero();

    //initialize Gamma_prime_s
    paillier_ciphertext_t **Gamma_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize L_prime_s
    paillier_ciphertext_t **L_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_s
    paillier_plaintext_t **M_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //init enc_u_i_times_v_i, u_i_times_v_i for debugging purpose
    paillier_ciphertext_t *enc_u_i_times_v_i = paillier_create_enc_zero();
    paillier_plaintext_t *u_i_times_v_i = 0;

    //init T_i, decrypted_T_i for debugging purpose
    paillier_ciphertext_t *T_i = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_T_i = 0;

    //initialize M_prime_s
    paillier_ciphertext_t **M_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialzie delta
    paillier_ciphertext_t *delta = paillier_create_enc_zero();

    //initialize delta_prime
    paillier_ciphertext_t *delta_prime = paillier_create_enc_zero();

    long i;

    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        //E(u_i * v_i) <- SMP(E(u_i), E(v_i))
        execute_smp_C_2(in_sock_fd, in_pk, in_sk);

#ifdef  DEBUG_SMIN_PROTOCOL
        //insert some code to check if E(u_i * v_i) is correct
        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_u_i_times_v_i);
        u_i_times_v_i = paillier_dec(u_i_times_v_i, in_pk, in_sk, enc_u_i_times_v_i);


        gmp_printf("u[%d]*v[%d]: %Zd\n", i, i, u_i_times_v_i->m);
#endif

#ifdef DEBUG_SMIN_PROTOCOL
        //insert some code to check the correctness of T_s[i]
        socket_receive_paillier_ciphertext_t(in_sock_fd, &T_i);
        decrypted_T_i = paillier_dec(decrypted_T_i, in_pk, in_sk, T_i);
        //gmp_printf("D(T[%d]): %Zd\n", i, decrypted_T_i->m);
#endif
    }

    //Step 1(e)
    //receive delta from C_1
    socket_receive_paillier_ciphertext_t(in_sock_fd, &delta);

    //receive Gamma_prime_s from C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(Gamma_prime_s[i]));

    }

    //receive L_prime_s from C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(L_prime_s[i]));

    }

    //Step 2(a)
    int existence = 0; //indicating whether or not there exists an j such that M_j == 1, F is a right guess
    for (i = 0; i < in_bit_length; i = i + 1) {

        //M_i <- D(L_prime_i)
        paillier_dec(M_s[i], in_pk, in_sk, L_prime_s[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //to see the contents of M_s
        gmp_printf("M_s[%ld]: %Zd\n", i, M_s[i]->m);
#endif

        if (mpz_cmp_ui(M_s[i]->m, 1) == 0) {
            existence = 1;
            //break;//consider to uncomment this break. the result does not depend on knowing all M_s
        }
    }


    if (existence == 1) {
        alpha = 1;
#ifdef DEBUG_SMIN_PROTOCOL
        printf("right guess\n");
#endif
    } else {
        alpha = 0;
#ifdef DEBUG_SMIN_PROTOCOL
        printf("wrong guess\n");
#endif
    }

    //Step 2(c)
    if (alpha == 1) { //F is a right guess

        //M_prime_i <- Gamma_prime_i * E(0), for i from "in_bit_length - 1" to "0"
        for (i = in_bit_length - 1; i >= 0; i = i - 1) {
            //E(0) should be created for each i
            paillier_enc(enc_zero, in_pk, zero, paillier_get_rand_devurandom);
            paillier_mul(in_pk, M_prime_s[i], Gamma_prime_s[i], enc_zero);
        }

        //delta_prime <- delta * E(0)
        paillier_enc(enc_zero, in_pk, zero, paillier_get_rand_devurandom);
        paillier_mul(in_pk, delta_prime, delta, enc_zero);


    } else { //alpha == 0, F is a wrong guess

        //M_prime_i <- E(0), for i from "in_bit_length - 1" to "0"
        for (i = in_bit_length - 1; i >= 0; i = i - 1) {
            //E(0) should be created for each i
            paillier_enc(M_prime_s[i], in_pk, zero, paillier_get_rand_devurandom);
        }

        //delta_prime <- E(0)
        paillier_enc(delta_prime, in_pk, zero, paillier_get_rand_devurandom);

    }

    //send M' to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_send_paillier_ciphertext_t(in_sock_fd, M_prime_s[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //check if M' is correctly received by gmp_printf
        gmp_printf("M'[%ld]: %Zd\n", i, M_prime_s[i]->c);
#endif

    }

    //send E(alpha) to C_1
    paillier_plaintext_t *alpha_pt = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(alpha_pt->m);
    if (alpha == 1) {
        mpz_set_ui(alpha_pt->m, 1);
    } else { //when alpha == 0
        mpz_set_ui(alpha_pt->m, 0);
    }
    paillier_enc(enc_alpha, in_pk, alpha_pt, paillier_get_rand_devurandom);

#ifdef DEBUG_SMIN_PROTOCOL
    gmp_printf("enc_alpha: %Zd\n", enc_alpha->c);
#endif

    socket_send_paillier_ciphertext_t(in_sock_fd, enc_alpha);

    //send delta_prime to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, delta_prime);

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_prime_s);
    free_paillier_ciphertexts_1_d(in_bit_length, L_prime_s);

    free_paillier_plaintexts_1_d(in_bit_length, M_s);

    free_paillier_ciphertexts_1_d(in_bit_length, M_prime_s);

    paillier_freeciphertext(delta);
    paillier_freeciphertext(delta_prime);

    paillier_freeplaintext(zero);
    paillier_freeciphertext(enc_zero);

    paillier_freeplaintext(alpha_pt);
    paillier_freeciphertext(enc_alpha);

}

void execute_smin_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                             paillier_prvkey_t *in_sk, int in_bit_length,
                                             paillier_ciphertext_t **in_enc_zero_s_M_prime,
                                             paillier_ciphertext_t *in_enc_zero_delta_prime,
                                             paillier_ciphertext_t *in_enc_zero_alpha,
                                             paillier_ciphertext_t **in_enc_zero_s_smp) {

    unsigned long alpha; //indicating whether or not F is a right guess
    paillier_ciphertext_t *enc_alpha = paillier_create_enc_zero();

    //initialize Gamma_prime_s
    paillier_ciphertext_t **Gamma_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize L_prime_s
    paillier_ciphertext_t **L_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_s
    paillier_plaintext_t **M_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //init enc_u_i_times_v_i, u_i_times_v_i for debugging purpose
    paillier_ciphertext_t *enc_u_i_times_v_i = paillier_create_enc_zero();
    paillier_plaintext_t *u_i_times_v_i = 0;

    //init T_i, decrypted_T_i for debugging purpose
    paillier_ciphertext_t *T_i = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_T_i = 0;

    //initialize M_prime_s
    paillier_ciphertext_t **M_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialzie delta
    paillier_ciphertext_t *delta = paillier_create_enc_zero();

    //initialize delta_prime
    paillier_ciphertext_t *delta_prime = paillier_create_enc_zero();

    long i;

    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        //E(u_i * v_i) <- SMP(E(u_i), E(v_i))
        execute_smp_precomputed_randomness_C_2(in_sock_fd, in_pk,
                                               in_sk, in_enc_zero_s_smp[i]);

#ifdef  DEBUG_SMIN_PROTOCOL
        //insert some code to check if E(u_i * v_i) is correct
        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_u_i_times_v_i);
        u_i_times_v_i = paillier_dec(u_i_times_v_i, in_pk, in_sk, enc_u_i_times_v_i);


        gmp_printf("u[%d]*v[%d]: %Zd\n", i, i, u_i_times_v_i->m);
#endif

#ifdef DEBUG_SMIN_PROTOCOL
        //insert some code to check the correctness of T_s[i]
        socket_receive_paillier_ciphertext_t(in_sock_fd, &T_i);
        decrypted_T_i = paillier_dec(decrypted_T_i, in_pk, in_sk, T_i);
        //gmp_printf("D(T[%d]): %Zd\n", i, decrypted_T_i->m);
#endif
    }

    //Step 1(e)
    //receive delta from C_1
    socket_receive_paillier_ciphertext_t(in_sock_fd, &delta);

    //receive Gamma_prime_s from C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(Gamma_prime_s[i]));

    }

    //receive L_prime_s from C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(L_prime_s[i]));

    }

    //Step 2(a)
    int existence = 0; //indicating whether or not there exists an j such that M_j == 1, F is a right guess
    for (i = 0; i < in_bit_length; i = i + 1) {

        //M_i <- D(L_prime_i)
        paillier_dec(M_s[i], in_pk, in_sk, L_prime_s[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //to see the contents of M_s
        gmp_printf("M_s[%ld]: %Zd\n", i, M_s[i]->m);
#endif

        if (mpz_cmp_ui(M_s[i]->m, 1) == 0) {
            existence = 1;
            //break;//consider to uncomment this break. the result does not depend on knowing all M_s
        }
    }


    if (existence == 1) {
        alpha = 1;
#ifdef DEBUG_SMIN_PROTOCOL
        printf("right guess\n");
#endif
    } else {
        alpha = 0;
#ifdef DEBUG_SMIN_PROTOCOL
        printf("wrong guess\n");
#endif
    }

    //Step 2(c)
    if (alpha == 1) { //F is a right guess

        //M_prime_i <- Gamma_prime_i * E(0), for i from "in_bit_length - 1" to "0"
        for (i = in_bit_length - 1; i >= 0; i = i - 1) {
            //E(0) should be created for each i
            paillier_mul(in_pk, M_prime_s[i], Gamma_prime_s[i], in_enc_zero_s_M_prime[i]);
        }

        //delta_prime <- delta * E(0)
        paillier_mul(in_pk, delta_prime, delta, in_enc_zero_delta_prime);


    } else { //alpha == 0, F is a wrong guess

        //M_prime_i <- E(0), for i from "in_bit_length - 1" to "0"
        for (i = in_bit_length - 1; i >= 0; i = i - 1) {
            //E(0) should be created for each i
            mpz_set(M_prime_s[i]->c, in_enc_zero_s_M_prime[i]->c);
        }

        //delta_prime <- E(0)
        mpz_set(delta_prime->c, in_enc_zero_delta_prime->c);

    }

    //send M' to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_send_paillier_ciphertext_t(in_sock_fd, M_prime_s[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //check if M' is correctly received by gmp_printf
        gmp_printf("M'[%ld]: %Zd\n", i, M_prime_s[i]->c);
#endif

    }

    //send E(alpha) to C_1
    //compute E(alpha) using in_enc_zero_alpha
    if (alpha == 1) {
        mpz_set(enc_alpha->c, in_pk->n_plusone); // (1 + n * 1) is an encryption of 1
        paillier_mul(in_pk, enc_alpha, enc_alpha, in_enc_zero_alpha);
    } else { //when alpha == 0
        mpz_set(enc_alpha->c, in_enc_zero_alpha->c);
    }

#ifdef DEBUG_SMIN_PROTOCOL
    gmp_printf("enc_alpha: %Zd\n", enc_alpha->c);
#endif

    socket_send_paillier_ciphertext_t(in_sock_fd, enc_alpha);

    //send delta_prime to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, delta_prime);

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_prime_s);
    free_paillier_ciphertexts_1_d(in_bit_length, L_prime_s);

    free_paillier_plaintexts_1_d(in_bit_length, M_s);

    free_paillier_ciphertexts_1_d(in_bit_length, M_prime_s);

    paillier_freeciphertext(delta);
    paillier_freeciphertext(delta_prime);

    paillier_freeciphertext(enc_alpha);

}

void execute_smin_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                paillier_prvkey_t *in_sk, int in_bit_length,
                                paillier_ciphertext_t **in_enc_zero_s_M_prime,
                                paillier_ciphertext_t *in_enc_zero_delta_prime,
                                paillier_ciphertext_t *in_enc_zero_alpha,
                                paillier_ciphertext_t **in_enc_zero_s_smp) {

#ifdef TIME_C_2
    timeval before_step_2;
    timeval after_step_2;
    long long time_spent_in_step_2 = 0;
#endif

    unsigned long alpha; //indicating whether or not F is a right guess
    paillier_ciphertext_t *enc_alpha = paillier_create_enc_zero();

    //initialize Gamma_prime_s
    paillier_ciphertext_t **Gamma_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize L_prime_s
    paillier_ciphertext_t **L_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_s
    paillier_plaintext_t **M_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //init enc_u_i_times_v_i, u_i_times_v_i for debugging purpose
    paillier_ciphertext_t *enc_u_i_times_v_i = paillier_create_enc_zero();
    paillier_plaintext_t *u_i_times_v_i = 0;

    //init T_i, decrypted_T_i for debugging purpose
    paillier_ciphertext_t *T_i = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_T_i = 0;

    //initialize M_prime_s
    paillier_ciphertext_t **M_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialzie delta
    paillier_ciphertext_t *delta = paillier_create_enc_zero();

    //initialize delta_prime
    paillier_ciphertext_t *delta_prime = paillier_create_enc_zero();

    long i;

    execute_smp_pipelined_C_2(in_sock_fd, in_pk,
                              in_sk, in_enc_zero_s_smp,
                              in_bit_length);

    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        //E(u_i * v_i) <- SMP(E(u_i), E(v_i))
//      execute_smp_precomputed_randomness_C_2(in_sock_fd, in_pk,
//                                             in_sk, in_enc_zero_s_smp[i]);

#ifdef  DEBUG_SMIN_PROTOCOL
        //insert some code to check if E(u_i * v_i) is correct
        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_u_i_times_v_i);
        u_i_times_v_i = paillier_dec(u_i_times_v_i, in_pk, in_sk, enc_u_i_times_v_i);


        gmp_printf("u[%d]*v[%d]: %Zd\n", i, i, u_i_times_v_i->m);
#endif

#ifdef DEBUG_SMIN_PROTOCOL
        //insert some code to check the correctness of T_s[i]
        socket_receive_paillier_ciphertext_t(in_sock_fd, &T_i);
        decrypted_T_i = paillier_dec(decrypted_T_i, in_pk, in_sk, T_i);
        //gmp_printf("D(T[%d]): %Zd\n", i, decrypted_T_i->m);
#endif
    }

    //Step 1(e)
    //receive delta from C_1
    socket_receive_paillier_ciphertext_t(in_sock_fd, &delta);

    //receive Gamma_prime_s from C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(Gamma_prime_s[i]));

    }

    //receive L_prime_s from C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(L_prime_s[i]));

    }

    //Step 2(a)
#ifdef TIME_C_2
    gettimeofday(&before_step_2, NULL);
#endif

    int existence = 0; //indicating whether or not there exists an j such that M_j == 1, F is a right guess
    for (i = 0; i < in_bit_length; i = i + 1) {

        //M_i <- D(L_prime_i)
        paillier_dec(M_s[i], in_pk, in_sk, L_prime_s[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //to see the contents of M_s
        gmp_printf("M_s[%ld]: %Zd\n", i, M_s[i]->m);
#endif

        if (mpz_cmp_ui(M_s[i]->m, 1) == 0) {
            existence = 1;
            //break;//consider to uncomment this break. the result does not depend on knowing all M_s
        }
    }


    if (existence == 1) {
        alpha = 1;
#ifdef DEBUG_SMIN_PROTOCOL
        printf("right guess\n");
#endif
    } else {
        alpha = 0;
#ifdef DEBUG_SMIN_PROTOCOL
        printf("wrong guess\n");
#endif
    }

    //Step 2(c)
    if (alpha == 1) { //F is a right guess

        //M_prime_i <- Gamma_prime_i * E(0), for i from "in_bit_length - 1" to "0"
        for (i = in_bit_length - 1; i >= 0; i = i - 1) {
            //E(0) should be created for each i
            paillier_mul(in_pk, M_prime_s[i], Gamma_prime_s[i], in_enc_zero_s_M_prime[i]);
        }

        //delta_prime <- delta * E(0)
        paillier_mul(in_pk, delta_prime, delta, in_enc_zero_delta_prime);


    } else { //alpha == 0, F is a wrong guess

        //M_prime_i <- E(0), for i from "in_bit_length - 1" to "0"
        for (i = in_bit_length - 1; i >= 0; i = i - 1) {
            //E(0) should be created for each i
            mpz_set(M_prime_s[i]->c, in_enc_zero_s_M_prime[i]->c);
        }

        //delta_prime <- E(0)
        mpz_set(delta_prime->c, in_enc_zero_delta_prime->c);

    }

    //compute E(alpha) using in_enc_zero_alpha
    if (alpha == 1) {
        mpz_set(enc_alpha->c, in_pk->n_plusone); // (1 + n * 1) is an encryption of 1
        paillier_mul(in_pk, enc_alpha, enc_alpha, in_enc_zero_alpha);
    } else { //when alpha == 0
        mpz_set(enc_alpha->c, in_enc_zero_alpha->c);
    }

#ifdef DEBUG_SMIN_PROTOCOL
    gmp_printf("enc_alpha: %Zd\n", enc_alpha->c);
#endif

#ifdef TIME_C_2
    gettimeofday(&after_step_2, NULL);
    time_spent_in_step_2 =
        ((after_step_2.tv_sec * 1000000 + after_step_2.tv_usec) -
         (before_step_2.tv_sec * 1000000 + before_step_2.tv_usec));
    time_spent_on_C_2_global = time_spent_on_C_2_global + time_spent_in_step_2;
#endif

    //send M' to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_send_paillier_ciphertext_t(in_sock_fd, M_prime_s[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //check if M' is correctly received by gmp_printf
        gmp_printf("M'[%ld]: %Zd\n", i, M_prime_s[i]->c);
#endif

    }

    //send E(alpha) to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, enc_alpha);

    //send delta_prime to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, delta_prime);

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_prime_s);
    free_paillier_ciphertexts_1_d(in_bit_length, L_prime_s);

    free_paillier_plaintexts_1_d(in_bit_length, M_s);

    free_paillier_ciphertexts_1_d(in_bit_length, M_prime_s);

    paillier_freeciphertext(delta);
    paillier_freeciphertext(delta_prime);

    paillier_freeciphertext(enc_alpha);

}

void execute_smin_k_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                        paillier_prvkey_t *in_sk, long in_k, int in_bit_length) {

    //initialize u_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **u_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize u_prime_i for i from 0 to "in_k - 1"
    paillier_plaintext_t **u_prime_s = initialize_paillier_plaintexts_1_d(in_k);

    //initialize U_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **U_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize zero
    paillier_plaintext_t *zero = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(zero->m);

    //initialize one
    paillier_plaintext_t *one = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(one->m);
    mpz_set_ui(one->m, 1);

    long i;

    //Step 1(a), 1(b)
    for (i = 0; i < in_k - 1; i = i + 1) {
        execute_smin_C_2(in_sock_fd, in_pk, in_sk, in_bit_length);
    }

#ifdef DEBUG_SMIN_K_PROTOCOL
//to test if step 1 is correct

    paillier_ciphertext_t *enc_bit = paillier_create_enc_zero();
    paillier_plaintext_t *bit = 0;

    paillier_ciphertext_t *I = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_I = 0;

    printf("\n");
    printf("T_bits: ");
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
        bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
        gmp_printf("%Zd", bit);

    }
    printf("\n");

    printf("decrypted I: ");
    socket_receive_paillier_ciphertext_t(in_sock_fd, &I);
    decrypted_I = paillier_dec(decrypted_I, in_pk, in_sk, I);
    gmp_printf("%Zd\n", decrypted_I);
#endif

    //Step 3(a): receive u from C_1
    for (i = 0; i < in_k; i = i + 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &(u_s[i]));
    }

    //Step 3(b)
    for (i = 0; i < in_k; i = i + 1) {
        //u'[i] <- D(u[i])
        u_prime_s[i] = paillier_dec(u_prime_s[i], in_pk, in_sk, u_s[i]);

#ifdef DEBUG_SMIN_K_PROTOCOL
        gmp_printf("u_prime_s[%ld]: %Zd\n", i, u_prime_s[i]->m);
#endif

    }

    //Step 3(c)
    for (i = 0; i < in_k; i = i + 1) {

        //if u'[i] == 0, U[i] <- E(1)
        if (mpz_cmp_ui(u_prime_s[i]->m, 0) == 0) {

            paillier_enc(U_s[i], in_pk, one, paillier_get_rand_devurandom);

        } else { //else U[i] <- E(0)

            paillier_enc(U_s[i], in_pk, zero, paillier_get_rand_devurandom);

        }

    }

    //Step 3(d): send U to C_1
    for (i = 0; i < in_k; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, U_s[i]);
    }

    //clean-up
#ifdef DEBUG_SMIN_K_PROTOCOL
    paillier_freeciphertext(enc_bit);
    paillier_freeplaintext(bit);
    paillier_freeciphertext(I);
#endif

    free_paillier_ciphertexts_1_d(in_k, u_s);

    free_paillier_plaintexts_1_d(in_k, u_prime_s);

    free_paillier_ciphertexts_1_d(in_k, U_s);

    paillier_freeplaintext(zero);
    paillier_freeplaintext(one);

}

void execute_smin_k_precomputed_randomness_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                               paillier_prvkey_t *in_sk, long in_k, int in_bit_length,
                                               paillier_ciphertext_t ***in_enc_zero_s_M_prime,
                                               paillier_ciphertext_t **in_enc_zero_s_delta_prime,
                                               paillier_ciphertext_t **in_enc_zero_s_alpha,
                                               paillier_ciphertext_t ***in_enc_zero_s_smp,
                                               paillier_ciphertext_t **in_enc_zero_s_U) {

    //initialize u_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **u_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize u_prime_i for i from 0 to "in_k - 1"
    paillier_plaintext_t **u_prime_s = initialize_paillier_plaintexts_1_d(in_k);

    //initialize U_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **U_s = initialize_paillier_ciphertexts_1_d(in_k);

    long i;

    //Step 1(a), 1(b)
    for (i = 0; i < in_k - 1; i = i + 1) {

        execute_smin_precomputed_randomness_C_2(in_sock_fd, in_pk,
                                                in_sk, in_bit_length,
                                                in_enc_zero_s_M_prime[i],
                                                in_enc_zero_s_delta_prime[i],
                                                in_enc_zero_s_alpha[i],
                                                in_enc_zero_s_smp[i]);

    }

#ifdef DEBUG_SMIN_K_PROTOCOL
//to test if step 1 is correct

    paillier_ciphertext_t *enc_bit = paillier_create_enc_zero();
    paillier_plaintext_t *bit = 0;

    paillier_ciphertext_t *I = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_I = 0;

    printf("\n");
    printf("T_bits: ");
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
        bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
        gmp_printf("%Zd", bit);

    }
    printf("\n");

    printf("decrypted I: ");
    socket_receive_paillier_ciphertext_t(in_sock_fd, &I);
    decrypted_I = paillier_dec(decrypted_I, in_pk, in_sk, I);
    gmp_printf("%Zd\n", decrypted_I);
#endif

    //Step 3(a): receive u from C_1
    for (i = 0; i < in_k; i = i + 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &(u_s[i]));
    }

    //Step 3(b)
    for (i = 0; i < in_k; i = i + 1) {
        //u'[i] <- D(u[i])
        u_prime_s[i] = paillier_dec(u_prime_s[i], in_pk, in_sk, u_s[i]);

#ifdef DEBUG_SMIN_K_PROTOCOL
        gmp_printf("u_prime_s[%ld]: %Zd\n", i, u_prime_s[i]->m);
#endif

    }

    //Step 3(c)
    for (i = 0; i < in_k; i = i + 1) {

        //if u'[i] == 0, U[i] <- E(1)
        if (mpz_cmp_ui(u_prime_s[i]->m, 0) == 0) {

            mpz_set(U_s[i]->c, in_pk->n_plusone); // (1 + n) is an encryption of 1
            paillier_mul(in_pk, U_s[i], U_s[i], in_enc_zero_s_U[i]);

        } else { //else U[i] <- E(0)

            mpz_set(U_s[i]->c, in_enc_zero_s_U[i]->c);

        }

    }

    //Step 3(d): send U to C_1
    for (i = 0; i < in_k; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, U_s[i]);
    }

    //clean-up
#ifdef DEBUG_SMIN_K_PROTOCOL
    paillier_freeciphertext(enc_bit);
    paillier_freeplaintext(bit);
    paillier_freeciphertext(I);
#endif

    free_paillier_ciphertexts_1_d(in_k, u_s);

    free_paillier_plaintexts_1_d(in_k, u_prime_s);

    free_paillier_ciphertexts_1_d(in_k, U_s);
}

void execute_smin_k_pipelined_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                                  paillier_prvkey_t *in_sk, long in_k, int in_bit_length,
                                  paillier_ciphertext_t ***in_enc_zero_s_M_prime,
                                  paillier_ciphertext_t **in_enc_zero_s_delta_prime,
                                  paillier_ciphertext_t **in_enc_zero_s_alpha,
                                  paillier_ciphertext_t ***in_enc_zero_s_smp,
                                  paillier_ciphertext_t **in_enc_zero_s_U) {

#ifdef TIME_C_2
    timeval before_step_3;
    timeval after_step_3;
    long long time_spent_in_step_3 = 0;
#endif

    //initialize u_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **u_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize u_prime_i for i from 0 to "in_k - 1"
    paillier_plaintext_t **u_prime_s = initialize_paillier_plaintexts_1_d(in_k);

    //initialize U_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **U_s = initialize_paillier_ciphertexts_1_d(in_k);

    long i;

    //Step 1(a), 1(b)
    for (i = 0; i < in_k - 1; i = i + 1) {

        execute_smin_pipelined_C_2(in_sock_fd, in_pk,
                                   in_sk, in_bit_length,
                                   in_enc_zero_s_M_prime[i],
                                   in_enc_zero_s_delta_prime[i],
                                   in_enc_zero_s_alpha[i],
                                   in_enc_zero_s_smp[i]);

    }

#ifdef DEBUG_SMIN_K_PROTOCOL
//to test if step 1 is correct

    paillier_ciphertext_t *enc_bit = paillier_create_enc_zero();
    paillier_plaintext_t *bit = 0;

    paillier_ciphertext_t *I = paillier_create_enc_zero();
    paillier_plaintext_t *decrypted_I = 0;

    printf("\n");
    printf("T_bits: ");
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_bit);
        bit = paillier_dec(bit, in_pk, in_sk, enc_bit);
        gmp_printf("%Zd", bit);

    }
    printf("\n");

    printf("decrypted I: ");
    socket_receive_paillier_ciphertext_t(in_sock_fd, &I);
    decrypted_I = paillier_dec(decrypted_I, in_pk, in_sk, I);
    gmp_printf("%Zd\n", decrypted_I);
#endif

    //Step 3(a): receive u from C_1
    for (i = 0; i < in_k; i = i + 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &(u_s[i]));
    }

    //Step 3(b)
#ifdef TIME_C_2
    gettimeofday(&before_step_3, NULL);
#endif

    for (i = 0; i < in_k; i = i + 1) {
        //u'[i] <- D(u[i])
        u_prime_s[i] = paillier_dec(u_prime_s[i], in_pk, in_sk, u_s[i]);

#ifdef DEBUG_SMIN_K_PROTOCOL
        gmp_printf("u_prime_s[%ld]: %Zd\n", i, u_prime_s[i]->m);
#endif

    }

    //Step 3(c)
    for (i = 0; i < in_k; i = i + 1) {

        //if u'[i] == 0, U[i] <- E(1)
        if (mpz_cmp_ui(u_prime_s[i]->m, 0) == 0) {

            mpz_set(U_s[i]->c, in_pk->n_plusone); // (1 + n) is an encryption of 1
            paillier_mul(in_pk, U_s[i], U_s[i], in_enc_zero_s_U[i]);

        } else { //else U[i] <- E(0)

            mpz_set(U_s[i]->c, in_enc_zero_s_U[i]->c);

        }

    }

#ifdef TIME_C_2
    gettimeofday(&after_step_3, NULL);
    time_spent_in_step_3 =
        ((after_step_3.tv_sec * 1000000 + after_step_3.tv_usec) -
         (before_step_3.tv_sec * 1000000 + before_step_3.tv_usec));
    time_spent_on_C_2_global = time_spent_on_C_2_global + time_spent_in_step_3;
#endif

    //Step 3(d): send U to C_1
    for (i = 0; i < in_k; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, U_s[i]);
    }

    //clean-up
#ifdef DEBUG_SMIN_K_PROTOCOL
    paillier_freeciphertext(enc_bit);
    paillier_freeplaintext(bit);
    paillier_freeciphertext(I);
#endif

    free_paillier_ciphertexts_1_d(in_k, u_s);

    free_paillier_plaintexts_1_d(in_k, u_prime_s);

    free_paillier_ciphertexts_1_d(in_k, U_s);
}

void execute_sinv_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk) {

    //initialize B
    paillier_ciphertext_t *B = paillier_create_enc_zero();

    //initialize b
    paillier_plaintext_t *b = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(b->m);

    //initialize b^{-1}
    paillier_plaintext_t *b_inv = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(b_inv->m);

    //initialize F
    paillier_ciphertext_t *F = paillier_create_enc_zero();

    //Step 3: receive B from C_1
    socket_receive_paillier_ciphertext_t(in_sock_fd, &B);

    //Step 4: b <- D(B)
    b = paillier_dec(b, in_pk, in_sk, B);

    //Step 5: F <- E(b^{-1} mod N)
    mpz_invert(b_inv->m, b->m, in_pk->n);
    paillier_enc(F, in_pk, b_inv, paillier_get_rand_devurandom);

    //Step 6: send F to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, F);

    //Step 7: SMP(E(r), F)
    execute_smp_C_2(in_sock_fd, in_pk, in_sk);

    //clean-up
    paillier_freeciphertext(B);
    paillier_freeplaintext(b);
    paillier_freeplaintext(b_inv);
    paillier_freeciphertext(F);
}

void execute_spci_C_2(int in_sock_fd, paillier_pubkey_t *in_pk,
                      paillier_prvkey_t *in_sk, int in_k, int in_num_dimensions) {

    int i;
    int j;

    //Step 1, compute b' with the corresponding C_1
    for (i = 0; i < in_k - 1; i = i + 1) {

        execute_smp_C_2(in_sock_fd, in_pk, in_sk);

    }

    //Step 2, compute b_h for each cluster h
    for (i = 0; i < in_k; i = i + 1) {

        execute_sinv_C_2(in_sock_fd, in_pk, in_sk);

        execute_smp_C_2(in_sock_fd, in_pk, in_sk);

    }

    //Step 3: compute lambda_s[i][j], for i from 0 to "in_k - 1", j from 0 to "in_num_dimensions - 1"
    for (i = 0; i < in_k; i = i + 1) {
        for (j = 0; j < in_num_dimensions; j = j + 1) {
            execute_smp_C_2(in_sock_fd, in_pk, in_sk);
        }
    }

}
