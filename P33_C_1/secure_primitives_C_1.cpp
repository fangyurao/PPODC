#include <stdlib.h>
#include <gmp.h>
#include "paillier.h"
#include "socket_utility.h"
#include <stdio.h>//fflush
#include <unistd.h>//usleep

#include <sys/time.h>

//#define DEBUG_SMIN_PROTOCOL
//#define DEBUG_SMIN_K_PROTOCOL

//#define DEBUG_SMP_PROTOCOL

//#define DEBUG_SMP_PIPELINED_PROTOCOL

#define TIME_C_1

long long time_spent_on_C_1_global;

void get_rand_file(void *buf, int len, char *file) {
    FILE *fp;
    void *p;
    //char* p;//use char* instead of void* to avoid error

    fp = fopen(file, "r");

    p = (char *)buf; //cast to avoid error
    while (len) {
        size_t s;
        s = fread(p, 1, len, fp);
        p += s;
        len -= s;
    }

    fclose(fp);
}

void init_rand_for_permutation(gmp_randstate_t rand, int bytes) {
    void *buf;

    buf = malloc(bytes);
    get_rand_file(buf, bytes, "/dev/urandom");

    gmp_randinit_default(rand);
    gmp_randseed_ui(rand, (unsigned long)buf);

    free(buf);
}

/* 
    Generate a uniformly random number from [in_lower_bound, in_upper_bound) 
*/
unsigned long generate_random_number(gmp_randstate_t in_state,
                                     unsigned long in_lower_bound, unsigned long in_upper_bound) {
    unsigned long r;
    r = gmp_urandomm_ui(in_state, in_upper_bound - in_lower_bound);
    return (r + in_lower_bound);

}

long* generate_random_permutation(gmp_randstate_t rand, long in_num_elements) {

    long *permutation;
    permutation = (long *)malloc(sizeof(long) * in_num_elements);

    long i;
    for (i = 0; i < in_num_elements; i = i + 1) {
        permutation[i] = i;
    }

    long j;
    long temp;
    for (i = 0; i < in_num_elements; i = i + 1) {
        //generate a uniformly random index j from i to "in_num_elements - 1"
        j = generate_random_number(rand, i, in_num_elements);

        //swap permutation[i] and permutation[j]
        temp = permutation[i];
        permutation[i] = permutation[j];
        permutation[j] = temp;
    }

    return permutation;
}

long* invert_permutation(long *in_permutation, long in_num_elements) {

    long *inverse_permutation = (long *)malloc(sizeof(long) * in_num_elements);

    long i;
    for (i = 0; i < in_num_elements; i = i + 1) {
        inverse_permutation[in_permutation[i]] = i;
    }

    return inverse_permutation;
}

void display_permutation(long *in_permutation, long in_num_elements) {
    long i;
    for (i = 0; i < in_num_elements; i = i + 1) {
        printf("in_permutation[%ld]: %ld\n", i, in_permutation[i]);
    }
}

/*
    Shuffle in_elements according to in_permutation given. 
*/
long** shuffle(long **in_elements, long in_num_elements, long *in_permutation) {

    long **out_elements = (long **)malloc(sizeof(long *) * in_num_elements);
    long i;

    for (i = 0; i < in_num_elements; i = i + 1) {
        out_elements[i] = (long *)malloc(sizeof(long));
    }

    for (i = 0; i < in_num_elements; i = i + 1) {
        *(out_elements[in_permutation[i]]) = *(in_elements[i]);
    }

    return out_elements;
}

paillier_ciphertext_t** shuffle_paillier_ciphertexts(paillier_ciphertext_t **out_ciphertexts,
                                                     paillier_ciphertext_t **in_ciphertexts,
                                                     long in_num_elements, long *in_permutation) {

    if (!out_ciphertexts) {
        out_ciphertexts = initialize_paillier_ciphertexts_1_d(in_num_elements);
    }

    long i;
    for (i = 0; i < in_num_elements; i = i + 1) {
        mpz_set(out_ciphertexts[in_permutation[i]]->c, in_ciphertexts[i]->c);
    }

    return out_ciphertexts;

}

void display_array(long **in_elements, long in_num_elements) {

    long i;
    for (i = 0; i < in_num_elements; i = i + 1) {
        printf("*(in_elements[%ld]): %ld\n", i, *(in_elements[i]));
    }

}

//secure primitives/protocols
void execute_smp_C_1(paillier_ciphertext_t *out_enc_a_times_b,
                     paillier_ciphertext_t *in_enc_a, paillier_ciphertext_t *in_enc_b,
                     paillier_pubkey_t *in_pk, int in_sock_fd) {

    //pick r_a, r_b
    paillier_plaintext_t *r_a = 0;
    paillier_plaintext_t *r_b = 0;

    r_a = generate_random_plaintext(r_a, in_pk, paillier_get_rand_devurandom);
    r_b = generate_random_plaintext(r_b, in_pk, paillier_get_rand_devurandom);

#ifdef DEBUG_SMP_PROTOCOL
    gmp_printf("r_a->m: %Zd\n", r_a->m);
    gmp_printf("r_b->m: %Zd\n", r_b->m);
#endif

    //compute E(r_a), E(r_b)
    paillier_ciphertext_t *enc_r_a = 0;
    paillier_ciphertext_t *enc_r_b = 0;
    enc_r_a = paillier_enc(enc_r_a, in_pk, r_a, paillier_get_rand_devurandom);
    enc_r_b = paillier_enc(enc_r_b, in_pk, r_b, paillier_get_rand_devurandom);

    //compute a_prime = E(a)E(r_a), b_prime = E(b)E(r_b)
    paillier_ciphertext_t *a_prime = paillier_create_enc_zero();
    paillier_ciphertext_t *b_prime = paillier_create_enc_zero();
    paillier_mul(in_pk, a_prime, in_enc_a, enc_r_a);
    paillier_mul(in_pk, b_prime, in_enc_b, enc_r_b);

    //send a_prime, b_prime to the client
    socket_send_paillier_ciphertext_t(in_sock_fd, a_prime);
    socket_send_paillier_ciphertext_t(in_sock_fd, b_prime);

    //receive h' = E(h) from the client
    paillier_ciphertext_t *h_prime = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &h_prime);
#ifdef DEBUG_SMP_PROTOCOL
    gmp_printf("h_prime->c: %Zd\n", h_prime->c);
#endif

    //compute s, s_prime, and E(r_a * r_b)^{N-1}
    paillier_ciphertext_t *s = paillier_create_enc_zero();
    paillier_ciphertext_t *s_prime = paillier_create_enc_zero();

    mpz_t raw_negative_r_a_times_r_b;
    mpz_init(raw_negative_r_a_times_r_b);
    mpz_mul(raw_negative_r_a_times_r_b, r_a->m, r_b->m);
    mpz_sub(raw_negative_r_a_times_r_b, in_pk->n, raw_negative_r_a_times_r_b);
    mpz_mod(raw_negative_r_a_times_r_b, raw_negative_r_a_times_r_b, in_pk->n);
    paillier_plaintext_t *negative_r_a_times_r_b = 0;
    negative_r_a_times_r_b = paillier_plaintext_from_mpz_t(&raw_negative_r_a_times_r_b);

    paillier_ciphertext_t *enc_negative_r_a_times_r_b = 0;
    enc_negative_r_a_times_r_b =
        paillier_enc(enc_negative_r_a_times_r_b, in_pk, negative_r_a_times_r_b, paillier_get_rand_devurandom);

    mpz_t raw_n_minus_r_a;
    mpz_t raw_n_minus_r_b;
    mpz_init(raw_n_minus_r_a);
    mpz_init(raw_n_minus_r_b);
    mpz_sub(raw_n_minus_r_a, in_pk->n, r_a->m);
    mpz_sub(raw_n_minus_r_b, in_pk->n, r_b->m);

    paillier_plaintext_t *n_minus_r_a = 0;
    paillier_plaintext_t *n_minus_r_b = 0;
    n_minus_r_a = paillier_plaintext_from_mpz_t(&raw_n_minus_r_a);
    n_minus_r_b = paillier_plaintext_from_mpz_t(&raw_n_minus_r_b);

#ifdef DEBUG_SMP_PROTOCOL
    gmp_printf("n_minus_r_a: %Zd\n", n_minus_r_a->m);
    gmp_printf("n_minus_r_b: %Zd\n", n_minus_r_b->m);
#endif

    paillier_exp(in_pk, s, in_enc_a, n_minus_r_b);
    paillier_mul(in_pk, s, s, h_prime);

    paillier_exp(in_pk, s_prime, in_enc_b, n_minus_r_a);
    paillier_mul(in_pk, s_prime, s_prime, s);

    paillier_mul(in_pk, out_enc_a_times_b, s_prime, enc_negative_r_a_times_r_b);

    //clean-up
    paillier_freeplaintext(r_a);
    paillier_freeplaintext(r_b);
    paillier_freeciphertext(enc_r_a);
    paillier_freeciphertext(enc_r_b);

    paillier_freeciphertext(a_prime);
    paillier_freeciphertext(b_prime);

    paillier_freeciphertext(h_prime);

    paillier_freeciphertext(s);
    paillier_freeciphertext(s_prime);

    mpz_clear(raw_negative_r_a_times_r_b);
    paillier_freeplaintext(negative_r_a_times_r_b);
    paillier_freeciphertext(enc_negative_r_a_times_r_b);

    mpz_clear(raw_n_minus_r_a);
    mpz_clear(raw_n_minus_r_b);
    paillier_freeplaintext(n_minus_r_a);
    paillier_freeplaintext(n_minus_r_b);

}

void execute_smp_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_a_times_b,
                                            paillier_ciphertext_t *in_enc_a, paillier_ciphertext_t *in_enc_b,
                                            paillier_pubkey_t *in_pk, int in_sock_fd,
                                            paillier_plaintext_t *in_negative_r_a, paillier_plaintext_t *in_negative_r_b,
                                            paillier_ciphertext_t *in_enc_r_a, paillier_ciphertext_t *in_enc_r_b,
                                            paillier_ciphertext_t *in_enc_negative_r_a_times_r_b) {

    //compute a_prime = E(a)E(r_a), b_prime = E(b)E(r_b)
    paillier_ciphertext_t *a_prime = paillier_create_enc_zero();
    paillier_ciphertext_t *b_prime = paillier_create_enc_zero();
    paillier_mul(in_pk, a_prime, in_enc_a, in_enc_r_a);
    paillier_mul(in_pk, b_prime, in_enc_b, in_enc_r_b);

    //send a_prime, b_prime to the corresponding C_2
    socket_send_paillier_ciphertext_t(in_sock_fd, a_prime);
    socket_send_paillier_ciphertext_t(in_sock_fd, b_prime);

    //receive h' = E(h) from the corresponding C_2
    paillier_ciphertext_t *h_prime = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &h_prime);

    //compute s, s_prime, and E(r_a * r_b)^{N-1}
    paillier_ciphertext_t *s = paillier_create_enc_zero();
    paillier_ciphertext_t *s_prime = paillier_create_enc_zero();

    paillier_exp(in_pk, s, in_enc_a, in_negative_r_b);
    paillier_mul(in_pk, s, s, h_prime);

    paillier_exp(in_pk, s_prime, in_enc_b, in_negative_r_a);
    paillier_mul(in_pk, s_prime, s_prime, s);

    paillier_mul(in_pk, out_enc_a_times_b, s_prime, in_enc_negative_r_a_times_r_b);

    //do not forget to clean-up
    paillier_freeciphertext(a_prime);
    paillier_freeciphertext(b_prime);
    paillier_freeciphertext(h_prime);
    paillier_freeciphertext(s);
    paillier_freeciphertext(s_prime);

}

void execute_smp_pipelined_C_1(paillier_ciphertext_t **out_enc_a_times_b_s,
                               paillier_ciphertext_t **in_enc_a_s, paillier_ciphertext_t **in_enc_b_s,
                               paillier_pubkey_t *in_pk, int in_sock_fd,
                               paillier_plaintext_t **in_negative_r_a_s, paillier_plaintext_t **in_negative_r_b_s,
                               paillier_ciphertext_t **in_enc_r_a_s, paillier_ciphertext_t **in_enc_r_b_s,
                               paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s,
                               int in_num_smp) {

    //below are added on 2015/03/11
#ifdef TIME_C_1
    timeval before_step_1;
    timeval after_step_1;
    long long time_spent_in_step_1 = 0;

    timeval before_step_3;
    timeval after_step_3;
    long long time_spent_in_step_3 = 0;

    gettimeofday(&before_step_1, NULL);
#endif
    //above are added on 2015/03/11

    int i;

    paillier_ciphertext_t **a_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);
    paillier_ciphertext_t **b_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);

    paillier_ciphertext_t **h_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);
    paillier_ciphertext_t **s_s = initialize_paillier_ciphertexts_1_d(in_num_smp);
    paillier_ciphertext_t **s_prime_s = initialize_paillier_ciphertexts_1_d(in_num_smp);

    for (i = 0; i < in_num_smp; i = i + 1) {

        paillier_mul(in_pk, a_prime_s[i], in_enc_a_s[i], in_enc_r_a_s[i]);
        paillier_mul(in_pk, b_prime_s[i], in_enc_b_s[i], in_enc_r_b_s[i]);

    }

    //below are added on 2015/03/11
#ifdef TIME_C_1
    gettimeofday(&after_step_1, NULL);
    time_spent_in_step_1 =
        ((after_step_1.tv_sec * 1000000 + after_step_1.tv_usec) -
         (before_step_1.tv_sec * 1000000 + before_step_1.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_1;
#endif
    //above are added on 2015/03/11

    socket_send_paillier_ciphertexts(in_sock_fd, a_prime_s, in_num_smp);
    socket_send_paillier_ciphertexts(in_sock_fd, b_prime_s, in_num_smp);

    for (i = 0; i < in_num_smp; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(h_prime_s[i]));

        //below is added on 2015/03/15
#ifdef TIME_C_1
        gettimeofday(&before_step_3, NULL);
#endif
        //above is added on 2015/03/15

        paillier_exp(in_pk, s_s[i], in_enc_a_s[i], in_negative_r_b_s[i]);
        paillier_mul(in_pk, s_s[i], s_s[i], h_prime_s[i]);

        paillier_exp(in_pk, s_prime_s[i], in_enc_b_s[i], in_negative_r_a_s[i]);
        paillier_mul(in_pk, s_prime_s[i], s_prime_s[i], s_s[i]);

        paillier_mul(in_pk, out_enc_a_times_b_s[i], s_prime_s[i], in_enc_negative_r_a_times_r_b_s[i]);


        if (i % 100 == 0) {
            printf("%d-th pipelined smp done\n", i);
        }

        //below are added on 2015/03/11
#ifdef TIME_C_1
        gettimeofday(&after_step_3, NULL);
        time_spent_in_step_3 = ((after_step_3.tv_sec * 1000000 + after_step_3.tv_usec) -
                                (before_step_3.tv_sec * 1000000 + before_step_3.tv_usec));
        time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_3;
#endif
        //above are added on 2015/03/11

    }

    //clean-up
    free_paillier_ciphertexts_1_d(in_num_smp, a_prime_s);
    free_paillier_ciphertexts_1_d(in_num_smp, b_prime_s);

    free_paillier_ciphertexts_1_d(in_num_smp, h_prime_s);
    free_paillier_ciphertexts_1_d(in_num_smp, s_s);
    free_paillier_ciphertexts_1_d(in_num_smp, s_prime_s);

}

void execute_ssp_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_a_squared,
                                            paillier_ciphertext_t *in_enc_a,
                                            paillier_pubkey_t *in_pk, int in_sock_fd,
                                            paillier_plaintext_t *in_negative_two_times_r_a,
                                            paillier_ciphertext_t *in_enc_r_a,
                                            paillier_ciphertext_t *in_enc_negative_r_a_squared) {

    //compute a_prime = E(a)E(r_a)
    paillier_ciphertext_t *a_prime = paillier_create_enc_zero();
    paillier_mul(in_pk, a_prime, in_enc_a, in_enc_r_a);

    //send a_prime to the corresponding C_2
    socket_send_paillier_ciphertext_t(in_sock_fd, a_prime);

    //receive h' = E(h) from the corresponding C_2
    paillier_ciphertext_t *h_prime = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &h_prime);

    //compute s, s_prime, and E(r_a * r_b)^{N-1}
    paillier_ciphertext_t *s = paillier_create_enc_zero();

    paillier_exp(in_pk, s, in_enc_a, in_negative_two_times_r_a);
    paillier_mul(in_pk, s, s, h_prime);
    paillier_mul(in_pk, out_enc_a_squared, s, in_enc_negative_r_a_squared);

    //clean-up
    paillier_freeciphertext(a_prime);
    paillier_freeciphertext(h_prime);
    paillier_freeciphertext(s);

}

void execute_ssp_pipelined_C_1(paillier_ciphertext_t **out_enc_a_squared_s,
                               paillier_ciphertext_t **in_enc_a_s,
                               paillier_pubkey_t *in_pk, int in_sock_fd,
                               paillier_plaintext_t **in_negative_two_times_r_a_s,
                               paillier_ciphertext_t **in_enc_r_a_s,
                               paillier_ciphertext_t **in_enc_negative_r_a_squared_s,
                               int in_num_ssp) {

#ifdef TIME_C_1
    timeval before_step_1;
    timeval after_step_1;
    long long time_spent_in_step_1 = 0;

    timeval before_step_3;
    timeval after_step_3;
    long long time_spent_in_step_3 = 0;

    gettimeofday(&before_step_1, NULL);
#endif

    int i;
    paillier_ciphertext_t **a_prime_s = initialize_paillier_ciphertexts_1_d(in_num_ssp);
    for (i = 0; i < in_num_ssp; i = i + 1) {
        paillier_mul(in_pk, a_prime_s[i], in_enc_a_s[i], in_enc_r_a_s[i]);
    }

#ifdef TIME_C_1
    gettimeofday(&after_step_1, NULL);
    time_spent_in_step_1 =
        ((after_step_1.tv_sec * 1000000 + after_step_1.tv_usec) -
         (before_step_1.tv_sec * 1000000 + before_step_1.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_1;
#endif

    socket_send_paillier_ciphertexts(in_sock_fd, a_prime_s, in_num_ssp);

    paillier_ciphertext_t **h_prime_s = initialize_paillier_ciphertexts_1_d(in_num_ssp);
    paillier_ciphertext_t **s_s = initialize_paillier_ciphertexts_1_d(in_num_ssp);
    for (i = 0; i < in_num_ssp; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(h_prime_s[i]));

#ifdef TIME_C_1
        gettimeofday(&before_step_3, NULL);
#endif

        paillier_exp(in_pk, s_s[i], in_enc_a_s[i], in_negative_two_times_r_a_s[i]);
        paillier_mul(in_pk, s_s[i], s_s[i], h_prime_s[i]);
        paillier_mul(in_pk, out_enc_a_squared_s[i], s_s[i], in_enc_negative_r_a_squared_s[i]);

        if (i % 100 == 0) {
            printf("%d-th pipelined ssp done\n", i);
        }

#ifdef TIME_C_1
        gettimeofday(&after_step_3, NULL);
        time_spent_in_step_3 =
            ((after_step_3.tv_sec * 1000000 + after_step_3.tv_usec) -
             (before_step_3.tv_sec * 1000000 + before_step_3.tv_usec));
        time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_3;
#endif
    }

    free_paillier_ciphertexts_1_d(in_num_ssp, a_prime_s);
    free_paillier_ciphertexts_1_d(in_num_ssp, h_prime_s);
    free_paillier_ciphertexts_1_d(in_num_ssp, s_s);

}

void execute_ssed_C_1(paillier_ciphertext_t *out_squared_distance,
                      paillier_ciphertext_t **in_vector_x, paillier_ciphertext_t **in_vector_y,
                      int in_num_dimensions,
                      paillier_pubkey_t *in_pk, int in_sock_fd) {

    //initialize an array for holding E(x_i - y_i)
    paillier_ciphertext_t **enc_difference_s;
    enc_difference_s = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
    int i;
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        enc_difference_s[i] = paillier_create_enc_zero();
    }

    //initialize an array for holding E((x_i - y_i)^2)
    paillier_ciphertext_t **enc_squared_difference_s;
    enc_squared_difference_s = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        enc_squared_difference_s[i] = paillier_create_enc_zero();
    }

    //Step 1 in SSED
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        mpz_invert(enc_difference_s[i]->c, in_vector_y[i]->c, in_pk->n_squared);
        paillier_mul(in_pk, enc_difference_s[i], enc_difference_s[i], in_vector_x[i]);
    }

    //Step 2 in SSED
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        execute_smp_C_1(enc_squared_difference_s[i], enc_difference_s[i], enc_difference_s[i], in_pk, in_sock_fd);
    }

    //Step 3 in SSED
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        paillier_mul(in_pk, out_squared_distance, out_squared_distance, enc_squared_difference_s[i]);
    }

    //clean-up
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        paillier_freeciphertext(enc_difference_s[i]);
        paillier_freeciphertext(enc_squared_difference_s[i]);
    }
    free(enc_difference_s);
    free(enc_squared_difference_s);

}

void execute_ssed_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_squared_distance,
                                             paillier_ciphertext_t **in_vector_x, paillier_ciphertext_t **in_vector_y,
                                             int in_num_dimensions,
                                             paillier_pubkey_t *in_pk, int in_sock_fd,
                                             paillier_ciphertext_t **in_enc_r_a_s_ssp,
                                             paillier_ciphertext_t **in_enc_negative_r_a_squared_s_ssp,
                                             paillier_plaintext_t **in_negative_two_times_r_a_s_ssp) {

    //initialize an array for holding E(x_i - y_i)
    paillier_ciphertext_t **enc_difference_s;
    enc_difference_s = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
    int i;
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        enc_difference_s[i] = paillier_create_enc_zero();
    }

    //initialize an array for holding E((x_i - y_i)^2)
    paillier_ciphertext_t **enc_squared_difference_s;
    enc_squared_difference_s = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        enc_squared_difference_s[i] = paillier_create_enc_zero();
    }

    //Step 1 in SSED
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        mpz_invert(enc_difference_s[i]->c, in_vector_y[i]->c, in_pk->n_squared);
        paillier_mul(in_pk, enc_difference_s[i], enc_difference_s[i], in_vector_x[i]);
    }

    //Step 2 in SSED
    for (i = 0; i < in_num_dimensions; i = i + 1) {

        execute_ssp_precomputed_randomness_C_1(enc_squared_difference_s[i],
                                               enc_difference_s[i],
                                               in_pk, in_sock_fd,
                                               in_negative_two_times_r_a_s_ssp[i],
                                               in_enc_r_a_s_ssp[i],
                                               in_enc_negative_r_a_squared_s_ssp[i]);

    }

    //Step 3 in SSED
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        paillier_mul(in_pk, out_enc_squared_distance, out_enc_squared_distance, enc_squared_difference_s[i]);
    }

    //clean-up
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        paillier_freeciphertext(enc_difference_s[i]);
        paillier_freeciphertext(enc_squared_difference_s[i]);
    }
    free(enc_difference_s);
    free(enc_squared_difference_s);

}

void execute_ssed_pipelined_C_1(paillier_ciphertext_t *out_enc_squared_distance,
                                paillier_ciphertext_t **in_vector_x, paillier_ciphertext_t **in_vector_y,
                                int in_num_dimensions,
                                paillier_pubkey_t *in_pk, int in_sock_fd,
                                paillier_ciphertext_t **in_enc_r_a_s_ssp,
                                paillier_ciphertext_t **in_enc_negative_r_a_squared_s_ssp,
                                paillier_plaintext_t **in_negative_two_times_r_a_s_ssp) {

#ifdef TIME_C_1
    timeval before_step_1;
    timeval after_step_1;
    long long time_spent_in_step_1 = 0;

    timeval before_step_3;
    timeval after_step_3;
    long long time_spent_in_step_3 = 0;
#endif

    //initialize an array for holding E(x_i - y_i)
    paillier_ciphertext_t **enc_difference_s;
    enc_difference_s = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
    int i;
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        enc_difference_s[i] = paillier_create_enc_zero();
    }

    //initialize an array for holding E((x_i - y_i)^2)
    paillier_ciphertext_t **enc_squared_difference_s;
    enc_squared_difference_s = (paillier_ciphertext_t **)malloc(sizeof(paillier_ciphertext_t *) * in_num_dimensions);
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        enc_squared_difference_s[i] = paillier_create_enc_zero();
    }

    //Step 1 in SSED
#ifdef TIME_C_1
    gettimeofday(&before_step_1, NULL);
#endif

    for (i = 0; i < in_num_dimensions; i = i + 1) {
        mpz_invert(enc_difference_s[i]->c, in_vector_y[i]->c, in_pk->n_squared);
        paillier_mul(in_pk, enc_difference_s[i], enc_difference_s[i], in_vector_x[i]);
    }

#ifdef TIME_C_1
    gettimeofday(&after_step_1, NULL);
    time_spent_in_step_1 =
        ((after_step_1.tv_sec * 1000000 + after_step_1.tv_usec) -
         (before_step_1.tv_sec * 1000000 + before_step_1.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_1;
#endif

    //Step 2 in SSED
    execute_ssp_pipelined_C_1(enc_squared_difference_s,
                              enc_difference_s,
                              in_pk, in_sock_fd,
                              in_negative_two_times_r_a_s_ssp,
                              in_enc_r_a_s_ssp,
                              in_enc_negative_r_a_squared_s_ssp,
                              in_num_dimensions);

    //Step 3 in SSED
#ifdef TIME_C_1
    gettimeofday(&before_step_3, NULL);
#endif

    for (i = 0; i < in_num_dimensions; i = i + 1) {
        paillier_mul(in_pk, out_enc_squared_distance, out_enc_squared_distance, enc_squared_difference_s[i]);
    }

#ifdef TIME_C_1
    gettimeofday(&after_step_3, NULL);
    time_spent_in_step_3 =
        ((after_step_3.tv_sec * 1000000 + after_step_3.tv_usec) -
         (before_step_3.tv_sec * 1000000 + before_step_3.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_3;
#endif


    //clean-up
    for (i = 0; i < in_num_dimensions; i = i + 1) {
        paillier_freeciphertext(enc_difference_s[i]);
        paillier_freeciphertext(enc_squared_difference_s[i]);
    }
    free(enc_difference_s);
    free(enc_squared_difference_s);

}

void execute_ssed_op_C_1(paillier_ciphertext_t *out_squared_distance,
                         paillier_ciphertext_t **in_enc_t_i,
                         paillier_ciphertext_t *in_b_prime,
                         paillier_ciphertext_t **in_a_prime_h,
                         int in_num_dimensions,
                         paillier_pubkey_t *in_pk, int in_sock_fd) {


    //initialize a_i[s] for s from 0 to "in_num_dimensions - 1"
    paillier_ciphertext_t **a_i = initialize_paillier_ciphertexts_1_d(in_num_dimensions);

    int s;
    for (s = 0; s < in_num_dimensions; s = s + 1) {

        execute_smp_C_1(a_i[s], in_b_prime, in_enc_t_i[s], in_pk, in_sock_fd);

    }

    execute_ssed_C_1(out_squared_distance, a_i, in_a_prime_h, in_num_dimensions, in_pk, in_sock_fd);

    //clean-up
    free_paillier_ciphertexts_1_d(in_num_dimensions, a_i);

}

void execute_ssed_op_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_squared_distance,
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
                                                paillier_plaintext_t **in_negative_two_times_r_a_s_ssp) {

    //initialize a_i[s] for s from 0 to "in_num_dimensions - 1"
    paillier_ciphertext_t **a_i = initialize_paillier_ciphertexts_1_d(in_num_dimensions);

    int s;
    for (s = 0; s < in_num_dimensions; s = s + 1) {

        execute_smp_precomputed_randomness_C_1(a_i[s], in_b_prime, in_enc_t_i[s], in_pk, in_sock_fd,
                                               in_negative_r_a_s_smp[s], in_negative_r_b_s_smp[s],
                                               in_enc_r_a_s_smp[s], in_enc_r_b_s_smp[s],
                                               in_enc_negative_r_a_times_r_b_s_smp[s]);

    }

    execute_ssed_precomputed_randomness_C_1(out_enc_squared_distance,
                                            a_i, in_a_prime_h,
                                            in_num_dimensions,
                                            in_pk, in_sock_fd,
                                            in_enc_r_a_s_ssp,
                                            in_enc_negative_r_a_squared_s_ssp,
                                            in_negative_two_times_r_a_s_ssp);

    //clean-up
    free_paillier_ciphertexts_1_d(in_num_dimensions, a_i);

}

void execute_ssed_op_pipelined_C_1(paillier_ciphertext_t *out_enc_squared_distance,
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
                                   paillier_plaintext_t **in_negative_two_times_r_a_s_ssp) {

    //initialize a_i[s] for s from 0 to "in_num_dimensions - 1"
    paillier_ciphertext_t **a_i = initialize_paillier_ciphertexts_1_d(in_num_dimensions);

    int s;

    paillier_ciphertext_t **b_prime_s = initialize_paillier_ciphertexts_1_d(in_num_dimensions);
    for (s = 0; s < in_num_dimensions; s = s + 1) {
        mpz_set(b_prime_s[s]->c, in_b_prime->c);
    }
    execute_smp_pipelined_C_1(a_i,
                              b_prime_s, in_enc_t_i,
                              in_pk, in_sock_fd,
                              in_negative_r_a_s_smp, in_negative_r_b_s_smp,
                              in_enc_r_a_s_smp, in_enc_r_b_s_smp,
                              in_enc_negative_r_a_times_r_b_s_smp,
                              in_num_dimensions);

//  execute_ssed_precomputed_randomness_C_1(out_enc_squared_distance,
//                                          a_i, in_a_prime_h,
//                                          in_num_dimensions,
//                                          in_pk, in_sock_fd,
//                                          in_enc_r_a_s_ssp,
//                                          in_enc_negative_r_a_squared_s_ssp,
//                                          in_negative_two_times_r_a_s_ssp);

    execute_ssed_pipelined_C_1(out_enc_squared_distance,
                               a_i, in_a_prime_h,
                               in_num_dimensions,
                               in_pk, in_sock_fd,
                               in_enc_r_a_s_ssp,
                               in_enc_negative_r_a_squared_s_ssp,
                               in_negative_two_times_r_a_s_ssp);

    //clean-up
    free_paillier_ciphertexts_1_d(in_num_dimensions, a_i);

    free_paillier_ciphertexts_1_d(in_num_dimensions, b_prime_s);

}

void execute_slsb_C_1(paillier_ciphertext_t *out_enc_lsb,
                      paillier_ciphertext_t *in_T,
                      paillier_pubkey_t *in_pk, int in_sock_fd) {

    //Step 1 in SLSB, create Y == T * E(r) mod N^2 and send Y to C_2
    paillier_plaintext_t *r = 0;
    r = generate_random_plaintext(r, in_pk, paillier_get_rand_devurandom);
#ifdef DEBUG_SLSB_PROTOCOL
    gmp_printf("r: %Zd\n", r->m);
#endif

    paillier_ciphertext_t *enc_r = 0;
    enc_r = paillier_enc(enc_r, in_pk, r, paillier_get_rand_devurandom);

    paillier_ciphertext_t *Y = paillier_create_enc_zero();

    paillier_mul(in_pk, Y, in_T, enc_r);

    //Step 1(b) in SLSB
    socket_send_paillier_ciphertext_t(in_sock_fd, Y);

    //Step 3(a) in SLSB, receive alpha from C_2
    paillier_ciphertext_t *alpha = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &alpha);

    //Step 3(b) in SLSB,
    if (mpz_tstbit(r->m, 0) == 0) {
        //when r is even
        mpz_set(out_enc_lsb->c, alpha->c);
    } else {
        //when r is odd
        mpz_invert(out_enc_lsb->c, alpha->c, in_pk->n_squared);
        mpz_mul(out_enc_lsb->c, out_enc_lsb->c, in_pk->n_plusone);
        mpz_mod(out_enc_lsb->c, out_enc_lsb->c, in_pk->n_squared);
    }


    //clean-up
    paillier_freeplaintext(r);
    paillier_freeciphertext(enc_r);
    paillier_freeciphertext(Y);
    paillier_freeciphertext(alpha);
}

void execute_slsb_precomputed_randomness_C_1(paillier_ciphertext_t *out_enc_lsb,
                                             paillier_ciphertext_t *in_T,
                                             paillier_pubkey_t *in_pk, int in_sock_fd,
                                             paillier_plaintext_t *in_r,
                                             paillier_ciphertext_t *in_enc_r) {

    //Step 1 in SLSB, create Y == T * E(r) mod N^2 and send Y to C_2
    paillier_ciphertext_t *Y = paillier_create_enc_zero();
    paillier_mul(in_pk, Y, in_T, in_enc_r);

    //Step 1(b) in SLSB
    socket_send_paillier_ciphertext_t(in_sock_fd, Y);

    //Step 3(a) in SLSB, receive alpha from C_2
    paillier_ciphertext_t *alpha = 0;
    socket_receive_paillier_ciphertext_t(in_sock_fd, &alpha);

    //Step 3(b) in SLSB,
    if (mpz_tstbit(in_r->m, 0) == 0) {
        //when r is even
        mpz_set(out_enc_lsb->c, alpha->c);
    } else {
        //when r is odd
        mpz_invert(out_enc_lsb->c, alpha->c, in_pk->n_squared);
        mpz_mul(out_enc_lsb->c, out_enc_lsb->c, in_pk->n_plusone);
        mpz_mod(out_enc_lsb->c, out_enc_lsb->c, in_pk->n_squared);
    }

    //clean-up
    paillier_freeciphertext(Y);
    paillier_freeciphertext(alpha);

}

/*
It is assumed that out_enc_bits[0], ..., out_enc_bits[in_bit_length - 1] have been 
initialized at the invocation of the protocol. 
*/
void execute_sbd_C_1(paillier_ciphertext_t **out_enc_bits,
                     paillier_ciphertext_t *in_enc_x,
                     paillier_pubkey_t *in_pk, paillier_plaintext_t *in_one_half,
                     int in_bit_length, int in_sock_fd) {

    int i;

    //T <- E(x)
    paillier_ciphertext_t *T;
    T = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
    mpz_init(T->c);
    mpz_init_set(T->c, in_enc_x->c);

    //initialize the intermediate variable, i.e., Z
    paillier_ciphertext_t *Z;
    Z = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
    mpz_init(Z->c);

    for (i = 0; i < in_bit_length; i = i + 1) {
        //E(x_i) <- Enc_LSB(T, i)
        execute_slsb_C_1(out_enc_bits[i], T, in_pk, in_sock_fd);

        //send E(x_i) to C_2 to check the correctness of sbd (for debugging)
        //socket_send_paillier_ciphertext_t(in_sock_fd, out_enc_bits[i]);

        //Z <- E(x_i)^{-1}
        mpz_invert(Z->c, out_enc_bits[i]->c, in_pk->n_squared);

        //Z <- Z * T
        paillier_mul(in_pk, Z, Z, T);

        //T <- Z^{1/2}
        paillier_exp(in_pk, T, Z, in_one_half);
    }



    //clean-up
    paillier_freeciphertext(T);
    paillier_freeciphertext(Z);

}

void execute_sbd_precomputed_randomness_C_1(paillier_ciphertext_t **out_enc_bits,
                                            paillier_ciphertext_t *in_enc_x,
                                            paillier_pubkey_t *in_pk, paillier_plaintext_t *in_one_half,
                                            int in_bit_length, int in_sock_fd,
                                            paillier_plaintext_t **in_r_s,
                                            paillier_ciphertext_t **in_enc_r_s) {

    int i;

    //T <- E(x)
    paillier_ciphertext_t *T;
    T = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
    mpz_init(T->c);
    mpz_init_set(T->c, in_enc_x->c);

    //initialize the intermediate variable, i.e., Z
    paillier_ciphertext_t *Z;
    Z = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
    mpz_init(Z->c);

    for (i = 0; i < in_bit_length; i = i + 1) {
        //E(x_i) <- Enc_LSB(T, i)
        execute_slsb_precomputed_randomness_C_1(out_enc_bits[i],
                                                T,
                                                in_pk, in_sock_fd,
                                                in_r_s[i],
                                                in_enc_r_s[i]);

        //Z <- E(x_i)^{-1}
        mpz_invert(Z->c, out_enc_bits[i]->c, in_pk->n_squared);

        //Z <- Z * T
        paillier_mul(in_pk, Z, Z, T);

        //T <- Z^{1/2}
        paillier_exp(in_pk, T, Z, in_one_half);
    }



    //clean-up
    paillier_freeciphertext(T);
    paillier_freeciphertext(Z);

}

void execute_sbd_pipelined_C_1(paillier_ciphertext_t ***out_enc_bits,
                               paillier_ciphertext_t **in_enc_x_s,
                               paillier_pubkey_t *in_pk, paillier_plaintext_t *in_one_half,
                               int in_bit_length, int in_sock_fd,
                               paillier_plaintext_t ***in_r_s,
                               paillier_ciphertext_t ***in_enc_r_s,
                               int in_num_sbd) {

#ifdef TIME_C_1
    timeval before_step_1;
    timeval after_step_1;
    long long time_spent_in_step_1 = 0;

    timeval before_step_3;
    timeval after_step_3;
    long long time_spent_in_step_3 = 0;
#endif

    paillier_ciphertext_t **T_s = initialize_paillier_ciphertexts_1_d(in_num_sbd);
    paillier_ciphertext_t *Y = paillier_create_enc_zero();
    paillier_ciphertext_t *alpha = paillier_create_enc_zero();
    paillier_ciphertext_t *Z = paillier_create_enc_zero();

    int i;
    int j;
    for (i = 0; i < in_num_sbd; i = i + 1) {
        mpz_set(T_s[i]->c, in_enc_x_s[i]->c);
    }

    for (i = 0; i < in_bit_length; i = i + 1) {

        for (j = 0; j < in_num_sbd; j = j + 1) {

#ifdef TIME_C_1
            gettimeofday(&before_step_1, NULL);
#endif

            paillier_mul(in_pk, Y, T_s[j], in_enc_r_s[j][i]);

#ifdef TIME_C_1
            gettimeofday(&after_step_1, NULL);
            time_spent_in_step_1 =
                ((after_step_1.tv_sec * 1000000 + after_step_1.tv_usec) -
                 (before_step_1.tv_sec * 1000000 + before_step_1.tv_usec));
            time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_1;
#endif


            socket_send_paillier_ciphertext_t(in_sock_fd, Y);
        }

        for (j = 0; j < in_num_sbd; j = j + 1) {

            socket_receive_paillier_ciphertext_t(in_sock_fd, &(alpha));

#ifdef TIME_C_1
            gettimeofday(&before_step_3, NULL);
#endif

            //Step 3(b) in SLSB,
            if (mpz_tstbit(in_r_s[j][i]->m, 0) == 0) {
                //when r is even
                mpz_set(out_enc_bits[j][i]->c, alpha->c);
            } else {
                //when r is odd
                mpz_invert(out_enc_bits[j][i]->c, alpha->c, in_pk->n_squared);

                mpz_mul(out_enc_bits[j][i]->c, out_enc_bits[j][i]->c, in_pk->n_plusone);
                mpz_mod(out_enc_bits[j][i]->c, out_enc_bits[j][i]->c, in_pk->n_squared);
            }

            mpz_invert(Z->c, out_enc_bits[j][i]->c, in_pk->n_squared);

            paillier_mul(in_pk, Z, Z, T_s[j]);

            paillier_exp(in_pk, T_s[j], Z, in_one_half);

#ifdef TIME_C_1
            gettimeofday(&after_step_3, NULL);
            time_spent_in_step_3 =
                ((after_step_3.tv_sec * 1000000 + after_step_3.tv_usec) -
                 (before_step_3.tv_sec * 1000000 + before_step_3.tv_usec));
            time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_3;
#endif

        }

        //E(x_i) <- Encrypted_LSB(T, i)
//      for (j = 0; j < in_num_sbd; j = j + 1) {
//
//          paillier_mul(in_pk, Y, T_s[j], in_enc_r_s[j][i]);
//
//          socket_send_paillier_ciphertext_t(in_sock_fd, Y);
//
//          socket_receive_paillier_ciphertext_t(in_sock_fd, &(alpha));
//
//          //Step 3(b) in SLSB,
//          if (mpz_tstbit(in_r_s[j][i]->m, 0) == 0) {
//              //when r is even
//              mpz_set(out_enc_bits[j][i]->c, alpha->c);
//          } else {
//              //when r is odd
//              mpz_invert(out_enc_bits[j][i]->c, alpha->c, in_pk->n_squared);
//
//              mpz_mul(out_enc_bits[j][i]->c, out_enc_bits[j][i]->c, in_pk->n_plusone);
//              mpz_mod(out_enc_bits[j][i]->c, out_enc_bits[j][i]->c, in_pk->n_squared);
//          }
//
//          mpz_invert(Z->c, out_enc_bits[j][i]->c, in_pk->n_squared);
//
//          paillier_mul(in_pk, Z, Z, T_s[j]);
//
//          paillier_exp(in_pk, T_s[j], Z, in_one_half);
//
//      }

    }

    //clean-up
    free_paillier_ciphertexts_1_d(in_num_sbd, T_s);
    paillier_freeciphertext(Y);
    paillier_freeciphertext(alpha);
    paillier_freeciphertext(Z);
}

/*
It is assumed that out_x_gt_y has been initialzed before the invocation of this protocol.
*/
void execute_gt_C_1(paillier_ciphertext_t *out_enc_x_gt_y,
                    paillier_ciphertext_t **in_enc_x_bits,
                    paillier_ciphertext_t **in_enc_y_bits,
                    paillier_pubkey_t *in_pk, int in_bit_length, int in_sock_fd) {
    int i;
    //the code below is for debugging purpose
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, in_enc_x_bits[i]);
    }

    for (i = in_bit_length - 1; i >= 0; i = i - 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, in_enc_y_bits[i]);
    }
    //the code above is for debugging purpose

    //initialize necessary ciphertexts
    paillier_ciphertext_t **enc_t_s;
    enc_t_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    paillier_ciphertext_t *enc_x_0_times_y_0;
    paillier_ciphertext_t *enc_y_i_times_t_i;
    paillier_ciphertext_t *enc_negative_y_i_times_t_i;
    paillier_ciphertext_t *enc_negative_two_times_y_i_times_t_i;
    paillier_ciphertext_t *enc_w_i; //let w_i = t_i - 2 * y_i * t_i + y_i
    paillier_ciphertext_t *enc_x_i_times_w_i;
    paillier_ciphertext_t *enc_negative_x_i_times_w_i;

    enc_x_0_times_y_0 = paillier_create_enc_zero();
    enc_y_i_times_t_i = paillier_create_enc_zero();
    enc_negative_y_i_times_t_i = paillier_create_enc_zero();
    enc_negative_two_times_y_i_times_t_i = paillier_create_enc_zero();
    enc_w_i = paillier_create_enc_zero();
    enc_x_i_times_w_i = paillier_create_enc_zero();
    enc_negative_x_i_times_w_i = paillier_create_enc_zero();

    //note that enc_t_s[0] has been initialized as E(0)

    execute_smp_C_1(enc_x_0_times_y_0, in_enc_x_bits[0], in_enc_y_bits[0], in_pk, in_sock_fd);
    mpz_invert(enc_t_s[1]->c, enc_x_0_times_y_0->c, in_pk->n_squared);
    paillier_mul(in_pk, enc_t_s[1], enc_t_s[1], in_enc_x_bits[0]);

    for (i = 1; i <= in_bit_length - 2; i = i + 1) {
        //t_{i+1} <- x_i + t_i - y_i * t_i - x_i * (t_i - 2 * y_i * t_i + y_i)

        //compute E(y_i * t_i)
        execute_smp_C_1(enc_y_i_times_t_i, in_enc_y_bits[i], enc_t_s[i], in_pk, in_sock_fd);

        //compute E(w_i) = E(t_i - 2 * y_i * t_i - y_i)
        //prepare E(-y_i * t_i)
        mpz_invert(enc_negative_y_i_times_t_i->c, enc_y_i_times_t_i->c, in_pk->n_squared);

        //prepare E(-2 * y_i * t_i)
        paillier_mul(in_pk, enc_negative_two_times_y_i_times_t_i,
                     enc_negative_y_i_times_t_i, enc_negative_y_i_times_t_i);

        //ready for E(w_i)
        paillier_mul(in_pk, enc_w_i, enc_t_s[i], enc_negative_two_times_y_i_times_t_i);
        paillier_mul(in_pk, enc_w_i, enc_w_i, in_enc_y_bits[i]);

        //prepare E(x_i * w_i)
        execute_smp_C_1(enc_x_i_times_w_i, in_enc_x_bits[i], enc_w_i, in_pk, in_sock_fd);

        //prepare E(-x_i * w_i)
        mpz_invert(enc_negative_x_i_times_w_i->c, enc_x_i_times_w_i->c, in_pk->n_squared);

        //ready for E(t_{i+1})
        paillier_mul(in_pk, enc_t_s[i + 1], in_enc_x_bits[i], enc_t_s[i]);
        paillier_mul(in_pk, enc_t_s[i + 1], enc_t_s[i + 1], enc_negative_y_i_times_t_i);
        paillier_mul(in_pk, enc_t_s[i + 1], enc_t_s[i + 1], enc_negative_x_i_times_w_i);
    }

    //compute E(t_m), i.e., enc_x_gt_y
    //compute E(y_{m - 1} * t_{m - 1})
    execute_smp_C_1(enc_y_i_times_t_i, in_enc_y_bits[in_bit_length - 1], enc_t_s[in_bit_length - 1],
                    in_pk, in_sock_fd);

    //compute E(w_{m - 1}) = E(t_{m - 1} - 2 * y_{m - 1} * t_{m - 1} - y_{m - 1})
    //prepare E(-y_{m - 1} * t_{m - 1})
    mpz_invert(enc_negative_y_i_times_t_i->c, enc_y_i_times_t_i->c, in_pk->n_squared);

    //prepare E(-2 * y_{m - 1} * t_{m - 1})
    paillier_mul(in_pk, enc_negative_two_times_y_i_times_t_i,
                 enc_negative_y_i_times_t_i, enc_negative_y_i_times_t_i);

    //ready for E(w_{m - 1})
    paillier_mul(in_pk, enc_w_i, enc_t_s[in_bit_length - 1], enc_negative_two_times_y_i_times_t_i);
    paillier_mul(in_pk, enc_w_i, enc_w_i, in_enc_y_bits[in_bit_length - 1]);

    //prepare E(x_{m - 1} * w_{m - 1})
    execute_smp_C_1(enc_x_i_times_w_i, in_enc_x_bits[in_bit_length - 1], enc_w_i, in_pk, in_sock_fd);

    //prepare E(-x_{m - 1} * w_{m - 1})
    mpz_invert(enc_negative_x_i_times_w_i->c, enc_x_i_times_w_i->c, in_pk->n_squared);

    //ready for E(t_{m})
    paillier_mul(in_pk, out_enc_x_gt_y, in_enc_x_bits[in_bit_length - 1], enc_t_s[in_bit_length - 1]);
    paillier_mul(in_pk, out_enc_x_gt_y, out_enc_x_gt_y, enc_negative_y_i_times_t_i);
    paillier_mul(in_pk, out_enc_x_gt_y, out_enc_x_gt_y, enc_negative_x_i_times_w_i);

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, enc_t_s);
    paillier_freeciphertext(enc_y_i_times_t_i);
    paillier_freeciphertext(enc_negative_y_i_times_t_i);
    paillier_freeciphertext(enc_negative_two_times_y_i_times_t_i);
    paillier_freeciphertext(enc_w_i);
    paillier_freeciphertext(enc_x_i_times_w_i);
    paillier_freeciphertext(enc_negative_x_i_times_w_i);
}

void execute_smin_C_1(paillier_ciphertext_t **out_enc_min_bits, paillier_ciphertext_t *out_enc_s_min,
                      gmp_randstate_t in_state,
                      paillier_ciphertext_t **in_enc_u_bits, paillier_ciphertext_t **in_enc_v_bits,
                      paillier_ciphertext_t *in_enc_s_u, paillier_ciphertext_t *in_enc_s_v,
                      paillier_ciphertext_t *in_enc_negative_one,
                      paillier_pubkey_t *in_pk, int in_bit_length, int in_sock_fd) {

    //initialize E(u_i * v_i) for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_u_i_times_v_i_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize E(-u_i * v_i) for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_negative_u_i_times_v_i_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize T_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **T_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize H_i for i from "in_bit_length" to "0"
    paillier_ciphertext_t **H_s = initialize_paillier_ciphertexts_1_d(in_bit_length + 1);

    //initialize r_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize Phi_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Phi_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize W_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **W_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize hat_r_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_hat_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize enc_hat_r_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_r_hat_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize Gamma_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Gamma_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize Gamma_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Gamma_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize r_prime_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_prime_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize L_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **L_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize L_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **L_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **M_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_tilde_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **M_tilde_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize enc_alpha
    paillier_ciphertext_t *enc_alpha = paillier_create_enc_zero();

    //initialize lambda_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **lambda_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize negative_r_hat_s for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **negative_r_hat_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize delta
    paillier_ciphertext_t *delta = paillier_create_enc_zero();

    //initialize delta_prime
    paillier_ciphertext_t *delta_prime = paillier_create_enc_zero();

    //initialize r_bar
    paillier_plaintext_t *r_bar = 0;

    //initialize enc_r_bar
    paillier_ciphertext_t *enc_r_bar = paillier_create_enc_zero();

    //initialize negative_r_bar
    paillier_plaintext_t *negative_r_bar = (paillier_plaintext_t *)malloc(sizeof(paillier_plaintext_t));
    mpz_init(negative_r_bar->m);

    //initialize theta
    paillier_ciphertext_t *theta = paillier_create_enc_zero();

    //Step 1(a)
    //Randomly choose the functionality F
    unsigned long F = generate_random_number(in_state, 0, 2);
    printf("F: %ld\n", F);

    long i;

    //Step 1(b)
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        //E(u_i * v_i) <- SMP(E(u_i), E(v_i))
        execute_smp_C_1(enc_u_i_times_v_i_s[i], in_enc_u_bits[i], in_enc_v_bits[i], in_pk, in_sock_fd);

#ifdef DEBUG_SMIN_PROTOCOL
        //check if E(u_i * v_i) is correct
        socket_send_paillier_ciphertext_t(in_sock_fd, enc_u_i_times_v_i_s[i]);
#endif

        //prepare E(-u_i * v_i)
        mpz_invert(enc_negative_u_i_times_v_i_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);

        //T_i <- E(u_i xor v_i)
        //Note that E(u_i xor v_i) = E(-u_i * v_i)^2 * E(u_i) * E(v_i)
        paillier_mul(in_pk, T_s[i], enc_negative_u_i_times_v_i_s[i], enc_negative_u_i_times_v_i_s[i]);
        paillier_mul(in_pk, T_s[i], T_s[i], in_enc_u_bits[i]);
        paillier_mul(in_pk, T_s[i], T_s[i], in_enc_v_bits[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //insert some code to check the correctness of T_s[i]
        socket_send_paillier_ciphertext_t(in_sock_fd, T_s[i]);
#endif

        //H_i <- H_{i+1}^{r_i} * T_i
        generate_random_plaintext(r_s[i], in_pk, paillier_get_rand_devurandom);
        paillier_exp(in_pk, H_s[i], H_s[i + 1], r_s[i]);
        paillier_mul(in_pk, H_s[i], H_s[i], T_s[i]);

        //Phi_i <- E(-1) * H_i
        paillier_mul(in_pk, Phi_s[i], in_enc_negative_one, H_s[i]);

        //if F == 0, indicating the guess/functionality is (u > v)
        if (F == 0) {
            //printf("case F: u > v\n");

            //W_i <- E(u_i) * E(u_i * v_i)^{-1}
            mpz_invert(W_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, W_s[i], W_s[i], in_enc_u_bits[i]);

            //Gamma_i <- E(v_i - u_i) * E(r_hat_i})
            mpz_invert(Gamma_s[i]->c, in_enc_u_bits[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_v_bits[i]);

            generate_random_plaintext(r_hat_s[i], in_pk, paillier_get_rand_devurandom);
            paillier_enc(enc_r_hat_s[i], in_pk, r_hat_s[i], paillier_get_rand_devurandom);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], enc_r_hat_s[i]);

        } else { //when F == 1, indicating the guess/functionality is (u < v)
                 //printf("case F: u < v\n");

            //W_i <- E(v_i) * E(u_i * v_i)^{-1}
            mpz_invert(W_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, W_s[i], W_s[i], in_enc_v_bits[i]);

            //Gamma_i <- E(u_i - v_i) * E(hat{r_i})
            mpz_invert(Gamma_s[i]->c, in_enc_v_bits[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_u_bits[i]);

            generate_random_plaintext(r_hat_s[i], in_pk, paillier_get_rand_devurandom);
            paillier_enc(enc_r_hat_s[i], in_pk, r_hat_s[i], paillier_get_rand_devurandom);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], enc_r_hat_s[i]);
        }

        //L_i <- W_i * Phi_i^{r_prime_i}
        generate_random_plaintext(r_prime_s[i], in_pk, paillier_get_rand_devurandom);
        paillier_exp(in_pk, L_s[i], Phi_s[i], r_prime_s[i]);
        paillier_mul(in_pk, L_s[i], L_s[i], W_s[i]);
    }

    //Step 1(c)
    r_bar = generate_random_plaintext(r_bar, in_pk, paillier_get_rand_devurandom);
    enc_r_bar = paillier_enc(enc_r_bar, in_pk, r_bar, paillier_get_rand_devurandom);
    if (F == 0) { //F: u > v

        //delta <- E(s_v - s_u) * E(r_bar)
        mpz_invert(delta->c, in_enc_s_u->c, in_pk->n_squared);
        paillier_mul(in_pk, delta, delta, in_enc_s_v);
        paillier_mul(in_pk, delta, delta, enc_r_bar);

    } else { //F == 1, i.e., F: u < v

        //delta <- E(s_u - s_v) * E(r_bar)
        mpz_invert(delta->c, in_enc_s_v->c, in_pk->n_squared);
        paillier_mul(in_pk, delta, delta, in_enc_s_u);
        paillier_mul(in_pk, delta, delta, enc_r_bar);

    }

    //Step 1(d)
    long *pi_1 = generate_random_permutation(in_state, in_bit_length);
    long *inverse_pi_1 = invert_permutation(pi_1, in_bit_length);

    long *pi_2 = generate_random_permutation(in_state, in_bit_length);
    long *inverse_pi_2 = invert_permutation(pi_2, in_bit_length);

    Gamma_prime_s = shuffle_paillier_ciphertexts(Gamma_prime_s, Gamma_s, in_bit_length, pi_1);
    L_prime_s = shuffle_paillier_ciphertexts(L_prime_s, L_s, in_bit_length, pi_2);

    //Step 1(e)
    //send delta to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, delta);

    //send Gamma_prime_s to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, Gamma_prime_s[i]);
    }

    //send L_prime_s to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, L_prime_s[i]);
    }

    //Step 2(d):
    //receive M' from C_2
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(M_prime_s[i]));

#ifdef DEBUG_SMIN_PROTOCOL
        //check if M' is correctly received
        gmp_printf("M'[%ld]: %Zd\n", i, M_prime_s[i]->c);
#endif

    }

    //receive E(alpha) from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_alpha);

    //receive delta_prime from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &delta_prime);

#ifdef DEBUG_SMIN_PROTOCOL
    gmp_printf("enc_alpha: %Zd\n", enc_alpha->c);
#endif

    //Step 3
    //Step 3(a)
    M_tilde_s = shuffle_paillier_ciphertexts(M_tilde_s, M_prime_s, in_bit_length, inverse_pi_1);

    //theta <- delta_prime * E(alpha)^{negative_r_bar}
    mpz_sub(negative_r_bar->m, in_pk->n, r_bar->m);
    paillier_exp(in_pk, theta, enc_alpha, negative_r_bar);
    paillier_mul(in_pk, theta, theta, delta_prime);

    //Step 3(b)
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {
        //lambda_i <- M_tilde_s[i] * E(alpha)^{negative_r_hat_i}
        mpz_sub(negative_r_hat_s[i]->m, in_pk->n, r_hat_s[i]->m);

        paillier_exp(in_pk, lambda_s[i], enc_alpha, negative_r_hat_s[i]);
        paillier_mul(in_pk, lambda_s[i], lambda_s[i], M_tilde_s[i]);
    }

    //Step 3(c)
    if (F == 0) { //F: u > v

        for (i = in_bit_length - 1; i >= 0; i = i - 1) {

            paillier_mul(in_pk, out_enc_min_bits[i], in_enc_u_bits[i], lambda_s[i]);

        }

        paillier_mul(in_pk, out_enc_s_min, in_enc_s_u, theta);

    } else { //when F == 1, indicating u < v

        for (i = in_bit_length - 1; i >= 0; i = i - 1) {

            paillier_mul(in_pk, out_enc_min_bits[i], in_enc_v_bits[i], lambda_s[i]);

        }

        paillier_mul(in_pk, out_enc_s_min, in_enc_s_v, theta);

    }

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, enc_u_i_times_v_i_s);
    free_paillier_ciphertexts_1_d(in_bit_length, enc_negative_u_i_times_v_i_s);
    free_paillier_ciphertexts_1_d(in_bit_length, T_s);
    free_paillier_ciphertexts_1_d(in_bit_length + 1, H_s);
    free_paillier_plaintexts_1_d(in_bit_length, r_s);
    free_paillier_ciphertexts_1_d(in_bit_length, Phi_s);
    free_paillier_ciphertexts_1_d(in_bit_length, W_s);

    free_paillier_plaintexts_1_d(in_bit_length, r_hat_s);
    free_paillier_ciphertexts_1_d(in_bit_length, enc_r_hat_s);

    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_s);
    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_prime_s);

    free_paillier_plaintexts_1_d(in_bit_length, r_prime_s);

    free(pi_1);
    free(inverse_pi_1);
    free(pi_2);
    free(inverse_pi_2);

    free_paillier_ciphertexts_1_d(in_bit_length, L_s);
    free_paillier_ciphertexts_1_d(in_bit_length, L_prime_s);

    free_paillier_ciphertexts_1_d(in_bit_length, M_prime_s);

    paillier_freeciphertext(enc_alpha);

    free_paillier_ciphertexts_1_d(in_bit_length, M_tilde_s);

    free_paillier_ciphertexts_1_d(in_bit_length, lambda_s);

    free_paillier_plaintexts_1_d(in_bit_length, negative_r_hat_s);


    paillier_freeciphertext(delta);
    paillier_freeciphertext(delta_prime);

    paillier_freeplaintext(r_bar);
    paillier_freeplaintext(negative_r_bar);

    paillier_freeciphertext(enc_r_bar);
    paillier_freeciphertext(theta);
}

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
                                             paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s_smp) {

    //initialize E(u_i * v_i) for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_u_i_times_v_i_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize E(-u_i * v_i) for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_negative_u_i_times_v_i_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize T_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **T_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize H_i for i from "in_bit_length" to "0"
    paillier_ciphertext_t **H_s = initialize_paillier_ciphertexts_1_d(in_bit_length + 1);

    //initialize r_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize Phi_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Phi_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize W_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **W_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize Gamma_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Gamma_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize Gamma_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Gamma_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize r_prime_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_prime_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize L_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **L_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize L_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **L_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **M_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_tilde_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **M_tilde_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize enc_alpha
    paillier_ciphertext_t *enc_alpha = paillier_create_enc_zero();

    //initialize lambda_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **lambda_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize delta
    paillier_ciphertext_t *delta = paillier_create_enc_zero();

    //initialize delta_prime
    paillier_ciphertext_t *delta_prime = paillier_create_enc_zero();

    //initialize theta
    paillier_ciphertext_t *theta = paillier_create_enc_zero();

    //Step 1(a)
    //Randomly choose the functionality F
    unsigned long F = generate_random_number(in_state, 0, 2);
    printf("F: %ld\n", F);

    long i;

    //Step 1(b)
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        //E(u_i * v_i) <- SMP(E(u_i), E(v_i))
        execute_smp_precomputed_randomness_C_1(enc_u_i_times_v_i_s[i],
                                               in_enc_u_bits[i], in_enc_v_bits[i],
                                               in_pk, in_sock_fd,
                                               in_negative_r_a_s_smp[i], in_negative_r_b_s_smp[i],
                                               in_enc_r_a_s_smp[i], in_enc_r_b_s_smp[i],
                                               in_enc_negative_r_a_times_r_b_s_smp[i]);


#ifdef DEBUG_SMIN_PROTOCOL
        //check if E(u_i * v_i) is correct
        socket_send_paillier_ciphertext_t(in_sock_fd, enc_u_i_times_v_i_s[i]);
#endif

        //prepare E(-u_i * v_i)
        mpz_invert(enc_negative_u_i_times_v_i_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);

        //T_i <- E(u_i xor v_i)
        //Note that E(u_i xor v_i) = E(-u_i * v_i)^2 * E(u_i) * E(v_i)
        paillier_mul(in_pk, T_s[i], enc_negative_u_i_times_v_i_s[i], enc_negative_u_i_times_v_i_s[i]);
        paillier_mul(in_pk, T_s[i], T_s[i], in_enc_u_bits[i]);
        paillier_mul(in_pk, T_s[i], T_s[i], in_enc_v_bits[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //insert some code to check the correctness of T_s[i]
        socket_send_paillier_ciphertext_t(in_sock_fd, T_s[i]);
#endif

        //H_i <- H_{i+1}^{r_i} * T_i
        generate_random_plaintext(r_s[i], in_pk, paillier_get_rand_devurandom);
        paillier_exp(in_pk, H_s[i], H_s[i + 1], r_s[i]);
        paillier_mul(in_pk, H_s[i], H_s[i], T_s[i]);

        //Phi_i <- E(-1) * H_i
        paillier_mul(in_pk, Phi_s[i], in_enc_negative_one, H_s[i]);

        //if F == 0, indicating the guess/functionality is (u > v)
        if (F == 0) {
            //printf("case F: u > v\n");

            //W_i <- E(u_i) * E(u_i * v_i)^{-1}
            mpz_invert(W_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, W_s[i], W_s[i], in_enc_u_bits[i]);

            //Gamma_i <- E(v_i - u_i) * E(r_hat_i})
            mpz_invert(Gamma_s[i]->c, in_enc_u_bits[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_v_bits[i]);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_r_hat_s[i]);

        } else { //when F == 1, indicating the guess/functionality is (u < v)
                 //printf("case F: u < v\n");

            //W_i <- E(v_i) * E(u_i * v_i)^{-1}
            mpz_invert(W_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, W_s[i], W_s[i], in_enc_v_bits[i]);

            //Gamma_i <- E(u_i - v_i) * E(hat{r_i})
            mpz_invert(Gamma_s[i]->c, in_enc_v_bits[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_u_bits[i]);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_r_hat_s[i]);
        }

        //L_i <- W_i * Phi_i^{r_prime_i}
        generate_random_plaintext(r_prime_s[i], in_pk, paillier_get_rand_devurandom);
        paillier_exp(in_pk, L_s[i], Phi_s[i], r_prime_s[i]);
        paillier_mul(in_pk, L_s[i], L_s[i], W_s[i]);
    }

    //Step 1(c)
    if (F == 0) { //F: u > v

        //delta <- E(s_v - s_u) * E(r_bar)
        mpz_invert(delta->c, in_enc_s_u->c, in_pk->n_squared);
        paillier_mul(in_pk, delta, delta, in_enc_s_v);
        paillier_mul(in_pk, delta, delta, in_enc_r_bar);

    } else { //F == 1, i.e., F: u < v

        //delta <- E(s_u - s_v) * E(r_bar)
        mpz_invert(delta->c, in_enc_s_v->c, in_pk->n_squared);
        paillier_mul(in_pk, delta, delta, in_enc_s_u);
        paillier_mul(in_pk, delta, delta, in_enc_r_bar);

    }

    //Step 1(d)
    long *pi_1 = generate_random_permutation(in_state, in_bit_length);
    long *inverse_pi_1 = invert_permutation(pi_1, in_bit_length);

    long *pi_2 = generate_random_permutation(in_state, in_bit_length);
    long *inverse_pi_2 = invert_permutation(pi_2, in_bit_length);

    Gamma_prime_s = shuffle_paillier_ciphertexts(Gamma_prime_s, Gamma_s, in_bit_length, pi_1);
    L_prime_s = shuffle_paillier_ciphertexts(L_prime_s, L_s, in_bit_length, pi_2);

    //Step 1(e)
    //send delta to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, delta);

    //send Gamma_prime_s to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, Gamma_prime_s[i]);
    }

    //send L_prime_s to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, L_prime_s[i]);
    }

    //Step 2(d):
    //receive M' from C_2
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(M_prime_s[i]));

#ifdef DEBUG_SMIN_PROTOCOL
        //check if M' is correctly received
        gmp_printf("M'[%ld]: %Zd\n", i, M_prime_s[i]->c);
#endif

    }

    //receive E(alpha) from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_alpha);

    //receive delta_prime from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &delta_prime);

#ifdef DEBUG_SMIN_PROTOCOL
    gmp_printf("enc_alpha: %Zd\n", enc_alpha->c);
#endif

    //Step 3
    //Step 3(a)
    M_tilde_s = shuffle_paillier_ciphertexts(M_tilde_s, M_prime_s, in_bit_length, inverse_pi_1);

    //theta <- delta_prime * E(alpha)^{negative_r_bar}
    paillier_exp(in_pk, theta, enc_alpha, in_negative_r_bar);
    paillier_mul(in_pk, theta, theta, delta_prime);

    //Step 3(b)
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {
        //lambda_i <- M_tilde_s[i] * E(alpha)^{negative_r_hat_i}
        paillier_exp(in_pk, lambda_s[i], enc_alpha, in_negative_r_hat_s[i]);
        paillier_mul(in_pk, lambda_s[i], lambda_s[i], M_tilde_s[i]);
    }

    //Step 3(c)
    if (F == 0) { //F: u > v

        for (i = in_bit_length - 1; i >= 0; i = i - 1) {

            paillier_mul(in_pk, out_enc_min_bits[i], in_enc_u_bits[i], lambda_s[i]);

        }

        paillier_mul(in_pk, out_enc_s_min, in_enc_s_u, theta);

    } else { //when F == 1, indicating u < v

        for (i = in_bit_length - 1; i >= 0; i = i - 1) {

            paillier_mul(in_pk, out_enc_min_bits[i], in_enc_v_bits[i], lambda_s[i]);

        }

        paillier_mul(in_pk, out_enc_s_min, in_enc_s_v, theta);

    }

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, enc_u_i_times_v_i_s);
    free_paillier_ciphertexts_1_d(in_bit_length, enc_negative_u_i_times_v_i_s);
    free_paillier_ciphertexts_1_d(in_bit_length, T_s);
    free_paillier_ciphertexts_1_d(in_bit_length + 1, H_s);
    free_paillier_plaintexts_1_d(in_bit_length, r_s);
    free_paillier_ciphertexts_1_d(in_bit_length, Phi_s);
    free_paillier_ciphertexts_1_d(in_bit_length, W_s);

    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_s);
    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_prime_s);

    free_paillier_plaintexts_1_d(in_bit_length, r_prime_s);

    free(pi_1);
    free(inverse_pi_1);
    free(pi_2);
    free(inverse_pi_2);

    free_paillier_ciphertexts_1_d(in_bit_length, L_s);
    free_paillier_ciphertexts_1_d(in_bit_length, L_prime_s);

    free_paillier_ciphertexts_1_d(in_bit_length, M_prime_s);

    paillier_freeciphertext(enc_alpha);

    free_paillier_ciphertexts_1_d(in_bit_length, M_tilde_s);

    free_paillier_ciphertexts_1_d(in_bit_length, lambda_s);

    paillier_freeciphertext(delta);
    paillier_freeciphertext(delta_prime);

    paillier_freeciphertext(theta);

}

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
                                paillier_ciphertext_t **in_enc_negative_r_a_times_r_b_s_smp) {

#ifdef TIME_C_1
    timeval before_step_1;
    timeval after_step_1;
    long long time_spent_in_step_1 = 0;

    timeval before_step_3;
    timeval after_step_3;
    long long time_spent_in_step_3 = 0;
#endif

    //initialize E(u_i * v_i) for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_u_i_times_v_i_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize E(-u_i * v_i) for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **enc_negative_u_i_times_v_i_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize T_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **T_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize H_i for i from "in_bit_length" to "0"
    paillier_ciphertext_t **H_s = initialize_paillier_ciphertexts_1_d(in_bit_length + 1);

    //initialize r_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize Phi_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Phi_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize W_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **W_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize Gamma_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Gamma_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize Gamma_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **Gamma_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize r_prime_i for i from "in_bit_length - 1" to "0"
    paillier_plaintext_t **r_prime_s = initialize_paillier_plaintexts_1_d(in_bit_length);

    //initialize L_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **L_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize L_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **L_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_prime_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **M_prime_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize M_tilde_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **M_tilde_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize enc_alpha
    paillier_ciphertext_t *enc_alpha = paillier_create_enc_zero();

    //initialize lambda_i for i from "in_bit_length - 1" to "0"
    paillier_ciphertext_t **lambda_s = initialize_paillier_ciphertexts_1_d(in_bit_length);

    //initialize delta
    paillier_ciphertext_t *delta = paillier_create_enc_zero();

    //initialize delta_prime
    paillier_ciphertext_t *delta_prime = paillier_create_enc_zero();

    //initialize theta
    paillier_ciphertext_t *theta = paillier_create_enc_zero();

    //Step 1(a)
    //Randomly choose the functionality F
    unsigned long F = generate_random_number(in_state, 0, 2);
    printf("F: %ld\n", F);

    long i;

    //Step 1(b)
    execute_smp_pipelined_C_1(enc_u_i_times_v_i_s,
                              in_enc_u_bits, in_enc_v_bits,
                              in_pk, in_sock_fd,
                              in_negative_r_a_s_smp, in_negative_r_b_s_smp,
                              in_enc_r_a_s_smp, in_enc_r_b_s_smp,
                              in_enc_negative_r_a_times_r_b_s_smp,
                              in_bit_length);

#ifdef TIME_C_1
    gettimeofday(&before_step_1, NULL);
#endif

    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        //E(u_i * v_i) <- SMP(E(u_i), E(v_i))
//      execute_smp_precomputed_randomness_C_1(enc_u_i_times_v_i_s[i],
//                                             in_enc_u_bits[i], in_enc_v_bits[i],
//                                             in_pk, in_sock_fd,
//                                             in_negative_r_a_s_smp[i], in_negative_r_b_s_smp[i],
//                                             in_enc_r_a_s_smp[i], in_enc_r_b_s_smp[i],
//                                             in_enc_negative_r_a_times_r_b_s_smp[i]);


#ifdef DEBUG_SMIN_PROTOCOL
        //check if E(u_i * v_i) is correct
        socket_send_paillier_ciphertext_t(in_sock_fd, enc_u_i_times_v_i_s[i]);
#endif

        //prepare E(-u_i * v_i)
        mpz_invert(enc_negative_u_i_times_v_i_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);

        //T_i <- E(u_i xor v_i)
        //Note that E(u_i xor v_i) = E(-u_i * v_i)^2 * E(u_i) * E(v_i)
        paillier_mul(in_pk, T_s[i], enc_negative_u_i_times_v_i_s[i], enc_negative_u_i_times_v_i_s[i]);
        paillier_mul(in_pk, T_s[i], T_s[i], in_enc_u_bits[i]);
        paillier_mul(in_pk, T_s[i], T_s[i], in_enc_v_bits[i]);

#ifdef DEBUG_SMIN_PROTOCOL
        //insert some code to check the correctness of T_s[i]
        socket_send_paillier_ciphertext_t(in_sock_fd, T_s[i]);
#endif

        //H_i <- H_{i+1}^{r_i} * T_i
        generate_random_plaintext(r_s[i], in_pk, paillier_get_rand_devurandom);
        paillier_exp(in_pk, H_s[i], H_s[i + 1], r_s[i]);
        paillier_mul(in_pk, H_s[i], H_s[i], T_s[i]);

        //Phi_i <- E(-1) * H_i
        paillier_mul(in_pk, Phi_s[i], in_enc_negative_one, H_s[i]);

        //if F == 0, indicating the guess/functionality is (u > v)
        if (F == 0) {
            //printf("case F: u > v\n");

            //W_i <- E(u_i) * E(u_i * v_i)^{-1}
            mpz_invert(W_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, W_s[i], W_s[i], in_enc_u_bits[i]);

            //Gamma_i <- E(v_i - u_i) * E(r_hat_i})
            mpz_invert(Gamma_s[i]->c, in_enc_u_bits[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_v_bits[i]);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_r_hat_s[i]);

        } else { //when F == 1, indicating the guess/functionality is (u < v)
                 //printf("case F: u < v\n");

            //W_i <- E(v_i) * E(u_i * v_i)^{-1}
            mpz_invert(W_s[i]->c, enc_u_i_times_v_i_s[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, W_s[i], W_s[i], in_enc_v_bits[i]);

            //Gamma_i <- E(u_i - v_i) * E(hat{r_i})
            mpz_invert(Gamma_s[i]->c, in_enc_v_bits[i]->c, in_pk->n_squared);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_u_bits[i]);
            paillier_mul(in_pk, Gamma_s[i], Gamma_s[i], in_enc_r_hat_s[i]);
        }

        //L_i <- W_i * Phi_i^{r_prime_i}
        generate_random_plaintext(r_prime_s[i], in_pk, paillier_get_rand_devurandom);
        paillier_exp(in_pk, L_s[i], Phi_s[i], r_prime_s[i]);
        paillier_mul(in_pk, L_s[i], L_s[i], W_s[i]);
    }

    //Step 1(c)
    if (F == 0) { //F: u > v

        //delta <- E(s_v - s_u) * E(r_bar)
        mpz_invert(delta->c, in_enc_s_u->c, in_pk->n_squared);
        paillier_mul(in_pk, delta, delta, in_enc_s_v);
        paillier_mul(in_pk, delta, delta, in_enc_r_bar);

    } else { //F == 1, i.e., F: u < v

        //delta <- E(s_u - s_v) * E(r_bar)
        mpz_invert(delta->c, in_enc_s_v->c, in_pk->n_squared);
        paillier_mul(in_pk, delta, delta, in_enc_s_u);
        paillier_mul(in_pk, delta, delta, in_enc_r_bar);

    }

    //Step 1(d)
    long *pi_1 = generate_random_permutation(in_state, in_bit_length);
    long *inverse_pi_1 = invert_permutation(pi_1, in_bit_length);

    long *pi_2 = generate_random_permutation(in_state, in_bit_length);
    long *inverse_pi_2 = invert_permutation(pi_2, in_bit_length);

    Gamma_prime_s = shuffle_paillier_ciphertexts(Gamma_prime_s, Gamma_s, in_bit_length, pi_1);
    L_prime_s = shuffle_paillier_ciphertexts(L_prime_s, L_s, in_bit_length, pi_2);

#ifdef TIME_C_1
    gettimeofday(&after_step_1, NULL);
    time_spent_in_step_1 =
        ((after_step_1.tv_sec * 1000000 + after_step_1.tv_usec) -
         (before_step_1.tv_sec * 1000000 + before_step_1.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_1;
#endif

    //Step 1(e)
    //send delta to C_1
    socket_send_paillier_ciphertext_t(in_sock_fd, delta);

    //send Gamma_prime_s to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, Gamma_prime_s[i]);
    }

    //send L_prime_s to C_1
    for (i = 0; i < in_bit_length; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, L_prime_s[i]);
    }

    //Step 2(d):
    //receive M' from C_2
    for (i = 0; i < in_bit_length; i = i + 1) {

        socket_receive_paillier_ciphertext_t(in_sock_fd, &(M_prime_s[i]));

#ifdef DEBUG_SMIN_PROTOCOL
        //check if M' is correctly received
        gmp_printf("M'[%ld]: %Zd\n", i, M_prime_s[i]->c);
#endif

    }

    //receive E(alpha) from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &enc_alpha);

    //receive delta_prime from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &delta_prime);

#ifdef DEBUG_SMIN_PROTOCOL
    gmp_printf("enc_alpha: %Zd\n", enc_alpha->c);
#endif

    //Step 3
#ifdef TIME_C_1
    gettimeofday(&before_step_3, NULL);
#endif

    //Step 3(a)
    M_tilde_s = shuffle_paillier_ciphertexts(M_tilde_s, M_prime_s, in_bit_length, inverse_pi_1);

    //theta <- delta_prime * E(alpha)^{negative_r_bar}
    paillier_exp(in_pk, theta, enc_alpha, in_negative_r_bar);
    paillier_mul(in_pk, theta, theta, delta_prime);

    //Step 3(b)
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {
        //lambda_i <- M_tilde_s[i] * E(alpha)^{negative_r_hat_i}
        paillier_exp(in_pk, lambda_s[i], enc_alpha, in_negative_r_hat_s[i]);
        paillier_mul(in_pk, lambda_s[i], lambda_s[i], M_tilde_s[i]);
    }

    //Step 3(c)
    if (F == 0) { //F: u > v

        for (i = in_bit_length - 1; i >= 0; i = i - 1) {

            paillier_mul(in_pk, out_enc_min_bits[i], in_enc_u_bits[i], lambda_s[i]);

        }

        paillier_mul(in_pk, out_enc_s_min, in_enc_s_u, theta);

    } else { //when F == 1, indicating u < v

        for (i = in_bit_length - 1; i >= 0; i = i - 1) {

            paillier_mul(in_pk, out_enc_min_bits[i], in_enc_v_bits[i], lambda_s[i]);

        }

        paillier_mul(in_pk, out_enc_s_min, in_enc_s_v, theta);

    }

#ifdef TIME_C_1
    gettimeofday(&after_step_3, NULL);
    time_spent_in_step_3 =
        ((after_step_3.tv_sec * 1000000 + after_step_3.tv_usec) -
         (before_step_3.tv_sec * 1000000 + before_step_3.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_3;
#endif

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, enc_u_i_times_v_i_s);
    free_paillier_ciphertexts_1_d(in_bit_length, enc_negative_u_i_times_v_i_s);
    free_paillier_ciphertexts_1_d(in_bit_length, T_s);
    free_paillier_ciphertexts_1_d(in_bit_length + 1, H_s);
    free_paillier_plaintexts_1_d(in_bit_length, r_s);
    free_paillier_ciphertexts_1_d(in_bit_length, Phi_s);
    free_paillier_ciphertexts_1_d(in_bit_length, W_s);

    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_s);
    free_paillier_ciphertexts_1_d(in_bit_length, Gamma_prime_s);

    free_paillier_plaintexts_1_d(in_bit_length, r_prime_s);

    free(pi_1);
    free(inverse_pi_1);
    free(pi_2);
    free(inverse_pi_2);

    free_paillier_ciphertexts_1_d(in_bit_length, L_s);
    free_paillier_ciphertexts_1_d(in_bit_length, L_prime_s);

    free_paillier_ciphertexts_1_d(in_bit_length, M_prime_s);

    paillier_freeciphertext(enc_alpha);

    free_paillier_ciphertexts_1_d(in_bit_length, M_tilde_s);

    free_paillier_ciphertexts_1_d(in_bit_length, lambda_s);

    paillier_freeciphertext(delta);
    paillier_freeciphertext(delta_prime);

    paillier_freeciphertext(theta);

}

/*
    in_enc_d_s_bits is an array of in_k bit-decomposed encrypted distances.
*/
void execute_smin_k_C_1(paillier_ciphertext_t **out_Gamma_s,
                        gmp_randstate_t in_state,
                        paillier_ciphertext_t ***in_enc_d_s_bits,
                        paillier_ciphertext_t *in_enc_negative_one,
                        paillier_pubkey_t *in_pk,
                        long in_k, int in_bit_length, int in_sock_fd) {

    long i;

    //initialize cluster_indices and enc_cluster_indices
    paillier_plaintext_t **cluster_indices = initialize_paillier_plaintexts_1_d(in_k);
    paillier_ciphertext_t **enc_cluster_indices = initialize_paillier_ciphertexts_1_d(in_k);

    for (i = 0; i < in_k; i = i + 1) {
        mpz_set_ui(cluster_indices[i]->m, i);
        paillier_enc(enc_cluster_indices[i], in_pk, cluster_indices[i], paillier_get_rand_devurandom);
    }

    //initialize (T_bits, I), T_bits is an array representing an encrypted bit-decomposed number
    paillier_ciphertext_t **T_bits = initialize_paillier_ciphertexts_1_d(in_bit_length);
    paillier_ciphertext_t *I = paillier_create_enc_zero();

    //initialzie Delta
    paillier_ciphertext_t *Delta = paillier_create_enc_zero();

    //initialize Delta_prime_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **Delta_prime_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize r_i for i from 0 to "in_k - 1"
    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(in_k);

    //initialize phi_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **phi_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize u_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **u_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize U_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **U_s = initialize_paillier_ciphertexts_1_d(in_k);

    //Step 1
    //Step 1(a): (T, I) <- SMIN((E(d_0), E(0)), (E(d_1), E(1)))
    execute_smin_C_1(T_bits, I,
                     in_state,
                     in_enc_d_s_bits[0], in_enc_d_s_bits[1],
                     enc_cluster_indices[0], enc_cluster_indices[1],
                     in_enc_negative_one,
                     in_pk, in_bit_length, in_sock_fd);

    //Step 1(b)
    //for i from 1 to "k - 2"
    //(T, I) <- SMIN((E(d_{i}), E(i)), (E(d_{i}), E(i+1)))
    for (i = 1; i < in_k - 1; i = i + 1) {

        execute_smin_C_1(T_bits, I,
                         in_state,
                         T_bits, in_enc_d_s_bits[i + 1],
                         I, enc_cluster_indices[i + 1],
                         in_enc_negative_one,
                         in_pk, in_bit_length, in_sock_fd);

    }

#ifdef DEBUG_SMIN_K_PROTOCOL
    //test if step 1 is correct
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        socket_send_paillier_ciphertext_t(in_sock_fd, T_bits[i]);

    }
    socket_send_paillier_ciphertext_t(in_sock_fd, I);
#endif

    //Step 2
    //Step 2(a): Delta <- I^{-1}
    mpz_invert(Delta->c, I->c, in_pk->n_squared);

    for (i = 0; i < in_k; i = i + 1) {
        //Delta'[i] <- E(i) * Delta
        paillier_mul(in_pk, Delta_prime_s[i], enc_cluster_indices[i], Delta);

        //phi[i] <- Delta'[i]^{r_i}
        generate_random_plaintext(r_s[i], in_pk, paillier_get_rand_devurandom);

//#ifdef DEBUG_SMIN_K_PROTOCOL
//        gmp_printf("r_s[%ld]: %Zd\n", i, r_s[i]->m);
//#endif

        paillier_exp(in_pk, phi_s[i], Delta_prime_s[i], r_s[i]);

    }

    //Step 2(c):
    //u <- pi(phi)
    long *pi = generate_random_permutation(in_state, in_k);
    long *pi_inverse = invert_permutation(pi, in_k);
    u_s = shuffle_paillier_ciphertexts(u_s, phi_s, in_k, pi);

    //send u to C_2
    for (i = 0; i < in_k; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, u_s[i]);
    }

    //Step 4(a): receive U from C_2
    for (i = 0; i < in_k; i = i + 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &(U_s[i]));
    }

    //Step 4(b):
    //Gamma <- pi^{-1}(U)
    out_Gamma_s = shuffle_paillier_ciphertexts(out_Gamma_s, U_s, in_k, pi_inverse);

    //clean-up
    free_paillier_plaintexts_1_d(in_k, cluster_indices);
    free_paillier_ciphertexts_1_d(in_k, enc_cluster_indices);

    free_paillier_ciphertexts_1_d(in_bit_length, T_bits);
    paillier_freeciphertext(I);

    paillier_freeciphertext(Delta);

    free_paillier_ciphertexts_1_d(in_k, Delta_prime_s);
    free_paillier_plaintexts_1_d(in_k, r_s);
    free_paillier_ciphertexts_1_d(in_k, phi_s);

    free_paillier_ciphertexts_1_d(in_k, u_s);

    free(pi);
    free(pi_inverse);

    free_paillier_ciphertexts_1_d(in_k, U_s);
}

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
                                               paillier_ciphertext_t **in_enc_cluster_indices) {

    long i;

    //initialize (T_bits, I), T_bits is an array representing an encrypted bit-decomposed number
    paillier_ciphertext_t **T_bits = initialize_paillier_ciphertexts_1_d(in_bit_length);
    paillier_ciphertext_t *I = paillier_create_enc_zero();

    //initialzie Delta
    paillier_ciphertext_t *Delta = paillier_create_enc_zero();

    //initialize Delta_prime_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **Delta_prime_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize r_i for i from 0 to "in_k - 1"
    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(in_k);

    //initialize phi_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **phi_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize u_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **u_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize U_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **U_s = initialize_paillier_ciphertexts_1_d(in_k);

    //Step 1
    //Step 1(a): (T, I) <- SMIN((E(d_0), E(0)), (E(d_1), E(1)))
    execute_smin_precomputed_randomness_C_1(T_bits, I,
                                            in_state,
                                            in_enc_d_s_bits[0], in_enc_d_s_bits[1],
                                            in_enc_cluster_indices[0], in_enc_cluster_indices[1],
                                            in_enc_negative_one,
                                            in_pk, in_bit_length, in_sock_fd,
                                            in_negative_r_hat_s[0], in_enc_r_hat_s[0],
                                            in_negative_r_bar_s_delta[0], in_enc_r_bar_s_delta[0],
                                            in_negative_r_a_s_smp[0], in_enc_r_a_s_smp[0],
                                            in_negative_r_b_s_smp[0], in_enc_r_b_s_smp[0],
                                            in_enc_negative_r_a_times_r_b_s_smp[0]);

    //Step 1(b)
    //for i from 1 to "k - 2"
    //(T, I) <- SMIN((E(d_{i}), E(i)), (E(d_{i+1}), E(i+1)))
    for (i = 1; i < in_k - 1; i = i + 1) {

        execute_smin_precomputed_randomness_C_1(T_bits, I,
                                                in_state,
                                                T_bits, in_enc_d_s_bits[i + 1],
                                                I, in_enc_cluster_indices[i + 1],
                                                in_enc_negative_one,
                                                in_pk, in_bit_length, in_sock_fd,
                                                in_negative_r_hat_s[i], in_enc_r_hat_s[i],
                                                in_negative_r_bar_s_delta[i], in_enc_r_bar_s_delta[i],
                                                in_negative_r_a_s_smp[i], in_enc_r_a_s_smp[i],
                                                in_negative_r_b_s_smp[i], in_enc_r_b_s_smp[i],
                                                in_enc_negative_r_a_times_r_b_s_smp[i]);

    }

#ifdef DEBUG_SMIN_K_PROTOCOL
    //test if step 1 is correct
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        socket_send_paillier_ciphertext_t(in_sock_fd, T_bits[i]);

    }
    socket_send_paillier_ciphertext_t(in_sock_fd, I);
#endif

    //Step 2
    //Step 2(a): Delta <- I^{-1}
    mpz_invert(Delta->c, I->c, in_pk->n_squared);

    for (i = 0; i < in_k; i = i + 1) {
        //Delta'[i] <- E(i) * Delta
        paillier_mul(in_pk, Delta_prime_s[i], in_enc_cluster_indices[i], Delta);

        //phi[i] <- Delta'[i]^{r_i}
        generate_random_plaintext(r_s[i], in_pk, paillier_get_rand_devurandom);

        paillier_exp(in_pk, phi_s[i], Delta_prime_s[i], r_s[i]);

    }

    //Step 2(c):
    //u <- pi(phi)
    long *pi = generate_random_permutation(in_state, in_k);
    long *pi_inverse = invert_permutation(pi, in_k);
    u_s = shuffle_paillier_ciphertexts(u_s, phi_s, in_k, pi);

    //send u to C_2
    for (i = 0; i < in_k; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, u_s[i]);
    }

    //Step 4(a): receive U from C_2
    for (i = 0; i < in_k; i = i + 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &(U_s[i]));
    }

    //Step 4(b):
    //Gamma <- pi^{-1}(U)
    out_Gamma_s = shuffle_paillier_ciphertexts(out_Gamma_s, U_s, in_k, pi_inverse);

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, T_bits);
    paillier_freeciphertext(I);

    paillier_freeciphertext(Delta);

    free_paillier_ciphertexts_1_d(in_k, Delta_prime_s);
    free_paillier_plaintexts_1_d(in_k, r_s);
    free_paillier_ciphertexts_1_d(in_k, phi_s);

    free_paillier_ciphertexts_1_d(in_k, u_s);

    free(pi);
    free(pi_inverse);

    free_paillier_ciphertexts_1_d(in_k, U_s);

}

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
                                  paillier_ciphertext_t **in_enc_cluster_indices) {

#ifdef TIME_C_1
    timeval before_step_2;
    timeval after_step_2;
    long long time_spent_in_step_2 = 0;

    timeval before_step_4;
    timeval after_step_4;
    long long time_spent_in_step_4 = 0;
#endif

    long i;

    //initialize (T_bits, I), T_bits is an array representing an encrypted bit-decomposed number
    paillier_ciphertext_t **T_bits = initialize_paillier_ciphertexts_1_d(in_bit_length);
    paillier_ciphertext_t *I = paillier_create_enc_zero();

    //initialzie Delta
    paillier_ciphertext_t *Delta = paillier_create_enc_zero();

    //initialize Delta_prime_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **Delta_prime_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize r_i for i from 0 to "in_k - 1"
    paillier_plaintext_t **r_s = initialize_paillier_plaintexts_1_d(in_k);

    //initialize phi_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **phi_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize u_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **u_s = initialize_paillier_ciphertexts_1_d(in_k);

    //initialize U_i for i from 0 to "in_k - 1"
    paillier_ciphertext_t **U_s = initialize_paillier_ciphertexts_1_d(in_k);

    //Step 1
    //Step 1(a): (T, I) <- SMIN((E(d_0), E(0)), (E(d_1), E(1)))
    execute_smin_pipelined_C_1(T_bits, I,
                               in_state,
                               in_enc_d_s_bits[0], in_enc_d_s_bits[1],
                               in_enc_cluster_indices[0], in_enc_cluster_indices[1],
                               in_enc_negative_one,
                               in_pk, in_bit_length, in_sock_fd,
                               in_negative_r_hat_s[0], in_enc_r_hat_s[0],
                               in_negative_r_bar_s_delta[0], in_enc_r_bar_s_delta[0],
                               in_negative_r_a_s_smp[0], in_enc_r_a_s_smp[0],
                               in_negative_r_b_s_smp[0], in_enc_r_b_s_smp[0],
                               in_enc_negative_r_a_times_r_b_s_smp[0]);

    //Step 1(b)
    //for i from 1 to "k - 2"
    //(T, I) <- SMIN((E(d_{i}), E(i)), (E(d_{i+1}), E(i+1)))
    for (i = 1; i < in_k - 1; i = i + 1) {

        execute_smin_pipelined_C_1(T_bits, I,
                                   in_state,
                                   T_bits, in_enc_d_s_bits[i + 1],
                                   I, in_enc_cluster_indices[i + 1],
                                   in_enc_negative_one,
                                   in_pk, in_bit_length, in_sock_fd,
                                   in_negative_r_hat_s[i], in_enc_r_hat_s[i],
                                   in_negative_r_bar_s_delta[i], in_enc_r_bar_s_delta[i],
                                   in_negative_r_a_s_smp[i], in_enc_r_a_s_smp[i],
                                   in_negative_r_b_s_smp[i], in_enc_r_b_s_smp[i],
                                   in_enc_negative_r_a_times_r_b_s_smp[i]);

    }

#ifdef DEBUG_SMIN_K_PROTOCOL
    //test if step 1 is correct
    for (i = in_bit_length - 1; i >= 0; i = i - 1) {

        socket_send_paillier_ciphertext_t(in_sock_fd, T_bits[i]);

    }
    socket_send_paillier_ciphertext_t(in_sock_fd, I);
#endif

    //Step 2
#ifdef TIME_C_1
    gettimeofday(&before_step_2, NULL);
#endif

    //Step 2(a): Delta <- I^{-1}
    mpz_invert(Delta->c, I->c, in_pk->n_squared);

    for (i = 0; i < in_k; i = i + 1) {
        //Delta'[i] <- E(i) * Delta
        paillier_mul(in_pk, Delta_prime_s[i], in_enc_cluster_indices[i], Delta);

        //phi[i] <- Delta'[i]^{r_i}
        generate_random_plaintext(r_s[i], in_pk, paillier_get_rand_devurandom);

        paillier_exp(in_pk, phi_s[i], Delta_prime_s[i], r_s[i]);

    }

    //Step 2(c):
    //u <- pi(phi)
    long *pi = generate_random_permutation(in_state, in_k);
    long *pi_inverse = invert_permutation(pi, in_k);
    u_s = shuffle_paillier_ciphertexts(u_s, phi_s, in_k, pi);

#ifdef TIME_C_1
    gettimeofday(&after_step_2, NULL);
    time_spent_in_step_2 =
        ((after_step_2.tv_sec * 1000000 + after_step_2.tv_usec) -
         (before_step_2.tv_sec * 1000000 + before_step_2.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_2;
#endif

    //send u to C_2
    for (i = 0; i < in_k; i = i + 1) {
        socket_send_paillier_ciphertext_t(in_sock_fd, u_s[i]);
    }

    //Step 4(a): receive U from C_2
    for (i = 0; i < in_k; i = i + 1) {
        socket_receive_paillier_ciphertext_t(in_sock_fd, &(U_s[i]));
    }

    //Step 4(b):
#ifdef TIME_C_1
    gettimeofday(&before_step_4, NULL);
#endif

    //Gamma <- pi^{-1}(U)
    out_Gamma_s = shuffle_paillier_ciphertexts(out_Gamma_s, U_s, in_k, pi_inverse);

#ifdef TIME_C_1
    gettimeofday(&after_step_4, NULL);
    time_spent_in_step_4 =
        ((after_step_4.tv_sec * 1000000 + after_step_4.tv_usec) -
         (before_step_4.tv_sec * 1000000 + before_step_4.tv_usec));
    time_spent_on_C_1_global = time_spent_on_C_1_global + time_spent_in_step_4;
#endif

    //clean-up
    free_paillier_ciphertexts_1_d(in_bit_length, T_bits);
    paillier_freeciphertext(I);

    paillier_freeciphertext(Delta);

    free_paillier_ciphertexts_1_d(in_k, Delta_prime_s);
    free_paillier_plaintexts_1_d(in_k, r_s);
    free_paillier_ciphertexts_1_d(in_k, phi_s);

    free_paillier_ciphertexts_1_d(in_k, u_s);

    free(pi);
    free(pi_inverse);

    free_paillier_ciphertexts_1_d(in_k, U_s);

}

void execute_sinv_C_1(paillier_ciphertext_t *out_enc_a_inv,
                      paillier_ciphertext_t *in_enc_a,
                      paillier_pubkey_t *in_pk, int in_sock_fd) {

    //initialize E(r):
    paillier_ciphertext_t *enc_r = paillier_create_enc_zero();

    //initialize B:
    paillier_ciphertext_t *B = paillier_create_enc_zero();

    //initialize F:
    paillier_ciphertext_t *F = paillier_create_enc_zero();

    //Step 1: generate a random nonzero r in Z_n and compute E(r)
    paillier_plaintext_t *r = 0;
    r = generate_random_nonzero_plaintext(r, in_pk, paillier_get_rand_devurandom);

    paillier_enc(enc_r, in_pk, r, paillier_get_rand_devurandom);

    //Step 2: B <- E(a)^r
    paillier_exp(in_pk, B, in_enc_a, r);

    //Step 3: send B to C_2
    socket_send_paillier_ciphertext_t(in_sock_fd, B);

    //Step 6: receive F from C_2
    socket_receive_paillier_ciphertext_t(in_sock_fd, &F);

    //Step 7: out_enc_a_inv <- SMP(E(r), F)
    execute_smp_C_1(out_enc_a_inv, enc_r, F, in_pk, in_sock_fd);

    //clean-up
    paillier_freeplaintext(r);
    paillier_freeciphertext(enc_r);

    paillier_freeciphertext(B);
    paillier_freeciphertext(F);
}

void execute_spci_C_1(paillier_ciphertext_t *out_b_prime, paillier_ciphertext_t **out_b_s,
                      paillier_ciphertext_t ***out_a_prime_s,
                      paillier_ciphertext_t **in_enc_cardinalities,
                      paillier_ciphertext_t ***in_enc_lambda_s,
                      int in_k, int in_num_dimensions,
                      paillier_pubkey_t *in_pk, int in_sock_fd) {



    //initialize E(|c_h|^{-1}) for h from 0 to "in_k - 1"
    paillier_ciphertext_t **enc_cluster_cardinality_inverse_s =
        initialize_paillier_ciphertexts_1_d(in_k);

    int i;
    int j;

    //Step 1: compute b', an encryption of the product of cluster cardinalities
    execute_smp_C_1(out_b_prime, in_enc_cardinalities[0], in_enc_cardinalities[1], in_pk, in_sock_fd);
    for (i = 1; i < in_k - 1; i = i + 1) {

        execute_smp_C_1(out_b_prime, out_b_prime, in_enc_cardinalities[i + 1], in_pk, in_sock_fd);

    }

    //Step 2: compute b_h for each cluster h
    for (i = 0; i < in_k; i = i + 1) {

        //compute E(|c_h|^{-1})
        execute_sinv_C_1(enc_cluster_cardinality_inverse_s[i], in_enc_cardinalities[i], in_pk, in_sock_fd);

        //compute SMP(b', E(|c_h|^{-1}))
        execute_smp_C_1(out_b_s[i], out_b_prime, enc_cluster_cardinality_inverse_s[i], in_pk, in_sock_fd);

    }

    //Step 3: compute a_prime_h_s[i][j], for i from 0 to "in_k - 1", j from 0 to "in_num_dimensions - 1"
    for (i = 0; i < in_k; i = i + 1) {
        for (j = 0; j < in_num_dimensions; j = j + 1) {
            execute_smp_C_1(out_a_prime_s[i][j], out_b_s[i], in_enc_lambda_s[i][j], in_pk, in_sock_fd);
        }
    }

    //clean-up
    free_paillier_ciphertexts_1_d(in_k, enc_cluster_cardinality_inverse_s);

}
