#include <gmp.h>
#include "paillier.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include "socket_utility.h"


#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define PORT "3490"
#define BACKLOG 10     // how many pending connections queue will hold
#define BUFFER_SIZE 3072
#define MAXDATASIZE 100 // max number of bytes we can get at once

int create_socket_and_listen(char *service) {
    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    //struct sigaction sa;
    int yes = 255;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, service, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        //        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
        //                sizeof (int)) == -1) {
        //            perror("setsockopt");
        //            exit(1);
        //        }

        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &yes,
                sizeof (int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    //while (1) { // main accept() loop
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
        perror("accept");
        //continue;
    }

    inet_ntop(their_addr.ss_family,
              get_in_addr((struct sockaddr *)&their_addr),
              s, sizeof s);
    printf("server: got connection from %s\n", s);

    close(sockfd);

    return new_fd;
}

int create_socket_and_connect(char inHostname[], char *port) {

    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int yes = 255;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(inHostname, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &yes,
                sizeof (int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    return sockfd;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

int socket_send_mpz_t(int sockid, mpz_t nb) {
    //call mpz_export to see how many bytes need to be transferred to the other side
    size_t bytesToSend = 0;
    char a[2048];
    mpz_export(a, &bytesToSend, 1, sizeof (a[0]), 0, 0, nb);
    //printf("bytesToSend: %d\n", bytesToSend);

    socket_send_int(sockid, bytesToSend);

    //send bytesToSend
    int bytesSentSoFar = 0;
    int currentBytesSent;
    while (bytesSentSoFar < bytesToSend) {
        currentBytesSent = send(sockid, a + bytesSentSoFar,
                bytesToSend - bytesSentSoFar, 0);
        bytesSentSoFar = bytesSentSoFar + currentBytesSent;
    }

    return bytesSentSoFar;
}

int socket_receive_mpz_t(int sockid, mpz_t *nb) {
    char buffer[2048];
    memset(buffer, 0, 2048);

    //make sure how many bytes to receive first
    uint32_t bytesToReceive;
    socket_receive_int(sockid, &bytesToReceive);
    //printf("bytesToReceive in socket_receive_mpz_t: %d\n", bytesToReceive);

    //receive this many bytes
    int bytesReceivedSoFar = 0;
    int currentBytesReceived;
    while (bytesReceivedSoFar < bytesToReceive) {
        currentBytesReceived = recv(sockid, buffer + bytesReceivedSoFar,
                bytesToReceive - bytesReceivedSoFar, 0);
        bytesReceivedSoFar = bytesReceivedSoFar + currentBytesReceived;
        //printf("in socket_receive_mpz_t, currentBytesReceived: %d\n", currentBytesReceived);
        if (currentBytesReceived == 0) {
            printf("in socket_receive_mpz_t, currentBytesReceived: %d\n", currentBytesReceived);
            return bytesReceivedSoFar;
        }
    }

    mpz_import(*nb, bytesToReceive, 1, sizeof (buffer[0]), 0, 0, buffer);
    //gmp_printf("imported *nb: %Zd\n", *nb);

    return bytesReceivedSoFar;
}

int socket_send_int(int sockid, uint32_t value_to_send) {
    uint32_t network_byte_order;
    memset(&network_byte_order, 0, sizeof(uint32_t));
    network_byte_order = htonl(value_to_send);

    int num_bytes_to_send = sizeof(uint32_t);
    //printf("num_bytes_to_send: %d\n", num_bytes_to_send);
    int num_bytes_sent_so_far = 0;
    int current_num_bytes_sent;
    while (num_bytes_sent_so_far < num_bytes_to_send) {
        current_num_bytes_sent =
            send(sockid, (&network_byte_order) + num_bytes_sent_so_far,
                 num_bytes_to_send - num_bytes_sent_so_far, 0);
        num_bytes_sent_so_far = num_bytes_sent_so_far + current_num_bytes_sent;
    }

    return num_bytes_sent_so_far;
}

int socket_receive_int(int sockid, uint32_t *value_to_receive) {
    memset(value_to_receive, 0, sizeof(uint32_t));
    int num_bytes_to_receive = sizeof(uint32_t);
    //printf("in socket_receive_int, num_bytes_to_receive: %d\n", num_bytes_to_receive);

    uint32_t network_byte_order;
    memset(&network_byte_order, 0, sizeof(uint32_t));

    int num_bytes_received_so_far = 0;
    int current_num_bytes_received;
    while (num_bytes_received_so_far < num_bytes_to_receive) {
        current_num_bytes_received =
            recv(sockid, (&network_byte_order) + num_bytes_received_so_far,
                 num_bytes_to_receive - num_bytes_received_so_far, 0);

        if (current_num_bytes_received == 0) {
#ifdef DUBUG_SOCKET_RECEIVE_INT
            printf("current_num_bytes_received: %d\n", current_num_bytes_received);
#endif
            return num_bytes_received_so_far;
        } else if (current_num_bytes_received < 0) {
            perror("in socket_receive_int: ");
            //return num_bytes_received_so_far;
            exit(EXIT_FAILURE);
        }

        num_bytes_received_so_far = num_bytes_received_so_far +
            current_num_bytes_received;
    }

    *value_to_receive = ntohl(network_byte_order);
    //    int numberInBuff = atoi(buff);
    //    printf("numberInBuff: %d\n", numberInBuff);
    //    *valueToReceive = atoi(buff);

    return num_bytes_received_so_far;
}

int socket_send_bytes(int sockid, char *bytes, int totalBytesToSend) {
    char buffer[2048];
    memset(buffer, 0, 2048);

    //do some memcpy
    memcpy(buffer, bytes, totalBytesToSend);

    int bytesToSendEachTime = 4;

    int bytesSentSoFar = 0;
    int currentBytesSent;
    while (bytesSentSoFar < totalBytesToSend) {
        currentBytesSent = send(sockid, buffer + bytesSentSoFar,
                bytesToSendEachTime, 0);
        bytesSentSoFar = bytesSentSoFar + currentBytesSent;
        printf("currentBytesSent: %d\n", currentBytesSent);
        if (currentBytesSent < 0) {
            perror("in socket_send_bytes: ");
            return bytesSentSoFar;
        }
    }

    return bytesSentSoFar;
}

int socket_receive_bytes(int sockid, char *bytesReceived,
        int totalBytesToReceive) {
    int bytesToReceiveEachTime = 4;
    char buffer[2048];
    memset(buffer, 0, 2048);

    int bytesReceivedSoFar = 0;
    int currentBytesReceived;
    while (bytesReceivedSoFar < totalBytesToReceive) {
        currentBytesReceived = recv(sockid, buffer + bytesReceivedSoFar,
                bytesToReceiveEachTime, 0);
        bytesReceivedSoFar = bytesReceivedSoFar + currentBytesReceived;
        printf("in socket_receive_bytes, currentBytesReceived: %d\n",
                currentBytesReceived);
        if (currentBytesReceived == 0) {
            return bytesReceivedSoFar;
        }
    }

    memcpy(bytesReceived, buffer, totalBytesToReceive);

    return bytesReceivedSoFar;
}

int socket_send_paillier_pubkey_t(int sockid, paillier_pubkey_t *pk) {
    int n1, n2, n3, n4;

    printf("bits: %d\n", pk->bits);
    gmp_printf("n: %Zd\n", pk->n);
    gmp_printf("n_squared: %Zd\n", pk->n_squared);
    gmp_printf("n_plusone: %Zd\n", pk->n_plusone);

    n1 = socket_send_int(sockid, pk->bits);
    //printf("n1: %d\n", n1);
    n2 = socket_send_mpz_t(sockid, pk->n);
    //printf("n2: %d\n", n2);
    n3 = socket_send_mpz_t(sockid, pk->n_squared);
    n4 = socket_send_mpz_t(sockid, pk->n_plusone);

    return 0;
}

int socket_receive_paillier_pubkey_t(int sockid,
        paillier_pubkey_t **pub) {
    int n1, n2, n3, n4;

    unsigned int bits;
    n1 = socket_receive_int(sockid, &bits);
    //printf("n1: %d\n", n1);
    mpz_t n;
    mpz_init(n);
    n2 = socket_receive_mpz_t(sockid, &n);
    //printf("n2: %d\n", n2);

    mpz_t n_squared;
    mpz_init(n_squared);
    n3 = socket_receive_mpz_t(sockid, &n_squared);

    mpz_t n_plusone;
    mpz_init(n_plusone);
    n4 = socket_receive_mpz_t(sockid, &n_plusone);

    //initialize pub
    if (!(*pub)) {
        //printf("init pub in socket_receive_paillier_pubkey_t\n");
        *pub = (paillier_pubkey_t*) malloc(sizeof (paillier_pubkey_t));
    }

    mpz_init((*pub)->n);
    mpz_init((*pub)->n_squared);
    mpz_init((*pub)->n_plusone);

    (*pub)->bits = bits;
    mpz_set((*pub)->n, n);
    mpz_set((*pub)->n_squared, n_squared);
    mpz_set((*pub)->n_plusone, n_plusone);
    
    //clean-up
    mpz_clear(n);
    mpz_clear(n_squared);
    mpz_clear(n_plusone);

    return 0;
}

int socket_send_paillier_ciphertext_t(int sockid, paillier_ciphertext_t *ct) {

    int bytesSentSoFar = socket_send_mpz_t(sockid, ct->c);

    return bytesSentSoFar;
}

int socket_send_paillier_ciphertexts(int sockid, paillier_ciphertext_t **in_ct_s, int in_num_ciphertexts) {

    unsigned char *out_buff = (unsigned char *) malloc(in_num_ciphertexts * 256);//256 is hardcoded for now
    size_t num_bytes;
    long i;

    memset(out_buff, 0, in_num_ciphertexts * 256);
    
    for (i = 0; i < in_num_ciphertexts; i = i + 1) {
        mpz_export(out_buff + i * 256, &num_bytes, -1, sizeof (out_buff[0]), 0, 0, in_ct_s[i]->c);
        //printf("num_bytes: %zd\n", num_bytes);
    }

    long num_bytes_to_send = in_num_ciphertexts * 256;
    long num_bytes_sent_so_far = 0;
    int current_num_bytes_sent = 0;
    int num_bytes_to_send_each_time = 4;
    while (num_bytes_sent_so_far < num_bytes_to_send) {
        current_num_bytes_sent = send(sockid, out_buff + num_bytes_sent_so_far,
                num_bytes_to_send_each_time, 0);
        num_bytes_sent_so_far = num_bytes_sent_so_far + current_num_bytes_sent;
        //printf("current_num_bytes_sent: %d\n", current_num_bytes_sent);
        if (current_num_bytes_sent < 0) {
            perror("in socket_send_paillier_ciphertexts\n");
        }
    }

    free(out_buff);
}

int socket_receive_paillier_ciphertext_t(int sockid, paillier_ciphertext_t **ct) {

    mpz_t rawCT;
    mpz_init(rawCT);
    int bytesReceivedSoFar = socket_receive_mpz_t(sockid, &rawCT);
    
    if (!(*ct)) {
        //printf("init paillier_ciphertext_t in socket_receive_paillier_ciphertext_t\n");
        *ct = (paillier_ciphertext_t *) malloc(sizeof(paillier_ciphertext_t));
    }
    
    mpz_init((*ct)->c);
    mpz_set((*ct)->c, rawCT);

    mpz_clear(rawCT);
    
    return bytesReceivedSoFar;
}

int socket_receive_paillier_ciphertexts(paillier_ciphertext_t ***out_ct_s, int in_num_ciphertexts, int sockid) {

    if (!(*out_ct_s)) {
        *out_ct_s = initialize_paillier_ciphertexts_1_d(in_num_ciphertexts);
    }

    unsigned char *in_buff = (unsigned char *) malloc(in_num_ciphertexts * 256);
    memset(in_buff, 0, in_num_ciphertexts * 256);

    long num_bytes_to_receive = in_num_ciphertexts * 256;
    long num_bytes_received_so_far = 0;
    int current_num_bytes_received = 0;
    int num_bytes_to_receive_each_time = 4;
    while (num_bytes_received_so_far < num_bytes_to_receive) {
        current_num_bytes_received = recv(sockid, in_buff + num_bytes_received_so_far,
                num_bytes_to_receive_each_time, 0);
        //printf("current_num_bytes_received: %d\n", current_num_bytes_received);
        num_bytes_received_so_far = num_bytes_received_so_far + current_num_bytes_received;
    }

    int i;
    for (i = 0; i < in_num_ciphertexts; i = i + 1) {

        mpz_import((*out_ct_s)[i]->c, 256, -1, sizeof(in_buff[0]), 0, 0, in_buff + i * 256);
        //gmp_printf("ct_s[%ld]: %Zd\n", i, ct_s[i]->c);

    }

    free(in_buff);

}

//the following are coming from C1.cpp
int socket_receive_command_master_to_C_1(int sockid, uint32_t *value_to_receive) {
    int num_bytes_received;
    num_bytes_received = socket_receive_int(sockid, value_to_receive);
    return num_bytes_received;
}

int socket_send_request_C_1_to_master(int sockid, uint32_t value_to_send) {
    int num_bytes_sent;
    num_bytes_sent = socket_send_int(sockid, value_to_send);
    return num_bytes_sent;
}

int socket_send_command_C_1_to_C_2(int sockid, uint32_t value_to_send) {
    int num_bytes_sent;
    num_bytes_sent = socket_send_int(sockid, value_to_send);
    return num_bytes_sent;
}

int socket_receive_request_C_2_to_C_1(int sockid, uint32_t *value_to_receive) {
    int num_bytes_received;
    num_bytes_received = socket_receive_int(sockid, value_to_receive);
    return num_bytes_received;
}

//the following are coming from C2.cpp
int socket_receive_command_C_1_to_C_2(int sockid, uint32_t *value_to_receive) {
    int num_bytes_received;
    num_bytes_received = socket_receive_int(sockid, value_to_receive);
    return num_bytes_received;
}

int socket_send_request_C_2_to_C_1(int sockid, uint32_t value_to_send) {
    int num_bytes_sent;
    num_bytes_sent = socket_send_int(sockid, value_to_send);
    return num_bytes_sent;
}

//the following are coming from master.cpp
int socket_send_command_master_to_C_1(int sockid, uint32_t value_to_send) {
    int num_bytes_sent;
    num_bytes_sent = socket_send_int(sockid, value_to_send);
    return num_bytes_sent;
}

int socket_receive_request_C_1_to_master(int sockid, uint32_t *value_to_receive) {
    int num_bytes_received;
    num_bytes_received = socket_receive_int(sockid, value_to_receive);
    return num_bytes_received;
}
