#include <iostream>

#include <stdio.h>//perror
#include <string.h>//memset
#include <unistd.h>//close

#include <sys/select.h>

#include <sys/socket.h>//socketlen_t
#include <netinet/in.h>//socketaddr_in
#include <stdlib.h>//exit,

#include <sys/types.h>//addrinfo
#include <netdb.h>//addrinfo
#include <arpa/inet.h>//inet_ntop

#include <gmp.h>
#include "paillier.h"
#include "socket_utility.h"

#include <sys/time.h>

//#define DEBUG_CHECK_CLIENTS
//#define DEBUG_SOCKET_RECEIVE_INT

#define BACKLOG 10
#define MAXLINE 1024

//requests related
#define REQUEST_FOR_TASK 0
#define TASK_IS_DONE 1

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

int byte_cnt = 0; /* counts total bytes received by server */

using namespace std;

struct pool { /* represents a pool of connected descriptors */
    int maxfd; /* largest descriptor in read_set */
    fd_set read_set; /* set of all active descriptors */
    fd_set ready_set; /* subset of descriptors ready for reading */
    int nready; /* number of ready descriptors from select */
    int maxi; /* highwater index into client array */
    int clientfd[FD_SETSIZE]; /* set of active descriptors */

    //the following fields are added by Fang-Yu according to our protocol

    int client_id[FD_SETSIZE];
    int previous_assigned_task[FD_SETSIZE];
    int num_connected_clients; //deal with this later...
    int index_of_pair_zero; //storing the fd with the C_1 with client id 0
};

int Open_listen_fd(char *port);
void init_pool(int listen_fd, struct pool *p);
int Accept(int listen_fd);
void add_client(int conn_fd, struct pool *p);

void check_clients(paillier_ciphertext_t **out_enc_dummy_received_setc_elements,
                   int in_num_dummy_setc_elements,
                   struct pool *p, int *in_task_is_done, int *in_spci_is_done);

int check_tasks_status(int in_num_pairs_of_servers, int *in_task_is_done);
void reset_tasks_status(int in_num_pairs_of_servers, int *in_task_is_done);

int check_termination_condition(int in_num_iterations, int in_required_num_iterations, struct pool *p);

int main(int argc, char *argv[]) {

    cout << "master_sbd starts" << endl;
    int i;

    //in the following, we declare and define some variables for testing the aggregation of setc information
    int num_dummy_setc_elements = 100;
    paillier_ciphertext_t **enc_dummy_setc_element_s =
        initialize_paillier_ciphertexts_1_d(num_dummy_setc_elements);
    //in the above, we declare and define some variables for testing the aggregation of setc information

    int listen_fd, conn_fd;
    pool p;
    int num_pairs_of_servers;
    int *task_is_done;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <port> <num_pairs_of_servers>\n", argv[0]);
        exit(0);
    }

    /* Initialization of struct pool p */
    listen_fd = Open_listen_fd(argv[1]);

    num_pairs_of_servers = atoi(argv[2]);
    task_is_done = (int *)malloc(sizeof(int) * num_pairs_of_servers);

    int required_num_iterations = 2;

    for (i = 0; i < num_pairs_of_servers; i = i + 1) {
        task_is_done[i] = 0; //0 stands for not done yet
    }

    //added by Fang-Yu on 2015/02/10
    int spci_is_done;
    spci_is_done = 0;

    init_pool(listen_fd, &p);


    int num_iterations;
    num_iterations = 0;

    int all_tasks_in_current_iteration_are_done;
    all_tasks_in_current_iteration_are_done = 0;
    all_tasks_in_current_iteration_are_done =
        check_tasks_status(num_pairs_of_servers, task_is_done);

    int termination_condition_satisfied;
    termination_condition_satisfied = 0;

    if (all_tasks_in_current_iteration_are_done == 0) {
        printf("some task(s) in current iteration is (are) not done yet\n");
    } else {
        printf("all tasks in current iteration are done\n");
    }

    //the following is for having a better estimation of time efficiency
    p.ready_set = p.read_set;
    p.nready = select(p.maxfd + 1, &p.ready_set, NULL, NULL, NULL);
    //the above is for having a better estimation of time efficiency

    timeval before_loop;
    timeval after_loop;
    timeval time_previous_iteration_done;
    timeval time_current_iteration_done;
    gettimeofday(&before_loop, NULL);
    gettimeofday(&time_previous_iteration_done, NULL);
    while (1) {
        /* Wait for listening/connected descriptor(s) to become ready */
        p.ready_set = p.read_set;
        p.nready = select(p.maxfd + 1, &p.ready_set, NULL, NULL, NULL);

        /* If listening descriptor ready, add new client to pool */
        if (FD_ISSET(listen_fd, &p.ready_set)) {
            conn_fd = Accept(listen_fd);
            add_client(conn_fd, &p);
        }

        /* Check if any other clients need an instruction */
        check_clients(enc_dummy_setc_element_s, num_dummy_setc_elements,
                      &p, task_is_done, &spci_is_done);

        //2 possible cases
        if ((termination_condition_satisfied == 1) && (p.num_connected_clients == 0)) {
            printf("(termination condition is satisfied) and (all clients are disconnected)\n");
            break;
        }

        if ((termination_condition_satisfied == 1) && (p.num_connected_clients > 0)) {
            //continue until all clients are logged out
            continue;
        }

        //if we reach here, then it means termination_condition_satisfied == 0
        all_tasks_in_current_iteration_are_done =
            check_tasks_status(num_pairs_of_servers, task_is_done);

        if (all_tasks_in_current_iteration_are_done == 1) {

            printf("all_tasks_in_current_iteration_are_done is true\n");

            //check if we can really leave the while-loop by an invocation to SETC
            termination_condition_satisfied = check_termination_condition(num_iterations, required_num_iterations, &p);

            //if we can really leave the while-loop, then inform every client to disconnect
            if (termination_condition_satisfied == 1) {

                printf("termination_condition_satisfied is 1\n");

                //note that if we reach here, then all clients are waiting for further instruction
                for (i = 0; i < num_pairs_of_servers; i = i + 1) {

                    printf("to tell client with fd %d to disconnect\n", p.clientfd[i]);

                    socket_send_command_master_to_C_1(p.clientfd[i], PERMISSION_TO_DISCONNECT);
                }

                gettimeofday(&time_current_iteration_done, NULL);

                long time_spent_in_most_recent_iteration =
                    ((time_current_iteration_done.tv_sec * 1000000 + time_current_iteration_done.tv_usec) -
                     (time_previous_iteration_done.tv_sec * 1000000 + time_previous_iteration_done.tv_usec)) / 1000;
                printf("time_spent_in_most_recent_iteration: %ld (ms)\n", time_spent_in_most_recent_iteration);

                continue;

            } else {

                //when termination_condition_satsified == 0
                //should initialize the next iteration
                num_iterations = num_iterations + 1;

                for (i = 0; i < num_pairs_of_servers; i = i + 1) {

                    socket_send_command_master_to_C_1(p.clientfd[i], SBD);
                    p.previous_assigned_task[i] = DOING_SBD;

                }

                //need to reset this variable for the next iteration
                all_tasks_in_current_iteration_are_done = 0;

                //also need to reset task_is_done array
                reset_tasks_status(num_pairs_of_servers, task_is_done);

                //also need to reset spci_is_done
                spci_is_done = 0;

                //compute how much time is spent in the most recent iteration
                
                gettimeofday(&time_current_iteration_done, NULL);

                long time_spent_in_most_recent_iteration =
                    ((time_current_iteration_done.tv_sec * 1000000 + time_current_iteration_done.tv_usec) -
                     (time_previous_iteration_done.tv_sec * 1000000 + time_previous_iteration_done.tv_usec)) / 1000;
                printf("time_spent_in_most_recent_iteration: %ld (ms)\n", time_spent_in_most_recent_iteration);

                time_previous_iteration_done.tv_sec = time_current_iteration_done.tv_sec;
                time_previous_iteration_done.tv_usec = time_current_iteration_done.tv_usec;

                continue;

            }

        } else {
            //when all_tasks_in_current_iteration_are_done == 0
            //wait until all_tasks_in_current_iteration_are_done becomes true
            continue;
        }

    }

    gettimeofday(&after_loop, NULL);
    long time_spent_in_loop =
        ((after_loop.tv_sec * 1000000 + after_loop.tv_usec) -
         (before_loop.tv_sec * 1000000 + before_loop.tv_usec)) / 1000;
    printf("time_spent_in_loop: %ld (ms)\n", time_spent_in_loop);

    printf("master node, after while-loop\n");

    return (0);
}

int Open_listen_fd(char *service) {
    printf("in Open_listenfd.\n");

    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    int rv;
    int port;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    port = atoi(service); //for debugging purpose
    printf("listening on port: %d\n", port); //for debuggin purpose

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

        //        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &yes,
        //                sizeof (int)) == -1) {
        //            perror("setsockopt");
        //            exit(1);
        //        }

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

    return sockfd; //the listening socket
}

void init_pool(int listen_fd, struct pool *p) {
    printf("in init_pool.\n");
    printf("listen_fd: %d\n", listen_fd); //for debugging purpose

    /* Initially, there are no connected descriptors */
    int i;
    p->maxi = -1;
    for (i = 0; i < FD_SETSIZE; i++) {
        p->clientfd[i] = -1;
        p->client_id[i] = -1;
        p->previous_assigned_task[i] = -1;
    }

    /* Initially, listenfd is only member of select read set */
    p->maxfd = listen_fd;
    FD_ZERO(&p->read_set);
    FD_SET(listen_fd, &p->read_set);

    /* Initially, there is no connected client */
    p->num_connected_clients = 0;

    /* Initialize index_of_pair_zero to -1 */
    p->index_of_pair_zero = -1;
}

int Accept(int listen_fd) {
    printf("in Accept.\n");

    int new_fd;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];

    sin_size = sizeof(their_addr);
    new_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
        perror("accept");
    }

    inet_ntop(their_addr.ss_family,
              get_in_addr((struct sockaddr *)&their_addr),
              s, sizeof s);
    printf("server: got connection from %s\n", s);

    return new_fd;
}

void add_client(int conn_fd, struct pool *p) {
    printf("in add_client.\n");

    //try to receive the client id
    int client_id;
    socket_receive_int(conn_fd, (unsigned int *)&client_id);
    if ((client_id < 0) || (client_id >= FD_SETSIZE)) {
        perror("add_client: (client_id < 0) or (client_id >= FD_SETSIZE)\n");
    }
    printf("client_id: %d\n", client_id);

    //do the bookkeeping of struct pool
    int i;
    p->nready--;
    for (i = 0; i < FD_SETSIZE; i++) /* Find an available slot */
        if (p->clientfd[i] < 0) {
            /* Add connected descriptor to the pool */
            p->clientfd[i] = conn_fd;
            p->client_id[i] = client_id;
            p->num_connected_clients = p->num_connected_clients + 1;

            /* Add the descriptor to descriptor set */
            FD_SET(conn_fd, &p->read_set);

            /* Update max descriptor and pool highwater mark */
            if (conn_fd > p->maxfd) p->maxfd = conn_fd;
            if (i > p->maxi) p->maxi = i;
            break;
        }
    if (i == FD_SETSIZE) /* Couldn't find an empty slot */
        perror("add_client error: Too many clients");
}

void check_clients(paillier_ciphertext_t **out_enc_dummy_received_setc_element_s,
                   int in_num_dummy_setc_elements,
                   struct pool *p, int *in_task_is_done, int *in_spci_is_done) {

#ifdef DEBUG_CHECK_CLIENTS
    printf("in check_client.\n");
#endif

    int i, j, conn_fd, n;
    int s;

    unsigned int request_to_receive;

    //in the following, we declare and define variables needed for receiving cluster information from pair 0
    int num_dummy_cluster_elements = 100;

    paillier_ciphertext_t **enc_dummy_received_cluster_element_s =
        initialize_paillier_ciphertexts_1_d(num_dummy_cluster_elements);
    //in the above, we declare and define variables needed for receiving cluster information from pair 0


#ifdef DEBUG_CHECK_CLIENTS
    printf("p->nready: %d\n", p->nready);
#endif

    for (i = 0; (i <= p->maxi) && (p->nready > 0); i++) {
        conn_fd = p->clientfd[i];

        /* If the descriptor is ready, echo a text line from it */
        if ((conn_fd > 0) && (FD_ISSET(conn_fd, &p->ready_set))) {
            p->nready--;

            n = socket_receive_request_C_1_to_master(conn_fd, &request_to_receive);
            if (n > 0) {

#ifdef DEBUG_CHECK_CLIENTS
                printf("from client with id %d, request_to_receive: %d\n", p->client_id[i], request_to_receive);
#endif

                //the code below deals with the communication logic with the clients
                if (request_to_receive == REQUEST_FOR_TASK) {

#ifdef DEBUG_CHECK_CLIENTS
                    printf("client with id %d requests for a task\n", p->client_id[i]);
#endif

                    socket_send_command_master_to_C_1(conn_fd, SBD);
                    p->previous_assigned_task[i] = DOING_SBD;
                    continue;

                }

                if (request_to_receive == TASK_IS_DONE) {

#ifdef DEBUG_CHECK_CLIENTS
                    printf("client %d is done with the task\n", p->client_id[i]);
#endif

                    if (p->previous_assigned_task[i] == DOING_SBD) {

                        printf("set task_is_done[%d] to 1\n", p->client_id[i]);
                        in_task_is_done[p->client_id[i]] = 1;

                        socket_send_command_master_to_C_1(conn_fd, WAIT_FOR_FURTHER_INSTRUCTION);
                        p->previous_assigned_task[i] = WAITING;
                        continue;
                    }

                }


            }
            //the case when n <= 0
            else {
                if (n == 0) {

                    //connection closed
#ifdef DEBUG_CHECK_CLIENTS
                    printf("current i: %d\n", i);
                    printf("select_server: socket %d hung up\n", conn_fd);
#endif

                } else {
                    //the case when n < 0
                    perror("recv");
                }
                /* EOF detected, remove descriptor from pool */
                close(conn_fd);
                FD_CLR(conn_fd, &p->read_set);
                p->clientfd[i] = -1;
                p->client_id[i] = -1;
                p->num_connected_clients = p->num_connected_clients - 1;
                p->previous_assigned_task[i] = -1;
            }
        }
    }

    //clean-up
    free_paillier_ciphertexts_1_d(num_dummy_cluster_elements, enc_dummy_received_cluster_element_s);

}


/* 
 This function returns 1 if all tasks assigned are done and 0 otherwise 
*/
int check_tasks_status(int in_num_pairs_of_servers, int *in_task_is_done) {
    int i;
    for (i = 0; i < in_num_pairs_of_servers; i = i + 1) {
        if (in_task_is_done[i] == 0) {
            return 0;
        }
    }
    return 1;
}

void reset_tasks_status(int in_num_pairs_of_servers, int *in_task_is_done) {
    int i;
    for (i = 0; i < in_num_pairs_of_servers; i = i + 1) {
        in_task_is_done[i] = 0;
    }
}

/* 
 This function returns 1 if the termination condition is satisfied and 0 otherwise
*/
int check_termination_condition(int in_num_iterations, int in_required_num_iterations, struct pool *p) {

    int n;
    unsigned int request_to_receive;
    int fd_pair_zero = p->clientfd[p->index_of_pair_zero];

    printf("fd_pair_zero: %d\n", fd_pair_zero);

    if (in_num_iterations >= in_required_num_iterations - 1) {
        return 1;
    } else {
        return 0;
    }
}

