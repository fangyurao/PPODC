#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libssh/libssh.h>

int verify_knownhost(ssh_session session);
int exec_remote_processes(ssh_session session, char *in_command);

int main(int argc, char *argv[]) {
    printf("start_smin_k_pipelined starts\n");

    if (argc != 7) {
        fprintf(stderr, "usage: %s <num_pairs_of_servers> <master_port> <C_1_base_port> <num_smin_k> <k> <bit_length>\n", argv[0]);
        exit(0);
    }

    int max_num_ssh_servers_for_C_1_s;
    int max_num_ssh_servers_for_C_2_s;
    max_num_ssh_servers_for_C_1_s = 8;
    max_num_ssh_servers_for_C_2_s = max_num_ssh_servers_for_C_1_s;
    printf("max_num_ssh_servers_for_C_1_s: %d\n", max_num_ssh_servers_for_C_1_s);
    printf("max_num_ssh_servers_for_C_2_s: %d\n", max_num_ssh_servers_for_C_2_s);

    int num_ssh_servers_for_C_1_s;
    int num_ssh_servers_for_C_2_s;
    num_ssh_servers_for_C_1_s = atoi(argv[1]);//change here
    num_ssh_servers_for_C_2_s = num_ssh_servers_for_C_1_s;
    printf("num_ssh_servers_for_C_1_s: %d\n", num_ssh_servers_for_C_1_s);
    printf("num_ssh_servers_for_C_2_s: %d\n", num_ssh_servers_for_C_2_s);

    ssh_session my_ssh_session_master;

    int i;
    ssh_session *my_ssh_session_C_1_s;
    ssh_session *my_ssh_session_C_2_s;
    int rc;
    char *password;

    // Open sessions and set options
    my_ssh_session_master = ssh_new();
    if (my_ssh_session_master == NULL) exit(-1);
    ssh_set_blocking(my_ssh_session_master, 1);

    my_ssh_session_C_1_s = (ssh_session *)malloc(sizeof(ssh_session) * max_num_ssh_servers_for_C_1_s);
    for (i = 0; i < max_num_ssh_servers_for_C_1_s; i = i + 1) {

        my_ssh_session_C_1_s[i] = ssh_new();
        if (my_ssh_session_C_1_s[i] == NULL) exit(-1);
        ssh_set_blocking(my_ssh_session_C_1_s[i], 1);

    }

    my_ssh_session_C_2_s = (ssh_session *)malloc(sizeof(ssh_session) * max_num_ssh_servers_for_C_2_s);
    for (i = 0; i < max_num_ssh_servers_for_C_2_s; i = i + 1) {

        my_ssh_session_C_2_s[i] = ssh_new();
        if (my_ssh_session_C_2_s[i] == NULL) exit(-1);
        ssh_set_blocking(my_ssh_session_C_2_s[i], 1);

    }

    //Note by Fang-Yu: need a function to set up the host names, hardcoded for now
    ssh_options_set(my_ssh_session_master, SSH_OPTIONS_HOST, "raof@mc18.cs.purdue.edu");

    ssh_options_set(my_ssh_session_C_1_s[0], SSH_OPTIONS_HOST, "raof@mc01.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[1], SSH_OPTIONS_HOST, "raof@mc03.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[2], SSH_OPTIONS_HOST, "raof@mc05.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[3], SSH_OPTIONS_HOST, "raof@mc07.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[4], SSH_OPTIONS_HOST, "raof@mc09.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[5], SSH_OPTIONS_HOST, "raof@mc11.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[6], SSH_OPTIONS_HOST, "raof@mc13.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_1_s[7], SSH_OPTIONS_HOST, "raof@mc15.cs.purdue.edu");

    ssh_options_set(my_ssh_session_C_2_s[0], SSH_OPTIONS_HOST, "raof@mc02.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[1], SSH_OPTIONS_HOST, "raof@mc04.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[2], SSH_OPTIONS_HOST, "raof@mc06.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[3], SSH_OPTIONS_HOST, "raof@mc08.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[4], SSH_OPTIONS_HOST, "raof@mc10.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[5], SSH_OPTIONS_HOST, "raof@mc12.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[6], SSH_OPTIONS_HOST, "raof@mc14.cs.purdue.edu");
    ssh_options_set(my_ssh_session_C_2_s[7], SSH_OPTIONS_HOST, "raof@mc16.cs.purdue.edu");

    //get the password from the end user
    password = getpass("Password: ");

    //connect to ssh servers using the password above, change here
    int master_port = atoi(argv[2]);
    int C_1_base_port = atoi(argv[3]);
    int num_smin_k = atoi(argv[4]);
    int k = atoi(argv[5]);
    int bit_length = atoi(argv[6]);

    char command_for_master[512];
    sprintf(command_for_master, 
            "./scratch/P32_Master/master_smin_k %d %d > scratch/P32_Master/out_master_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P32_Master/err_master_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, num_ssh_servers_for_C_1_s, num_smin_k, k, bit_length, num_smin_k, k, bit_length);

    char command_for_C_1_s[8][512];
    sprintf(command_for_C_1_s[0], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 0 %d %d %d %d > scratch/P33_C_1/out_C_1_0_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_0_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 0, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[1], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 1 %d %d %d %d > scratch/P33_C_1/out_C_1_1_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_1_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 1, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[2], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 2 %d %d %d %d > scratch/P33_C_1/out_C_1_2_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_2_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 2, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[3], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 3 %d %d %d %d > scratch/P33_C_1/out_C_1_3_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_3_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 3, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[4], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 4 %d %d %d %d > scratch/P33_C_1/out_C_1_4_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_4_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 4, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[5], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 5 %d %d %d %d > scratch/P33_C_1/out_C_1_5_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_5_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 5, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[6], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 6 %d %d %d %d > scratch/P33_C_1/out_C_1_6_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_6_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 6, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_1_s[7], 
            "./scratch/P33_C_1/C_1_smin_k_pipelined mc18.cs.purdue.edu %d 7 %d %d %d %d > scratch/P33_C_1/out_C_1_7_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P33_C_1/err_C_1_7_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            master_port, C_1_base_port + 7, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);   


    char command_for_C_2_s[8][512];
    sprintf(command_for_C_2_s[0], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc01.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_0_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_0_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 0, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[1], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc03.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_1_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_1_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 1, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[2], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc05.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_2_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_2_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 2, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[3], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc07.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_3_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_3_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 3, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[4], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc09.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_4_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_4_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 4, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[5], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc11.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_5_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_5_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 5, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[6], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc13.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_6_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_6_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 6, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);
    sprintf(command_for_C_2_s[7], 
            "./scratch/P34_C_2/C_2_smin_k_pipelined mc15.cs.purdue.edu %d scratch/P34_C_2/factorization.txt %d %d %d > scratch/P34_C_2/out_C_2_7_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt 2> scratch/P34_C_2/err_C_2_7_num_smin_k_%d_k_%d_bit_length_%d_pipelined.txt &", 
            C_1_base_port + 7, num_smin_k, k, bit_length, num_smin_k, k, bit_length, num_smin_k, k, bit_length);

    //connect to master node, and then exec
    rc = ssh_connect(my_ssh_session_master);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n",
                ssh_get_error(my_ssh_session_master));
        ssh_free(my_ssh_session_master);
        exit(-1);
    }

    if (verify_knownhost(my_ssh_session_master) < 0) {
        ssh_disconnect(my_ssh_session_master);
        ssh_free(my_ssh_session_master);
        exit(-1);
    }

    rc = ssh_userauth_password(my_ssh_session_master, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session_master));
        ssh_disconnect(my_ssh_session_master);
        ssh_free(my_ssh_session_master);
        exit(-1);
    }

    exec_remote_processes(my_ssh_session_master, command_for_master);

    //sleep for 2 seconds
    usleep(2000000L);

    //connect to C_1_s, and then exec
    for (i = 0; i < num_ssh_servers_for_C_1_s; i = i + 1) {

        rc = ssh_connect(my_ssh_session_C_1_s[i]);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error connecting to localhost: %s\n",
                    ssh_get_error(my_ssh_session_C_1_s[i]));
            ssh_free(my_ssh_session_C_1_s[i]);
            exit(-1);
        }

        if (verify_knownhost(my_ssh_session_C_1_s[i]) < 0) {
            ssh_disconnect(my_ssh_session_C_1_s[i]);
            ssh_free(my_ssh_session_C_1_s[i]);
            exit(-1);
        }

        rc = ssh_userauth_password(my_ssh_session_C_1_s[i], NULL, password);
        if (rc != SSH_AUTH_SUCCESS) {
            fprintf(stderr, "Error authenticating with password: %s\n",
                    ssh_get_error(my_ssh_session_C_1_s[i]));
            ssh_disconnect(my_ssh_session_C_1_s[i]);
            ssh_free(my_ssh_session_C_1_s[i]);
            exit(-1);
        }

        exec_remote_processes(my_ssh_session_C_1_s[i], command_for_C_1_s[i]);
    }

    //sleep for 2 seconds
    usleep(2000000L);

    //connect to C_2_s, and then exec
    for (i = 0; i < num_ssh_servers_for_C_2_s; i = i + 1) {

        rc = ssh_connect(my_ssh_session_C_2_s[i]);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error connecting to localhost: %s\n",
                    ssh_get_error(my_ssh_session_C_2_s[i]));
            ssh_free(my_ssh_session_C_2_s[i]);
            exit(-1);
        }

        if (verify_knownhost(my_ssh_session_C_2_s[i]) < 0) {
            ssh_disconnect(my_ssh_session_C_2_s[i]);
            ssh_free(my_ssh_session_C_2_s[i]);
            exit(-1);
        }

        rc = ssh_userauth_password(my_ssh_session_C_2_s[i], NULL, password);
        if (rc != SSH_AUTH_SUCCESS) {
            fprintf(stderr, "Error authenticating with password: %s\n",
                    ssh_get_error(my_ssh_session_C_2_s[i]));
            ssh_disconnect(my_ssh_session_C_2_s[i]);
            ssh_free(my_ssh_session_C_2_s[i]);
            exit(-1);
        }

        exec_remote_processes(my_ssh_session_C_2_s[i], command_for_C_2_s[i]);
    }

    ssh_disconnect(my_ssh_session_master);
    ssh_free(my_ssh_session_master);
    for (i = 0; i < num_ssh_servers_for_C_1_s; i = i + 1) {
        ssh_disconnect(my_ssh_session_C_1_s[i]);
        ssh_free(my_ssh_session_C_1_s[i]);
    }
    for (i = 0; i < num_ssh_servers_for_C_2_s; i = i + 1) {
        ssh_disconnect(my_ssh_session_C_2_s[i]);
        ssh_free(my_ssh_session_C_2_s[i]);
    }

    return (0);
}

int verify_knownhost(ssh_session session) {
    char *hexa;
    int state;
    char buf[10];
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey;
    int rc;

    state = ssh_is_server_known(session);

    rc = ssh_get_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    switch (state) {
    case SSH_SERVER_KNOWN_OK:
        break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
        fprintf(stderr, "Host key for server changed : server's one is now :\n");
        ssh_print_hexa("Public key hash", hash, hlen);
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr, "For security reason, connection will be stopped\n");
        return -1;
    case SSH_SERVER_FOUND_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other type of key exists.\n");
        fprintf(stderr, "An attacker might change the default server key to confuse your client"
                "into thinking the key does not exist\n"
                "We advise you to rerun the client with -d or -r for more safety.\n");
        return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
        fprintf(stderr, "Could not find known host file. If you accept the host key here,\n");
        fprintf(stderr, "the file will be automatically created.\n");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_SERVER_NOT_KNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        fprintf(stderr, "The server is unknown. Do you trust the host key ?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa);
        ssh_string_free_char(hexa);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        if (strncasecmp(buf, "yes", 3) != 0) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        fprintf(stderr, "This new key will be written on disk for further usage. do you agree ?\n");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        if (strncasecmp(buf, "yes", 3) == 0) {
            if (ssh_write_knownhost(session) < 0) {
                ssh_clean_pubkey_hash(&hash);
                fprintf(stderr, "error %s\n", strerror(errno));
                return -1;
            }
        }

        break;
    case SSH_SERVER_ERROR:
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr, "%s", ssh_get_error(session));
        return -1;
    }
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int exec_remote_processes(ssh_session session, char *in_command) {
    ssh_channel channel;
    int rc;
    char buffer[256];
    unsigned int nbytes;
    channel = ssh_channel_new(session);
    if (channel == NULL) return SSH_ERROR;
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }
    rc = ssh_channel_request_exec(channel, in_command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        if (write(1, buffer, nbytes) != nbytes) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_OK;
}

