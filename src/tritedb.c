/* BSD 2-Clause License
 *
 * Copyright (c) 2018, Andrea Giacomo Baldan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/eventfd.h>
#include "server.h"
#include "network.h"
#include "util.h"
#include "config.h"


// Stops epoll_wait loops by sending an event
void sigint_handler(int signum) {
    printf("\n");
    eventfd_write(config.run, 1);
}


int main(int argc, char **argv) {

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    char *addr = DEFAULT_HOSTNAME;
    char *port = DEFAULT_PORT;
    char *conf = DEFAULT_CONF_PATH;
    char *mode = "STANDALONE";
    int debug = 0;
    int fd = -1;
    int opt;

    // Set default configuration
    config_set_default();

    while ((opt = getopt(argc, argv, "a:c:p:m:vn:")) != -1) {
        switch (opt) {
            case 'a':
                addr = optarg;
                strcpy(config.hostname, addr);
                break;
            case 'c':
                conf = optarg;
                break;
            case 'p':
                port = optarg;
                strcpy(config.port, port);
                break;
            case 'm':
                mode = optarg;
                config.mode = STREQ(mode, "CLUSTER", 7) ? CLUSTER : STANDALONE;
                break;
            case 'v':
                debug = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a addr] [-p port] [-m mode] [-c conf] [-v]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        if (STREQ(argv[optind], "join", 4) == 0) {

            // Target is the pair target_host:port+10000
            char *target = argv[optind + 1];
            int tport = atoi(argv[optind + 2]) + 10000;

            tinfo("Connecting to %s:%d", target, tport);
            // Connect to the listening peer node
            fd = open_connection(target, tport);
            set_nonblocking(fd);
            set_tcp_nodelay(fd);
        }
    }

    // Override default DEBUG mode
    config.loglevel = debug == 1 ? DEBUG : WARNING;

    // Try to load a configuration, if found
    config_load(conf);

    // Initialize logging
    t_log_init(config.logpath);

    config_print();

    // Start
    start_server(config.hostname, config.port, fd);

    // Close logger
    t_log_close();

    return 0;
}
