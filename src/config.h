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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

// Run mode

#define STANDALONE                  0x00
#define CLUSTER                     0x01

// Default parameters

#define VERSION                     "0.5.1"
#define DEFAULT_MODE                STANDALONE
#define DEFAULT_SOCKET_FAMILY       INET
#define DEFAULT_LOG_LEVEL           INFORMATION
#define DEFAULT_LOG_PATH            "/tmp/triedb.log"
#define DEFAULT_CONF_PATH           "/etc/triedb/triedb.conf"
#define DEFAULT_HOSTNAME            "127.0.0.1"
#define DEFAULT_PORT                "9090"
#define DEFAULT_MAX_MEMORY          "4GB"
#define DEFAULT_MEM_RECLAIM_TIME    "1d"
#define DEFAULT_MAX_REQUEST_SIZE    "2MB"


struct config {
    /* triedb version <MAJOR.MINOR.PATCH> */
    const char *version;
    /* Instance run mode, can be either STANDALONE for a single node or CLUSTER
       for a distributed system */
    int mode;
    /* Eventfd to break the epoll_wait loop in case of signals */
    uint8_t run;
    /* Logging level, to be set by reading configuration */
    uint8_t loglevel;
    /* Epoll wait timeout, define even the number of times per second that the
       system will check for expired keys */
    int epoll_timeout;
    /* Socket family (Unix domain or TCP) */
    int socket_family;
    /* Log file path */
    char logpath[0xFF];
    /* Hostname to listen on */
    char hostname[0xFF];
    /* Port to open while listening, only if socket_family is INET,
     * otherwise it's ignored */
    char port[0xFF];
    /* Max memory to be used, after which the system starts to reclaim back by
     * freeing older items stored */
    size_t max_memory;
    /* Memory reclaim threshold, when reclaiming memory if max_memory limit has
     * been reached, the system starts to reclaim items older than this value */
    size_t mem_reclaim_time;
    /* Max memory request can allocate */
    size_t max_request_size;
    /* TCP backlog size */
    int tcp_backlog;
};

extern struct config *conf;


void config_set_default(void);
void config_print(void);
bool config_load(const char *);

char *time_to_string(size_t);
char *memory_to_string(size_t);

#endif
