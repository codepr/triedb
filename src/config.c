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

#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <sys/eventfd.h>
#include "util.h"
#include "config.h"
#include "network.h"


struct llevel {
    const char *lname;
    int loglevel;
};

static const struct llevel lmap[5] = {
    {"DEBUG", DEBUG},
    {"WARNING", WARNING},
    {"ERROR", ERROR},
    {"INFO", INFORMATION},
    {"INFORMATION", INFORMATION}
};


// Reference to the config structure, could be refactored lately to a more
// structured configuration
struct config config;


static size_t read_memory_with_mul(const char *memory) {

    /* Extract digit part */
    size_t num = parse_int(memory);
    int mul = 1;

    /* Move the pointer forward till the first non-digit char */
    while (isdigit(*memory)) memory++;

    /* Set multiplier */
    if (STREQ(memory, "kb", 2))
        mul = 1024;
    else if (STREQ(memory, "mb", 2))
        mul = 1024 * 1024;
    else if (STREQ(memory, "gb", 2))
        mul = 1024 * 1024 * 1024;

    return num * mul;
}


static size_t read_time_with_mul(const char *time) {

    /* Extract digit part */
    size_t num = parse_int(time);
    int mul = 1;

    /* Move the pointer forward till the first non-digit char */
    while (isdigit(*time)) time++;

    /* Set multiplier */
    switch (*time) {
        case 'm':
            mul = 60;
            break;
        case 'd':
            mul = 60 * 60 * 24;
            break;
        default:
            mul = 1;
            break;
    }

    return num * mul;

}


static void add_config_value(const char *key, const char *value) {

    size_t klen = strlen(key);
    size_t vlen = strlen(value);

    if (STREQ("log_level", key, klen) == true) {
        for (int i = 0; i < 3; i++) {
            if (STREQ(lmap[i].lname, value, vlen) == true)
                config.loglevel = lmap[i].loglevel;
        }
    } else if (STREQ("log_path", key, klen) == true) {
        strcpy(config.logpath, value);
    } else if (STREQ("unix_socket", key, klen) == true) {
        config.socket_family = UNIX;
        strcpy(config.hostname, value);
    } else if (STREQ("ip_address", key, klen) == true) {
        config.socket_family = INET;
        strcpy(config.hostname, value);
    } else if (STREQ("ip_port", key, klen) == true) {
        strcpy(config.port, value);
    } else if (STREQ("max_memory", key, klen) == true) {
        config.max_memory = read_memory_with_mul(value);
    } else if (STREQ("mem_reclaim_time", key, klen) == true) {
        config.mem_reclaim_time = read_time_with_mul(value);
    }
}


static void strip_spaces(char **str) {
    if (!*str) return;
    while (isspace(**str) && **str) ++(*str);
}


static void read_bytes(char **str, char *dest) {

    if (!str || !dest) return;

    while (!isspace(**str) && **str) *dest++ = *(*str)++;
}


bool config_load(const char *configpath) {

    assert(configpath);

    FILE *fh = fopen(configpath, "r");

    if (!fh) {
        twarning("WARNING: Unable to open conf file %s", configpath);
        return false;
    }

    char line[0xff], key[0xff], value[0xff];
    int linenr = 0;
    char *pline, *pkey, *pval;

    while (fgets(line, 0xff, fh) != NULL) {

        memset(key, 0x00, 0xff);
        memset(value, 0x00, 0xff);

        linenr++;

        // Skip comments or empty lines
        if (line[0] == '#') continue;

        // Remove whitespaces if any before the key
        pline = line;
        strip_spaces(&pline);

        if (*pline == '\0') continue;

        // Read key
        pkey = key;
        read_bytes(&pline, pkey);

        // Remove whitespaces if any after the key and before the value
        strip_spaces(&pline);

        // Ignore eventually incomplete configuration, but notify it
        if (line[0] == '\0') {
            twarning("WARNING: Incomplete configuration '%s' at line %d. "
                    "Fallback to default.", key, linenr);
            continue;
        }

        // Read value
        pval = value;
        read_bytes(&pline, pval);

        // At this point we have key -> value ready to be ingested on the
        // global configuration object
        add_config_value(key, value);
    }

    return true;
}


void config_set_default(void) {
    config.version = VERSION;
    config.socket_family = DEFAULT_SOCKET_FAMILY;
    config.loglevel = DEFAULT_LOG_LEVEL;
    strcpy(config.logpath, DEFAULT_LOG_PATH);
    strcpy(config.hostname, DEFAULT_HOSTNAME);
    strcpy(config.port, DEFAULT_PORT);
    config.epoll_timeout = -1;
    config.run = eventfd(0, EFD_NONBLOCK);
    config.max_memory = read_memory_with_mul(DEFAULT_MAX_MEMORY);
    config.mem_reclaim_time = read_time_with_mul(DEFAULT_MEM_RECLAIM_TIME);
}


void config_print(void) {
    if (config.loglevel < WARNING) {
        const char *sfamily = config.socket_family == UNIX ? "Unix" : "Tcp";
        const char *llevel = NULL;
        for (int i = 0; i < 4; i++) {
            if (lmap[i].loglevel == config.loglevel)
                llevel = lmap[i].lname;
        }
        tinfo("Socket family: %s", sfamily);
        if (config.socket_family == UNIX) {
            tinfo("\tUnix socket: %s", config.hostname);
        } else {
            tinfo("\tAddress: %s", config.hostname);
            tinfo("\tPort: %s", config.port);
        }
        tinfo("Logging:");
        tinfo("\tlevel: %s", llevel);
        tinfo("\tlogpath: %s", config.logpath);
        tinfo("Max memory: %ld", config.max_memory);
        tinfo("Memory reclaim time: %ld", config.mem_reclaim_time);
    }
}
