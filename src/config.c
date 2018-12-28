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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include "util.h"
#include "config.h"


#define STREQ(s1, s2, len) strncasecmp(s1, s2, len) == 0 ? true : false


struct llevel {
    const char *lname;
    int loglevel;
};

static const struct llevel lmap[3] = {
    {"DEBUG", DEBUG},
    {"ERROR", ERROR},
    {"INFO", INFO}
};


/* static void config_deploy(Trie *ctrie); */
static void add_config_value(const char *key, const char *value) {

    size_t klen = strlen(key);
    size_t vlen = strlen(value);

    if (STREQ("log_level", key, klen) == true) {
        for (int i = 0; i < 3; i++) {
            if (STREQ(lmap[i].lname, value, vlen) == true)
                config.loglevel = lmap[i].loglevel;
        }
    } else if (STREQ("logpath", key, klen) == true) {
        config.logpath = value;
    }
}


static void strip_spaces(char **str) {
    if (!*str) return;
    while (isspace(**str) && **str) ++(*str);
}


static void read_string(char **str, char *dest) {

    if (!str || !dest) return;

    while (!isspace(**str) && **str) *dest++ = *(*str)++;
}


bool config_load(const char *configpath) {

    assert(configpath);

    FILE *fh = fopen(configpath, "r");

    if (!fh) {
        terror("Unable to open conf file %s", configpath);
        return false;
    }

    char line[256], key[256], value[256];
    int linenr = 0;
    char *pline, *pkey, *pval;

    while (fgets(line, 256, fh) != NULL) {

        memset(key, 0x00, 256);
        memset(value, 0x00, 256);

        linenr++;

        // Skip comments or empty lines
        if (line[0] == '#') continue;

        // Remove whitespaces if any before the key
        pline = line;
        strip_spaces(&pline);

        if (*pline == '\0') continue;

        // Read key
        pkey = key;
        read_string(&pline, pkey);

        // Remove whitespaces if any after the key and before the value
        strip_spaces(&pline);

        // Ignore eventually incomplete configuration, but notify it
        if (line[0] == '\0') {
            // TODO make warning
            terror("Incomplete configuration '%s' at line %d", key, linenr);
            continue;
        }

        // Read value
        pval = value;
        read_string(&pline, pval);

        // At this point we have key -> value ready to be ingested on the
        // global configuration object
        add_config_value(key, strdup(value));
    }

    return true;
}
