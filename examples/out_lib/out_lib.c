#if 0
/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_meta.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_parser.h>


#ifdef FLB_HAVE_LIBBACKTRACE
#undef FLB_HAVE_LIBBACKTRACE
#endif

/* Libbacktrace support */
#ifdef FLB_HAVE_LIBBACKTRACE
#include <backtrace.h>
#include <backtrace-supported.h>

struct flb_stacktrace {
    struct backtrace_state *state;
	int error;
    int line;
};

struct flb_stacktrace flb_st;

static void flb_stacktrace_error_callback(void *data,
                                          const char *msg, int errnum)
{
    struct flb_stacktrace *ctx = data;
    fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
	ctx->error = 1;
}

static int flb_stacktrace_print_callback(void *data, uintptr_t pc,
                                         const char *filename, int lineno,
                                         const char *function)
{
    struct flb_stacktrace *p = data;

    fprintf(stdout, "#%-2i 0x%-17lx in  %s() at %s:%d\n",
            p->line,
            (unsigned long) pc,
            function == NULL ? "???" : function,
            filename == NULL ? "???" : filename + sizeof(FLB_SOURCE_DIR),
            lineno);
    p->line++;
    return 0;
}

static inline void flb_stacktrace_init(char *prog)
{
    memset(&flb_st, '\0', sizeof(struct flb_stacktrace));
    flb_st.state = backtrace_create_state(prog,
                                          BACKTRACE_SUPPORTS_THREADS,
                                          flb_stacktrace_error_callback, NULL);
}

void flb_stacktrace_print()
{
    struct flb_stacktrace *ctx;

    ctx = &flb_st;
    backtrace_full(ctx->state, 3, flb_stacktrace_print_callback,
                   flb_stacktrace_error_callback, ctx);
}

#endif

#ifdef FLB_HAVE_MTRACE
#include <mcheck.h>
#endif

struct flb_config *config;

#define PLUGIN_INPUT    0
#define PLUGIN_OUTPUT   1
#define PLUGIN_FILTER   2

#define get_key(a, b, c)   mk_rconf_section_get_key(a, b, c)
#define n_get_key(a, b, c) (intptr_t) get_key(a, b, c)
#define s_get_key(a, b, c) (char *) get_key(a, b, c)

static void flb_help(int rc, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *in;
    struct flb_output_plugin *out;
    struct flb_filter_plugin *filter;

    printf("Usage: fluent-bit [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -b  --storage_path=PATH\tspecify a storage buffering path\n");
    printf("  -c  --config=FILE\tspecify an optional configuration file\n");
#ifdef FLB_HAVE_FORK
    printf("  -d, --daemon\t\trun Fluent Bit in background mode\n");
#endif
    printf("  -f, --flush=SECONDS\tflush timeout in seconds (default: %i)\n",
           FLB_CONFIG_FLUSH_SECS);
    printf("  -F  --filter=FILTER\t set a filter\n");
    printf("  -i, --input=INPUT\tset an input\n");
    printf("  -m, --match=MATCH\tset plugin match, same as '-p match=abc'\n");
    printf("  -o, --output=OUTPUT\tset an output\n");
    printf("  -p, --prop=\"A=B\"\tset plugin configuration property\n");
#ifdef FLB_HAVE_PARSER
    printf("  -R, --parser=FILE\tspecify a parser configuration file\n");
#endif
    printf("  -e, --plugin=FILE\tload an external plugin (shared lib)\n");
    printf("  -l, --log_file=FILE\twrite log info to a file\n");
    printf("  -t, --tag=TAG\t\tset plugin tag, same as '-p tag=abc'\n");
#ifdef FLB_HAVE_STREAM_PROCESSOR
    printf("  -T, --sp-task=SQL\tdefine a stream processor task\n");
#endif
    printf("  -v, --verbose\t\tenable verbose mode\n");
#ifdef FLB_HAVE_HTTP_SERVER
    printf("  -H, --http\t\tenable monitoring HTTP server\n");
    printf("  -P, --port\t\tset HTTP server TCP port (default: %s)\n",
           FLB_CONFIG_HTTP_PORT);
#endif
    printf("  -s, --coro_stack_size\tSet coroutines stack size in bytes "
           "(default: %i)\n", config->coro_stack_size);
    printf("  -q, --quiet\t\tquiet mode\n");
    printf("  -S, --sosreport\tsupport report for Enterprise customers\n");
    printf("  -V, --version\t\tshow version number\n");
    printf("  -h, --help\t\tprint this help\n\n");

    printf("%sInputs%s\n", ANSI_BOLD, ANSI_RESET);

    /* Iterate each supported input */
    mk_list_foreach(head, &config->in_plugins) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        if (strcmp(in->name, "lib") == 0 || (in->flags & FLB_INPUT_PRIVATE)) {
            /* useless..., just skip it. */
            continue;
        }
        printf("  %-22s%s\n", in->name, in->description);
    }
    printf("\n%sOutputs%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->out_plugins) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (strcmp(out->name, "lib") == 0) {
            /* useless..., just skip it. */
            continue;
        }
        printf("  %-22s%s\n", out->name, out->description);
    }

    printf("\n%sFilters%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->filter_plugins) {
        filter = mk_list_entry(head, struct flb_filter_plugin, _head);
        printf("  %-22s%s\n", filter->name, filter->description);
    }

    printf("\n%sInternal%s\n", ANSI_BOLD, ANSI_RESET);
    printf(" Event Loop  = %s\n", mk_event_backend());
    printf(" Build Flags = %s\n", FLB_INFO_FLAGS);
    exit(rc);
}

static void flb_version()
{
    printf("Fluent Bit v%s\n", FLB_VERSION_STR);
    exit(EXIT_SUCCESS);
}

static void flb_banner()
{
    fprintf(stderr, "%sFluent Bit v%s%s\n",
            ANSI_BOLD, FLB_VERSION_STR, ANSI_RESET);
    fprintf(stderr, "%sCopyright (C) Treasure Data%s\n\n",
            ANSI_BOLD ANSI_YELLOW, ANSI_RESET);
}

#define flb_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n" , sizeof(#X ")\n")-1); \
    break;

static void flb_signal_handler(int signal)
{
    char s[] = "[engine] caught signal (";

    /* write signal number */
    write(STDERR_FILENO, s, sizeof(s) - 1);
    switch (signal) {
        flb_print_signal(SIGINT);
#ifndef _WIN32
        flb_print_signal(SIGQUIT);
        flb_print_signal(SIGHUP);
#endif
        flb_print_signal(SIGTERM);
        flb_print_signal(SIGSEGV);
    };

    /* Signal handlers */
    switch (signal) {
    case SIGINT:
#ifndef _WIN32
    case SIGQUIT:
    case SIGHUP:
#endif
        flb_engine_shutdown(config);
#ifdef FLB_HAVE_MTRACE
        /* Stop tracing malloc and free */
        muntrace();
#endif
        _exit(EXIT_SUCCESS);
    case SIGTERM:
        flb_engine_exit(config);
        break;
    case SIGSEGV:
#ifdef FLB_HAVE_LIBBACKTRACE
        flb_stacktrace_print();
#endif
        abort();
    default:
        break;
    }
}

static void flb_signal_init()
{
    signal(SIGINT,  &flb_signal_handler);
#ifndef _WIN32
    signal(SIGQUIT, &flb_signal_handler);
    signal(SIGHUP,  &flb_signal_handler);
#endif
    signal(SIGTERM, &flb_signal_handler);
    signal(SIGSEGV, &flb_signal_handler);
}

static int input_set_property(struct flb_input_instance *in, char *kv)
{
    int ret;
    int len;
    int sep;
    char *key;
    char *value;

    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }

    key = mk_string_copy_substr(kv, 0, sep);
    value = kv + sep + 1;

    if (!key) {
        return -1;
    }

    ret = flb_input_set_property(in, key, value);
    if (ret == -1) {
        fprintf(stderr, "[error] setting up '%s' plugin property '%s'\n",
                in->p->name, key);
    }

    flb_free(key);
    return ret;
}

static int output_set_property(struct flb_output_instance *out, char *kv)
{
    int ret;
    int len;
    int sep;
    char *key;
    char *value;
    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }

    key = mk_string_copy_substr(kv, 0, sep);
    value = kv + sep + 1;

    if (!key) {
        return -1;
    }

    ret = flb_output_set_property(out, key, value);
    flb_free(key);
    return ret;
}

static int filter_set_property(struct flb_filter_instance *filter, char *kv)
{
    int ret;
    int len;
    int sep;
    char *key;
    char *value;

    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }

    key = mk_string_copy_substr(kv, 0, sep);
    value = kv + sep + 1;

    if (!key) {
        return -1;
    }

    ret = flb_filter_set_property(filter, key, value);
    flb_free(key);
    return ret;
}

static void flb_service_conf_err(struct mk_rconf_section *section, char *key)
{
    fprintf(stderr, "Invalid configuration value at %s.%s\n",
            section->name, key);
}

static int flb_service_conf_path_set(struct flb_config *config, char *file)
{
    char *end;
    char *path;

    path = realpath(file, NULL);
    if (!path) {
        return -1;
    }

    /* lookup path ending and truncate */
    end = strrchr(path, FLB_DIRCHAR);
    if (!end) {
        free(path);
        return -1;
    }

    end++;
    *end = '\0';
    config->conf_path = flb_strdup(path);
    free(path);

    return 0;
}

static int my_stdout_json(void* data, size_t size)
{
    printf("[%s]\n",__FUNCTION__);
    printf("data is %p\n", data);
    printf("%s\n",(char*)data);
    printf("\n");

    flb_lib_free(data);
    return 0;
}

int my_stdout_json1(void *record, size_t size, void *data)
{
    printf("[%s]\n",__FUNCTION__);
    printf("%s\n",(char*)record);

    flb_lib_free(record);
    return 0;
}


int my_stdout_msgpack(void* data, size_t size)
{
    printf("[%s]",__FUNCTION__);
    msgpack_object_print(stdout, *(msgpack_object*)data);
    printf("\n");

    flb_lib_free(data);
    return 0;
}


static int flb_service_conf(struct flb_config *config, char *file)
{
    int ret = -1;
    char *tmp;
    char *name;
    struct mk_list *head;
    struct mk_list *h_prop;
    struct mk_rconf *fconf = NULL;
    struct mk_rconf_entry *entry;
    struct mk_rconf_section *section;
    struct flb_input_instance *in;
    struct flb_output_instance *out;
    struct flb_filter_instance *filter;

#ifdef FLB_HAVE_STATIC_CONF
    fconf = flb_config_static_open(file);
#else
    fconf = mk_rconf_open(file);
#endif

    if (!fconf) {
        return -1;
    }

    /* Process all meta commands */
    mk_list_foreach(head, &fconf->metas) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        flb_meta_run(config, entry->key, entry->val);
    }

    /* Set configuration root path */
    flb_service_conf_path_set(config, file);

    /* Validate sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);

        if (strcasecmp(section->name, "SERVICE") == 0 ||
            strcasecmp(section->name, "INPUT") == 0 ||
            strcasecmp(section->name, "FILTER") == 0 ||
            strcasecmp(section->name, "OUTPUT") == 0) {

            /* continue on valid sections */
            continue;
        }

        /* Extra sanity checks */
        if (strcasecmp(section->name, "PARSER") == 0) {
            fprintf(stderr,
                    "Section [PARSER] is not valid in the main "
                    "configuration file. It belongs to \n"
                    "the Parsers_File configuration files.\n");
        }
        else {
            fprintf(stderr,
                    "Error: unexpected section [%s] in the main "
                    "configuration file.\n", section->name);
        }
        exit(EXIT_FAILURE);
    }

    /* Read main [SERVICE] section */
    section = mk_rconf_section_get(fconf, "SERVICE");
    if (section) {
        /* Iterate properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            /* Set the property */
            flb_config_set_property(config, entry->key, entry->val);
        }
    }


    /* Read all [INPUT] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "INPUT") != 0) {
            continue;
        }

        /* Get the input plugin name */
        name = s_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        flb_debug("[service] loading input: %s", name);

        /* Create an instace of the plugin */
        tmp = flb_env_var_translate(config->env, name);
        in = flb_input_new(config, tmp, NULL, FLB_TRUE);
        mk_mem_free(name);
        if (!in) {
            fprintf(stderr, "Input plugin '%s' cannot be loaded\n", tmp);
            mk_mem_free(tmp);
            goto flb_service_conf_end;
        }
        mk_mem_free(tmp);

        /* Iterate other properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            if (strcasecmp(entry->key, "Name") == 0) {
                continue;
            }

            /* Set the property */
            ret = flb_input_set_property(in, entry->key, entry->val);
            if (ret == -1) {
                fprintf(stderr, "Error setting up %s plugin property '%s'\n",
                        in->name, entry->key);
                goto flb_service_conf_end;
            }
        }
    }

    /* Read all [OUTPUT] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "OUTPUT") != 0) {
            continue;
        }

        /* Get the output plugin name */
        name = s_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        /* Create an instace of the plugin */
        tmp = flb_env_var_translate(config->env, name);
        out = flb_output_new(config, tmp, NULL);
        mk_mem_free(name);
        if (!out) {
            fprintf(stderr, "Output plugin '%s' cannot be loaded\n", tmp);
            mk_mem_free(tmp);
            goto flb_service_conf_end;
        }
        if(tmp != NULL && strcmp(tmp, "lib") == 0) {
            struct flb_lib_out_cb * cb = (struct flb_lib_out_cb *)calloc(1, sizeof(struct flb_lib_out_cb));
            cb->cb = my_stdout_json1;
            cb->data = NULL;
            out->data = (void *)cb;
        }
        mk_mem_free(tmp);

        /* Iterate other properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            if (strcasecmp(entry->key, "Name") == 0) {
                continue;
            }

            /* Set the property */
            flb_output_set_property(out, entry->key, entry->val);
        }
    }

    /* Read all [FILTER] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "FILTER") != 0) {
            continue;
        }
        /* Get the filter plugin name */
        name = s_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }
        /* Create an instace of the plugin */
        tmp = flb_env_var_translate(config->env, name);
        filter = flb_filter_new(config, tmp, NULL);
        mk_mem_free(tmp);
        mk_mem_free(name);
        if (!filter) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        /* Iterate other properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            if (strcasecmp(entry->key, "Name") == 0) {
                continue;
            }

            /* Set the property */
            flb_filter_set_property(filter, entry->key, entry->val);
        }
    }

    ret = 0;

 flb_service_conf_end:
    if (fconf != NULL) {
        mk_rconf_free(fconf);
    }
    return ret;
}

int main(int argc, char **argv)
{
    int opt;
    int ret;

    /* handle plugin properties:  -1 = none, 0 = input, 1 = output */
    int last_plugin = -1;

    /* local variables to handle config options */
    char *cfg_file = NULL;
    struct flb_input_instance *in = NULL;
    struct flb_output_instance *out = NULL;
    struct flb_filter_instance *filter = NULL;

#ifdef FLB_HAVE_LIBBACKTRACE
    flb_stacktrace_init(argv[0]);
#endif

    /* Setup long-options */
    static const struct option long_opts[] = {
        { "storage_path",    required_argument, NULL, 'b' },
        { "config",          required_argument, NULL, 'c' },
#ifdef FLB_HAVE_FORK
        { "daemon",          no_argument      , NULL, 'd' },
#endif
        { "flush",           required_argument, NULL, 'f' },
        { "http",            no_argument      , NULL, 'H' },
        { "log_file",        required_argument, NULL, 'l' },
        { "port",            required_argument, NULL, 'P' },
        { "input",           required_argument, NULL, 'i' },
        { "match",           required_argument, NULL, 'm' },
        { "output",          required_argument, NULL, 'o' },
        { "filter",          required_argument, NULL, 'F' },
#ifdef FLB_HAVE_PARSER
        { "parser",          required_argument, NULL, 'R' },
#endif
        { "prop",            required_argument, NULL, 'p' },
        { "plugin",          required_argument, NULL, 'e' },
        { "tag",             required_argument, NULL, 't' },
#ifdef FLB_HAVE_STREAM_PROCESSOR
        { "sp-task",         required_argument, NULL, 'T' },
#endif
        { "version",         no_argument      , NULL, 'V' },
        { "verbose",         no_argument      , NULL, 'v' },
        { "quiet",           no_argument      , NULL, 'q' },
        { "help",            no_argument      , NULL, 'h' },
        { "coro_stack_size", required_argument, NULL, 's'},
        { "sosreport",       no_argument      , NULL, 'S' },
#ifdef FLB_HAVE_HTTP_SERVER
        { "http_server",     no_argument      , NULL, 'H' },
        { "http_listen",     required_argument, NULL, 'L' },
        { "http_port",       required_argument, NULL, 'P' },
#endif
        { NULL, 0, NULL, 0 }
    };

#ifdef FLB_HAVE_MTRACE
    /* Start tracing malloc and free */
    mtrace();
#endif


#ifdef _WIN32
    /* Initialize sockets */
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", err);
        exit(EXIT_FAILURE);
    }
#endif

    /* Signal handler */
    flb_signal_init();

    /* Initialize Monkey Core library */
    mk_core_init();

    /* Create configuration context */
    config = flb_config_init();
    if (!config) {
        exit(EXIT_FAILURE);
    }

#ifndef FLB_HAVE_STATIC_CONF

    /* Parse the command line options */
    while ((opt = getopt_long(argc, argv,
                              "b:c:df:i:m:o:R:F:p:e:"
                              "t:T:l:vqVhL:HP:s:S",
                              long_opts, NULL)) != -1) {

        switch (opt) {
        case 'b':
            config->storage_path = flb_strdup(optarg);
            break;
        case 'c':
            cfg_file = flb_strdup(optarg);
            break;
#ifdef FLB_HAVE_FORK
        case 'd':
            config->daemon = FLB_TRUE;
            break;
#endif
        case 'e':
            ret = flb_plugin_load_router(optarg, config);
            if (ret == -1) {
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            config->flush = atof(optarg);
            break;
        case 'i':
            in = flb_input_new(config, optarg, NULL, FLB_TRUE);
            if (!in) {
                flb_utils_error(FLB_ERR_INPUT_INVALID);
            }
            last_plugin = PLUGIN_INPUT;
            break;
        case 'm':
            if (last_plugin == PLUGIN_FILTER) {
                flb_filter_set_property(filter, "match", optarg);
            }
            else if (last_plugin == PLUGIN_OUTPUT) {
                flb_output_set_property(out, "match", optarg);
            }
            break;
        case 'o':
            out = flb_output_new(config, optarg, NULL);
            if (!out) {
                flb_utils_error(FLB_ERR_OUTPUT_INVALID);
            }
            if(optarg != NULL && strcmp(optarg, "lib") == 0) {
                printf("%d:pass\n", __LINE__);
                struct flb_lib_out_cb * cb = (struct flb_lib_out_cb *)calloc(1, sizeof(struct flb_lib_out_cb));
                cb->cb = my_stdout_json1;
                cb->data = NULL;
                out->data = (void *)cb;
            }
            last_plugin = PLUGIN_OUTPUT;
            break;
#ifdef FLB_HAVE_PARSER
        case 'R':
            ret = flb_parser_conf_file(optarg, config);
            if (ret != 0) {
                exit(EXIT_FAILURE);
            }
            break;
#endif
        case 'F':
            filter = flb_filter_new(config, optarg, NULL);
            if (!filter) {
                flb_utils_error(FLB_ERR_FILTER_INVALID);
            }
            last_plugin = PLUGIN_FILTER;
            break;
        case 'l':
            config->log_file = flb_strdup(optarg);
            break;
        case 'p':
            if (last_plugin == PLUGIN_INPUT) {
                ret = input_set_property(in, optarg);
                if (ret != 0) {
                    exit(EXIT_FAILURE);
                }
            }
            else if (last_plugin == PLUGIN_OUTPUT) {
                output_set_property(out, optarg);
            }
            else if (last_plugin == PLUGIN_FILTER) {
                filter_set_property(filter, optarg);
            }
            break;
        case 't':
            if (in) {
                flb_input_set_property(in, "tag", optarg);
            }
            break;
#ifdef FLB_HAVE_STREAM_PROCESSOR
        case 'T':
            flb_slist_add(&config->stream_processor_tasks, optarg);
            break;
#endif
        case 'h':
            flb_help(EXIT_SUCCESS, config);
            break;
#ifdef FLB_HAVE_HTTP_SERVER
        case 'H':
            config->http_server = FLB_TRUE;
            break;
        case 'L':
            if (config->http_listen) {
                flb_free(config->http_listen);
            }
            config->http_listen = flb_strdup(optarg);
            break;
        case 'P':
            if (config->http_port) {
                flb_free(config->http_port);
            }
            config->http_port = flb_strdup(optarg);
            break;
#endif
        case 'V':
            flb_version();
            exit(EXIT_SUCCESS);
        case 'v':
            config->verbose++;
            break;
        case 'q':
            config->verbose = FLB_LOG_OFF;
            break;
        case 's':
            config->coro_stack_size = (unsigned int) atoi(optarg);
            break;
        case 'S':
            config->support_mode = FLB_TRUE;
            break;
        default:
            flb_help(EXIT_FAILURE, config);
        }
    }
#endif /* !FLB_HAVE_STATIC_CONF */

    if (config->verbose != FLB_LOG_OFF) {
        flb_banner();
    }

    /* Validate config file */
#ifndef FLB_HAVE_STATIC_CONF
    if (cfg_file) {
        if (access(cfg_file, R_OK) != 0) {
            flb_utils_error(FLB_ERR_CFG_FILE);
        }

        /* Load the service configuration file */
        ret = flb_service_conf(config, cfg_file);
        if (ret != 0) {
            flb_utils_error(FLB_ERR_CFG_FILE_STOP);
        }
        flb_free(cfg_file);
    }
#else
    ret = flb_service_conf(config, "fluent-bit.conf");
    if (ret != 0) {
        flb_utils_error(FLB_ERR_CFG_FILE_STOP);
    }
#endif

    /* Check co-routine stack size */
    if (config->coro_stack_size < getpagesize()) {
        flb_utils_error(FLB_ERR_CORO_STACK_SIZE);
    }

    /* Validate flush time (seconds) */
    if (config->flush <= (double) 0.0) {
        flb_utils_error(FLB_ERR_CFG_FLUSH);
    }

    /* Inputs */
    ret = flb_input_check(config);
    if (ret == -1 && config->support_mode == FLB_FALSE) {
        flb_utils_error(FLB_ERR_INPUT_UNDEF);
    }

    /* Outputs */
    ret = flb_output_check(config);
    if (ret == -1 && config->support_mode == FLB_FALSE) {
        flb_utils_error(FLB_ERR_OUTPUT_UNDEF);
    }

    if (config->verbose == FLB_TRUE) {
        flb_utils_print_setup(config);
    }

#ifdef FLB_HAVE_FORK
    /* Run in background/daemon mode */
    if (config->daemon == FLB_TRUE) {
        flb_utils_set_daemon(config);
    }
#endif

    ret = flb_engine_start(config);
    if (ret == -1) {
        flb_engine_shutdown(config);
    }

    return 0;
}

#else
/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015-2017 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit.h>
#include <msgpack.h>

static flb_ctx_t *gCtx = NULL;

//add by lym
#define CONFIG_LINE_BUFFERSIZE 4096
#define CONFIG_KEY_LENGTH 32
#define CONFIG_PARSER_MAX_NUM 100
struct config_result{
    char *Parsers_File;
    char *grep_regex;
    int  parser_num;
    char *parser[CONFIG_PARSER_MAX_NUM];
};
static struct config_result configResult;

static int config_filter_value_get(char *config_file_name)
{
    FILE *fp=NULL;
    char buf[CONFIG_LINE_BUFFERSIZE];
    char *find = NULL;
    int index = 0;
    int wait_flag=0;
    char wait_key[CONFIG_KEY_LENGTH];
    int value_len;

    if(config_file_name==NULL)
    {
        printf("%s, param error\n", __FUNCTION__);
        return -1;
    }

    fp=fopen(config_file_name,"rb");
    if(fp==NULL)
    {
        printf("%s, error: cant find usbconfig file=%s\n", __FUNCTION__, config_file_name);
        return -1;
    }

    memset(wait_key, 0, CONFIG_KEY_LENGTH);
    memset(&configResult, 0, sizeof(struct config_result));

    while(!feof(fp))
    {
        memset(buf, 0, CONFIG_LINE_BUFFERSIZE);
        fgets(buf, CONFIG_LINE_BUFFERSIZE, fp);
        if(buf[0] == '#' || buf[0] == '\0' || buf[0] == '\n' || (buf[0] == '\r' && buf[1] == '\n'))
            continue;

        printf("%s, buf=%s\n", __FUNCTION__, buf);
        index = strlen(buf);
        if(buf[index-1] == '\n')
            buf[index-1] = '\0';
        if((buf[index -2]) == '\r')
            buf[index -2] = '\0';

        if(buf[0]=='['){
            if(buf[1]=='\0'||buf[1]==']'){
                continue;
            }
            if(strncmp(buf+1, "SERVICE",7)==0)
            {
                //we need get Parsers_File
                strncpy(wait_key,"Parsers_File",CONFIG_KEY_LENGTH);
                wait_flag=1;
            }
            else if(strncmp(buf+1, "FILTER", 6)==0)
            {
                //we need get name=grep | parser
                strncpy(wait_key,"Name",CONFIG_KEY_LENGTH);
                wait_flag=1;
            }
            else
            {
                wait_flag=0;
            }
            printf("%s, wait_flag=%d, wait_key=%s\n", __FUNCTION__, wait_flag, wait_key);
        }
        else
        {
            if(wait_flag)
            {
                find=strstr(buf, wait_key);
                if(find==NULL)
                {
                    //printf("%s not find\n", wait_key);
                    continue;
                }
                if(((find-buf)>4)||(find[0]=='#'))//not key, maybe only in value
                {
                    printf("%s, find but position error\n", wait_key);
                    continue;
                }
                if(wait_flag==1)
                {
                    if(strncmp(find,"Parsers_File",strlen("Parsers_File"))==0)
                    {
                        printf("%s, find=%s\n", __FUNCTION__, find);
                        char *ptmp=find+strlen("Parsers_File");
                        printf("%s, ptmp=%s\n", __FUNCTION__, ptmp);
                        while(1)
                        {
                            //jump blankspace
                            if(ptmp[0]==' ')
                                ptmp++;
                            else
                                break;
                        }
                        printf("%s, ptmp=%s\n", __FUNCTION__, ptmp);
                        value_len=strlen(ptmp);
                        if(value_len>0)
                        {
                            //store value
                            printf("len=%d, Parsers_File=%s\n", value_len, ptmp);
                            configResult.Parsers_File=(char*)calloc(value_len+1, 1);
                            if(configResult.Parsers_File==NULL)
                            {
                                printf("%s, %d, calloc %d error\n", __FUNCTION__, __LINE__,value_len+1);
                                continue;
                            }
                            strncpy(configResult.Parsers_File, ptmp, value_len);
                            wait_flag=0;
                        }
                    }
                    else if(strncmp(find,"Name",strlen("Name"))==0)
                    {
                        printf("%s, find=%s\n", __FUNCTION__, find);
                        if(strstr(find, "grep"))
                        {
                            //we need get Regex
                            strncpy(wait_key,"Regex",CONFIG_KEY_LENGTH);
                            wait_flag=2;
                        }
                        else if(strstr(find, "parser"))
                        {
                            //we need get Parser, not only 1
                            strncpy(wait_key,"Parser",CONFIG_KEY_LENGTH);
                            wait_flag=3;
                        }
                        printf("%s, 2, wait_flag=%d, wait_key=%s\n", __FUNCTION__, wait_flag, wait_key);
                    }
                }
                else if(wait_flag==2)
                {//Regex log xxxxxx
                    char *find2 = NULL;
                    find2=strstr(buf, "log");
                    if(find2==NULL)
                        continue;

                    /*char *ptmp=find2+strlen("log");
                    while(1)
                    {
                        //jump blankspace
                        if(ptmp[0]==' ')
                            ptmp++;
                        else
                            break;
                    }*/
                    value_len=strlen(find2);
                    if(value_len>0)
                    {
                        //store value
                        printf("len=%d, log=%s\n", value_len, find2);
                        configResult.grep_regex=(char*)calloc(value_len+1, 1);
                        if(configResult.grep_regex==NULL)
                        {
                            printf("%s, %d, calloc %d error\n", __FUNCTION__, __LINE__,value_len+1);
                            continue;
                        }
                        strncpy(configResult.grep_regex, find2, value_len);
                        wait_flag=0;
                    }

                }
                else if(wait_flag==3)
                {//Parser parser_name
                    char *ptmp=find+strlen("Parser");
                    while(1)
                    {
                        //jump blankspace
                        if(ptmp[0]==' ')
                            ptmp++;
                        else
                            break;
                    }
                    value_len=strlen(ptmp);
                    if(value_len>0)
                    {
                        //store value
                        printf("len=%d, parser=%s\n", value_len, ptmp);
                        if(configResult.parser_num >= CONFIG_PARSER_MAX_NUM)
                        {
                            printf("%s, error: too many parser num=%d\n", __FUNCTION__, configResult.parser_num);
                            continue;
                        }

                        configResult.parser[configResult.parser_num]=(char*)calloc(value_len+1, 1);
                        if(configResult.parser[configResult.parser_num]==NULL)
                        {
                            printf("%s, %d, calloc %d error\n", __FUNCTION__, __LINE__,value_len+1);
                            continue;
                        }
                        strncpy(configResult.parser[configResult.parser_num], ptmp, value_len);
                        configResult.parser_num++;
                        printf("%s, parser_num=%d, parser=%s\n", __FUNCTION__, configResult.parser_num, ptmp);
                    }

                }
            }
            else
            {
                //printf("%s, wait_flag=%d\n", __FUNCTION__, wait_flag);
            }
        }

    }
    fclose(fp);

    return 0;
}
static int config_filter_value_free(void)
{
    int i=0;

    if(configResult.Parsers_File != NULL)
    {
        free(configResult.Parsers_File);
        configResult.Parsers_File=NULL;
    }
    if(configResult.grep_regex != NULL)
    {
        free(configResult.grep_regex);
        configResult.grep_regex=NULL;
    }
    for(i=0;i<configResult.parser_num;i++)
    {
        if(configResult.parser[i] != NULL)
        {
            free(configResult.parser[i]);
            configResult.parser[i]=NULL;
        }
    }
    configResult.parser_num=0;

    return 0;
}

//end by lym


int my_lib_json(void *record, size_t size, void *data)
{
    printf("[%s]:%s\n",__FUNCTION__, (char *)record);
    flb_lib_free(record);
    return 0;
}


int my_stdout_msgpack1(void *record, size_t size, void *data)
{
    printf("[%s]",__FUNCTION__);
    msgpack_object_print(stdout, *(msgpack_object*)record);
    printf("\n");

    flb_lib_free(record);
    return 0;
}


int main()
{
    const char *config_file_path = "/data/stb.conf";
    const char *log_file_path = "/data/logtest.log";
    int in_ffd;
    int filter_ffd;
    int out_ffd;


    if(access(log_file_path, F_OK) != 0) {
        FILE *f = fopen(log_file_path,  "w");
        if(f == NULL) {
            printf("failed to create log file\n");
            return -1;
        }
        fclose(f);
    }

    config_filter_value_get(config_file_path);

    /* Initialize library */
    gCtx = (flb_ctx_t *) flb_create();
    if (!gCtx) {
        return -1;
    }


    if(configResult.Parsers_File != NULL) {
        printf("%s, set services=%s\n", __FUNCTION__, configResult.Parsers_File);
        //service set
        flb_service_set(gCtx,
                        "Flush", "1",
                        "Daemon", "off",
                        "Parsers_File", configResult.Parsers_File,
                        NULL);
    }

    in_ffd = flb_input(gCtx, "tail", NULL);
    flb_input_set(gCtx, in_ffd, "tag", "test", "Path", log_file_path, NULL);

    /* filter grep */
    if(configResult.grep_regex != NULL)
    {
        printf("%s, set grep=%s\n", __FUNCTION__, configResult.grep_regex);
        filter_ffd = flb_filter(gCtx, "grep", NULL);
        flb_filter_set(gCtx, filter_ffd,"match", "*",  "Regex", configResult.grep_regex, NULL);
    }

    /* filter parser */
    printf("lym, filter start\n");
    filter_ffd = flb_filter(gCtx, "parser", NULL);
    flb_filter_set(gCtx, filter_ffd,
                   "Match", "*",
                   "Match_Rule", "*",
                   "Key_Name", "log",
                   "Reserve_Data", "On",
                   NULL);
    if(configResult.parser_num > 0)
    {
        int index=0;
        for(index=0;index<configResult.parser_num;index++)
        {
            if(configResult.parser[index] != NULL)
            {
                flb_filter_set(gCtx, filter_ffd, "Parser", configResult.parser[index],NULL);
                printf("%s, set Parser=%s\n", __FUNCTION__, configResult.parser[index]);
            }
        }
    }
    config_filter_value_free();

    /* Register my callback function */
    struct flb_lib_out_cb * cb = (struct flb_lib_out_cb *)calloc(1, sizeof(struct flb_lib_out_cb));
    cb->data = NULL;

    /* JSON format */
    cb->cb = my_lib_json;
    out_ffd = flb_output(gCtx, "lib", cb);
    flb_output_set(gCtx, out_ffd, "match", "test", "format", "json", NULL);

    /* Start the background worker */
    flb_start(gCtx);

    while(1) {
        sleep(100);
    }
    
    flb_stop(gCtx);

    /* Release Resources */
    flb_destroy(gCtx);

    return 0;
}


#endif
