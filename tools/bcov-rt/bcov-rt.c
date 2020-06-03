/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 *
 * ****************************************************************************/
/**
 *  \brief
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include "dump/patch.h"
#include "bcov-rt.h"

#define BCOV_DIR_SEP '/'
#define BCOV_FILE_SUFFIX ".bcov"
#define BCOV_OPTS_NAME "BCOV_OPTIONS"
#define BCOV_OPTS_DIR_NAME "coverage_dir"
#define BCOV_OPTS_PID_NAME "log_pid"
#define BCOV_OPTS_USER_TAG_NAME "tag"
#define BCOV_OPTS_USER_TAG_SIZE 32
#define BCOV_OPTS_TIME_TAG_SIZE 16
#define MAX_MOD_NAME_SIZE (64)
#define MAX_MOD_PATH_SIZE (1024)
#define MEM_PAGE_SIZE (0x1000U)
#define UNUSED(x) ((void)(x))

#ifdef NDEBUG
#define DEBUG_PRINT(fmt, ...) \
            do { ((void)(fmt, __VA_ARGS__)); } while (0)
#else
#define DEBUG_PRINT(fmt, ...) \
            do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)
#endif

static bool
is_data_segment(const char *permissions)
{
    return permissions[0] == 'r' && permissions[1] == 'w';
}

static bool
begins_with_bcov_magic(uint64_t addr)
{
    return bcov_has_valid_magic((const uint8_t *) addr);
}

static const char *
get_basename(const char *mod_name)
{
    return strrchr(mod_name, '/');
}

static void
parse_line(const char *line, size_t *mod_start, size_t *mod_end, char *perms,
           size_t *offset, char *device, int *inode, char *mod_name)
{
    sscanf(line, "%lx-%lx %s %lx %s %d %s", mod_start, mod_end,
           perms, offset, device, inode, mod_name);
}

static void
make_current_time_tag(char *out_str)
{
    long ms;  // Milliseconds
    time_t s; // Seconds
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    s = spec.tv_sec;
    ms = (spec.tv_nsec >> 19);
    sprintf(out_str, ".%lu.%04li", s, ms);
}

static bool
copy_user_option(const char *opts_str, char *output, unsigned len)
{
    char *c = output;
    const char *n = opts_str;
    while (*n != '\0' && *n != ',' &&
           (c < output + len)) {
        *c = *n;
        ++n;
        ++c;
    }
    *c = 0;
    return *n == 0 || *n == ',';
}

static bool
parse_options(char *output_path, char *user_tag, bool *log_pid)
{
    const char *opts_str_st = getenv(BCOV_OPTS_NAME);
    const char *str_p;
    if (opts_str_st == NULL) {
        *output_path = '\0';
        *user_tag = '\0';
        *log_pid = false;
        return true;
    }
    *log_pid = strstr(opts_str_st, BCOV_OPTS_PID_NAME) != NULL;

    str_p = strstr(opts_str_st, BCOV_OPTS_DIR_NAME);
    if (str_p == NULL) {
        *output_path = '\0';
    } else {
        str_p += sizeof(BCOV_OPTS_DIR_NAME);
        if (!copy_user_option(str_p, output_path, MAX_MOD_PATH_SIZE)) {
            return false;
        }
    }

    str_p = strstr(opts_str_st, BCOV_OPTS_USER_TAG_NAME);
    if (str_p == NULL) {
        *user_tag = '\0';
    } else {
        str_p += sizeof(BCOV_OPTS_USER_TAG_NAME);
        if (!copy_user_option(str_p, user_tag, BCOV_OPTS_USER_TAG_SIZE)) {
            return false;
        }
    }
    return true;
}

static bool
make_file_path_suffix(const char *module_path, const char *user_tag, char *path)
{
    const char *basename = get_basename(module_path);
    size_t basename_len = strnlen(basename, MAX_MOD_NAME_SIZE);
    if (basename_len == 0) {
        DEBUG_PRINT("module name too long: %s\n", module_path);
        return false;
    }

    char *c = path;
    while (*c != '\0') ++c;
    if (path != c) {
        *(c++) = BCOV_DIR_SEP;
    }
    strcpy(c, basename + 1);
    c += basename_len - 1;
    make_current_time_tag(c);
    c += BCOV_OPTS_TIME_TAG_SIZE;
    if (*user_tag) {
        *(c++) = '.';
        strncpy(c, user_tag, BCOV_OPTS_USER_TAG_SIZE);
        c += strnlen(user_tag, BCOV_OPTS_USER_TAG_SIZE);
    }
    strcpy(c, BCOV_FILE_SUFFIX);
    return true;
}

static void
dump_bcov_data_segments()
{
    static FILE *maps_file;
    static FILE *dump_file;
    static size_t line_len = 0;
    static size_t mod_start, mod_end, offset;
    static size_t data_size = 0;
    static size_t base_address = 0;
    static char line[MAX_MOD_PATH_SIZE];
    static char permissions[5];
    static char device[8];
    static char parsed_module_path[MAX_MOD_PATH_SIZE];
    static char output_path[MAX_MOD_PATH_SIZE];
    static char user_tag[BCOV_OPTS_USER_TAG_SIZE];
    static int inode;
    static bool log_pid;

    maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL) {
        fprintf(stderr, "failed to open process maps!\n");
        return;
    }

    char *line_c = &line[0];

    if (parse_options(output_path, user_tag, &log_pid) != true) {
        DEBUG_PRINT("unknown %s in parsing options \n", "error");
        return;
    }

    while ((getline(&(line_c), &line_len, maps_file)) != -1) {
        parse_line(line_c, &mod_start, &mod_end, permissions, &offset, device,
                   &inode, parsed_module_path);

        if (offset == 0 && inode != 0) {
            base_address = mod_start;
        }

        if (!is_data_segment(permissions) || !begins_with_bcov_magic(mod_start)) {
            continue;
        }

        if (!make_file_path_suffix(parsed_module_path, user_tag, output_path)) {
            continue;
        }

        uint8_t *hdr_buf = (uint8_t *) mod_start;
        bcov_write_base_address(hdr_buf, base_address);
        if (log_pid) {
            bcov_write_process_id(hdr_buf);
        }
        data_size = bcov_read_probe_count(hdr_buf);
        if (data_size > (mod_end - mod_start) || data_size == 0) {
            DEBUG_PRINT("%s: invalid size expected <= %lx, found %lx! \n",
                        output_path, mod_end - mod_start, data_size);
            continue;
        }
        data_size += BCOV_DATA_HDR_SIZE;
        dump_file = fopen(output_path, "wb");
        if (dump_file == NULL) {
            DEBUG_PRINT("%s: failed to open dump file!\n", output_path);
            return;
        }
        if (fwrite((const char *) hdr_buf, 1, data_size, dump_file) != data_size) {
            DEBUG_PRINT("%s: %lx-%lx, file write error! \n",
                        output_path, mod_start, mod_end);
        } else {
            DEBUG_PRINT("%s: %lx-%lx, %lu page(s) written successfully. \n",
                        output_path, mod_start, mod_end,
                        (data_size / MEM_PAGE_SIZE));
        }
        fclose(dump_file);
    }

    fclose(maps_file);
}

static void
user_signal_handler(int signum, siginfo_t *info, void *ptr)
{
    UNUSED(info);
    UNUSED(ptr);
    DEBUG_PRINT("received bcov dump request %d. ", signum);
    dump_bcov_data_segments();
    if (signum == SIGINT) {
        signal(SIGINT, SIG_DFL);
    }
}

void
bcov_init(void)
{
    static struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = user_signal_handler;
    act.sa_flags = SA_SIGINFO;
#ifdef ONLINE_COVERAGE
    sigaction(SIGUSR1, &act, NULL);
#endif
}

void
bcov_fini(void)
{
    dump_bcov_data_segments();
}
