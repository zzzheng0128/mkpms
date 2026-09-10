#pragma once
#define MAX_OPTS 32

struct opts
{
    const char *args[MAX_OPTS];
    int size;
    char *_copy;
};

struct opts *getopt(const char *input);
void free_opts(struct opts *options);