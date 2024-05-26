#ifndef HEADER_H
#define HEADER_H

#include "cmdline.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Constants
#define BUFLEN 512
#define DEBUG false

// Colors definition
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define BLUE "\x1b[34m"
#define GRAY "\x1b[90m"
#define NC "\x1b[0m"

#define YES_NO(i) ((i) ? "Y" : "N")

// Structures
struct bg_status_node {
    pid_t pid;
    int status;
    bool finished;
    char *command;
    struct bg_status_node *next;
};

struct bg_status_queue {
    struct bg_status_node *head;
    struct bg_status_node *tail;
};

// Function declarations
void exeCommand(struct line li);
void printCommandLine(struct line li);
int detectInternCommand(struct cmd cmd);
int exitFish(struct cmd command);
void handle_redirections(char *input_file, char *output_file, int const append_mode);
void sigint_handler();
void sigchld_handler(int const signum);
void print_finished_bg_processes();
int exeInternCommand(struct line const li);
void sigint_ignore();
void sigint_default();
int cd(struct cmd command);
void print_queue();

#endif // HEADER_H
