/*  Quentin RADLO TP1A
    Fait : SIGINT géré
    Commandes simples ou non, avec des tubes et en BG marche
    en FG aussi.
    Commandes internes implémentées.
    J'ai veillé au cas ou l'user utilise :
    'cd ~repertoire' ce qui équivaut à un '~/repertoire'
    l'utilisateur ne peut pas utiliser exit s'il n'utilise pas
    les bons paramètres (trop d'arguments / pas un entier).

    Problèmes : des blocs encore reachable avec valgrind :
    '==14946==    still reachable: 5 bytes in 1 blocks'
    Quand on fait des sleep à la suite en background, les
    process zombies ne sont pas bien récupérés.
    Une fois les process en backgrounds finis leur état est
    directement affichés, j'ai commencé à implémenter une liste pour
    gèrer ce cas et attendre la fin des process en avant plan
    mais cela m'a prit beaucoup trop de temps, et je n'ai pas réussi donc
    il reste des fantomes de cette implémentation dans mon code, car mon SIGCHLD
    utilise encore cette structure de données.
    */
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 700

#include "fish.h"

volatile struct bg_status_queue bg_status = {NULL, NULL};
int main() {
    char buf[BUFLEN];

    struct line li;
    line_init(&li);

    // We handle the signal for SIGCHLD
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, 0) == -1) {
      perror("sigaction");
      exit(EXIT_FAILURE);
    }

    for (;;) {
        // We set the sigaction signal to be ignore
        sigint_ignore();

        char pwd[1024];
        getcwd(pwd, 1024);
        fprintf(stdout, "%s%s%s\n", GRAY, pwd, NC);
        fprintf(stdout, "%sFish> %s", BLUE, NC);
        fgets(buf, BUFLEN, stdin);

        int const err = line_parse(&li, buf);
        if (err) {
            // The command line entered by the user isn't valid
            line_reset(&li);
            continue;
        }

        printCommandLine(li);
        exeCommand(li); // We execute the command
        //print_finished_bg_processes(); // Print the finished background processes
        line_reset(&li);
    }
    return 0;
}

/**
 * Executes the command given in the struct line
 * Works with simple commands with and without arg, and commands with pipes
 * Add '&' at the end of the command to execute it in background
 * \param li (struct line) the line to execute
 * */
void exeCommand(struct line const li) {
    // We check if the user just pressed enter
    if (li.n_cmds == 0) {
        return;
    }
    int const num_pipes = li.n_cmds - 1;
    int pipefds[2 * num_pipes];
    pid_t pid;
    int status;

    // We look if there is only a command, because it can be an intern command
    if (li.n_cmds == 1) {
        if(exeInternCommand(li) == 0) {
            // We have executed an intern command, we return
            return;
        }
    }
    // Create pipes
    for (int i = 0; i < num_pipes; i++) {
        if (pipe(pipefds + i * 2) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }
    }
    for (size_t i = 0; i < li.n_cmds; i++) {
        if(DEBUG) printf("We are in the %lu command\n", i);
        pid = fork();
        if (pid == 0) {
            // Child process
            // Redirect input from previous command if not the first command
            if (i > 0) {
                if (dup2(pipefds[(i - 1) * 2], 0) == -1) {
                    perror("dup2 input");
                    exit(EXIT_FAILURE);
                }
            }

            // Redirect output to next command if not the last command
            if (i < li.n_cmds - 1) {
                if (dup2(pipefds[i * 2 + 1], 1) == -1) {
                    perror("dup2 output");
                    exit(EXIT_FAILURE);
                }
            }

            // Close all pipe fds in child process
            for (int j = 0; j < 2 * num_pipes; j++) {
                close(pipefds[j]);
            }

            // Handle redirections for the first and last commands
            if (i == 0 && li.file_input) {
                freopen(li.file_input, "r", stdin);
            }
            if (i == li.n_cmds - 1 && li.file_output) {
                if (li.file_output_append) {
                    freopen(li.file_output, "a", stdout);
                } else {
                    freopen(li.file_output, "w", stdout);
                }
            }

            // Execute command
            if (execvp(li.cmds[i].args[0], li.cmds[i].args) == -1) {
                perror("execvp");
                exit(EXIT_FAILURE);
            }
        } else if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        } else {
            if(DEBUG) printf("parent process pid %d\n", getpid());
        }

        // If this is a background cmd we add it to the queue
        if(li.background) {
            printf("Treating a bg command : pid = %d\n", pid);
            struct bg_status_node *node = malloc(sizeof(struct bg_status_node));
            node->pid = pid;
            node->status = 0;
            node->finished = false;
            node->command = strdup(li.cmds[i].args[0]);
            node->next = NULL;
            if(bg_status.tail) {
                bg_status.tail->next = node;
            } else {
                bg_status.head = node;
            }
        } else {
            if(DEBUG) printf("Treating foreground process of pid : %d\n", pid);
        }
    }

    // Parent process closes all pipe fds
    for (int i = 0; i < 2 * num_pipes; i++) {
        close(pipefds[i]);
    }

    // Wait for child processes to finish if not a background job
    if (!li.background) {
        for (size_t i = 0; i < li.n_cmds; i++) {
            wait(&status);
        }
        // We print the exit status of the process
        // foreground_pid = pid;
        fprintf(stderr, "%sFG : Process %d exited with status %d%s\n",BLUE, pid, status, NC);
        // print_finished_bg_processes();
    }

}

/* ----------------- Signal handlers ----------------- */

/**
 * Sets the SIGINT signal to be ignored when received
 */
void sigint_ignore() {
    struct sigaction sa;

    // We set the handler to ignore the signal
    sigemptyset(&sa.sa_mask); // We empty the mask
    sa.sa_handler = SIG_IGN; // We set the handler to SIG_IGN
    sa.sa_flags = 0; // We set the flags to 0

    if(sigaction(SIGINT, &sa, NULL) == -1) {
        // We control the return value of sigaction
        perror("sigaction");
    }
}

/**
 * We set the SIGINT signal to be handled by the default handler
 */
void sigint_default() {
    struct sigaction sa;

    // Clear the sigaction structure
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to reset SIGINT to default");
    }
}

/**
 * When sigchild is called, this function is executed
 * @param signum Should always be SIGCHLD
 */
void sigchld_handler(int signum) {
    if(DEBUG) printf("SIGCHLD HANDLER %d\n", signum);
    int status;
    pid_t pid;

    struct bg_status_node *current = bg_status.head;
    while(current) {
        pid = current->pid;
        if (pid != 1 && waitpid(pid, &status, WNOHANG) > 0) {
            if (WIFEXITED(status)) {
                fprintf(stderr,"BG: Command `%d` exited with status %d\n", pid, WEXITSTATUS(status));
            }
            else if (WIFSIGNALED(status)) {
                fprintf(stderr,"BG: Command `%d` killed by signal %d\n", pid, WTERMSIG(status));
            }
            current->pid = -1;
        }
        current = current->next;
    }
}
/* ---------------- End Signal handlers -------------- */

/* ----------------- Background Queue ---------------- */
/**
 * Prints the finished background processes
 */
void print_finished_bg_processes() {
    struct bg_status_node *current = bg_status.head;
    struct bg_status_node *prev = NULL;
    if(current == NULL) {
        if(DEBUG) printf("No background process in the queue\n");
    }
    while(current) {
        if(current->pid != 1 && current->finished) {
            if(DEBUG) fprintf(stderr, "%sBG : Process %d exited with status %d%s\n", BLUE, current->pid, current->status, NC);
            if(prev) {
                prev->next = current->next;
                free(current);
                current = prev->next;
            } else {
                bg_status.head = current->next;
                free(current);
                current = bg_status.head;
            }
        } else {
            prev = current;
            current = current->next;
        }
    }
}

/**
 * Prints the queue of background processes
 * Used for debug purposes
 */
void print_queue() {
    struct bg_status_node *current = bg_status.head;
    while(current) {
        printf("PID : %d\n", current->pid);
        current = current->next;
    }
}

/**
 * Frees the queue of background processes
 * Used when we exit the program
 */
void free_queue() {
    struct bg_status_node *current = bg_status.head;
    struct bg_status_node *next = NULL;
    while(current) {
        next = current->next;
        free(current->command);
        free(current);
        current = next;
    }
}

/* ----------------- End Background Queue ------------ */

/* ----------------- Intern commands ----------------- */

/**
 * Executes intern commands 'cd' and 'exit'
 * Or nothing if the command is not an intern command
 * \param li the line to execute
 * */
int exeInternCommand(struct line const li) {
    const int internCommand = detectInternCommand(li.cmds[0]);
    if (internCommand == 0) {
        // We have a 'cd' command
        if (DEBUG) printf("CD\n");
        cd(li.cmds[0]);
        return 0;
    } else if (internCommand == 1) {
        // We have a 'exit' command
        printf("%sexiting fish...%s\n", RED, NC);
        exitFish(li.cmds[0]);
        return 0;
    }
    return -1;
}

/**
 * Detects if the command entered by the user is an intern command
 * \param cmd the command to parse
 * \return 0 for 'cd', 1 for 'exit' and -1 for the rest
 */
int detectInternCommand(struct cmd cmd) {
    char *command = cmd.args[0];
    int const len = strlen(command);
    if (DEBUG) printf("LEN == %d\n", len);
    if (len != 2 && len != 4) return -1; // because len("cd") == 2 and len("exit") == 4
    else if (strcmp("cd", command) == 0) return 0; // cd command
    else if (strcmp("exit", command) == 0) return 1; // exit command
    return -1; // Not an intern command
}

/**
 * Exits fish
 * \param command the command to execute
 * \return -1 if execution failed, nothing if the exit works
 */
int exitFish(struct cmd command) {
    long exitStatus = 0;
    char *endptr;

    // No parameters given, we exit with the code 0
    if (command.n_args == 1) {
        free_queue(); // Free the queue that contains the bg process
        exit(0);
    }

    // Check the validity of the parameters given
    if (command.n_args != 2) {
        fprintf(stderr, "%sexit: Invalid number of arguments%s\n", RED, NC);
        return -1;
    }

    // We check if the second parameter given is not an int
    exitStatus = strtol(command.args[1], &endptr, 10);
    if (endptr == command.args[1] || *endptr != '\0') {
        fprintf(stderr, "%sexit: Invalid argument \"%s\", must be a number%s\n", RED, command.args[1], NC);
        return -1;
    }

    free_queue(); // Free the queue that contains the bg process
    // We exit with the code given by the user
    exit((int)exitStatus);
}


/**
 * Changes the current directory
 * \param command the command to execute
 * \return -1 if execution failed, 0 if the cd works
 */
int cd(struct cmd command) {
    char *finalPath = NULL;
    char *first_arg = NULL;
    char first_char;
    bool alloc = false;

    // Check if there is no arguments we go to home dir
    if (command.n_args == 1) {
        if(DEBUG)printf("HOME = %s\n", getenv("HOME"));
        finalPath = getenv("HOME");
    } else if (command.n_args != 2) { // Check if there is too many args
        fprintf(stderr, "%sErrror !%s Too many arguments for %s'cd'%s command\n", RED, NC, GREEN, NC);
        return -1;
    } else {
        // Check for the ~ shortcut
        first_arg = command.args[1];
        first_char = first_arg[0];

        if (first_char == '~') {
            // We check if only '~' was given
            if (first_arg[1] == '\0') {
                // Only '~' was given
                if(DEBUG) printf("// Only '~' was given");
                finalPath = getenv("HOME");
            } else {
                finalPath = malloc(strlen(getenv("HOME")) + strlen(first_arg) + 1); // +1 for null char
                alloc = true;
                if (finalPath == NULL) {
                    perror("Memory allocation error");
                    return -1;
                }
                strcpy(finalPath, getenv("HOME"));
                strcat(finalPath, "/");
                strcat(finalPath, &first_arg[1]);

                if(DEBUG) printf("\nFINALPATH=%s\n", finalPath);
            }
        } else {
            // If we are here then we have the correct number of args,
            // and finalPath has been set so we try to chdir
            finalPath = command.args[1];
        }
    }

    if (chdir(finalPath) == -1) {
        // If there is a problem with chdir
        if (first_char == '~' && first_arg[1] != '\0') {
            // it means we have malloc'ed' finalPath so we must free it
            free(finalPath);
        }
        perror("chdir");
        return -1;
    }

    if (DEBUG) printf("CD INTO %s\n", finalPath);
    if(alloc) free(finalPath);
    return 0;
}

/**
 * Prints the whole struct line
 * the #define DEBUG needs to be set to true
 * \param struct line li - Line to print
 * */
void printCommandLine(struct line li) {
    if (!DEBUG) return;
    fprintf(stderr, "Command line:\n");
    fprintf(stderr, "\tNumber of commands: %zu\n", li.n_cmds);

    for (size_t i = 0; i < li.n_cmds; ++i) {
        fprintf(stderr, "\t\tCommand #%zu:\n", i);
        fprintf(stderr, "\t\t\tNumber of args: %zu\n", li.cmds[i].n_args);
        fprintf(stderr, "\t\t\tArgs:");
        for (size_t j = 0; j < li.cmds[i].n_args; ++j) {
            fprintf(stderr, " \"%s\"", li.cmds[i].args[j]);
        }
        fprintf(stderr, "\n");
    }

    fprintf(stderr, "\tRedirection of input: %s\n", YES_NO(li.file_input));
    if (li.file_input) {
        fprintf(stderr, "\t\tFilename: '%s'\n", li.file_input);
    }

    fprintf(stderr, "\tRedirection of output: %s\n", YES_NO(li.file_output));
    if (li.file_output) {
        fprintf(stderr, "\t\tFilename: '%s'\n", li.file_output);
        fprintf(stderr, "\t\tMode: %s\n", li.file_output_append ? "APPEND" : "TRUNC");
    }

    fprintf(stderr, "\tBackground: %s\n", YES_NO(li.background));
}

/* ----------------- End Intern commands ------------- */

/* ---------------- Redirections (deprecated) -------- */

/**
 * Handles redirection of standard I/O
 * @param char* input_file the name of the input file
 * @param char* output_file the name of the file we will use as output
 * @param int append_mode
 *
 * @return void
 * */
void handle_redirections(char *input_file, char *output_file, int const append_mode) {
    // We handle the case where we have an input file
    if (input_file) {
        printf("TREATING INPUT FILE which is : '%s'\n", input_file);
        int const input_fd = open(input_file, O_RDONLY);
        if (input_fd == -1) {
            perror("Error while opening input file");
            exit(EXIT_FAILURE);
        }

        dup2(input_fd, STDIN_FILENO);
        close(input_fd);
    }

    // We handle the case where we have an output file
    if (output_file) {
        printf("TREATING OUTPUT FILE which is : '%s'\n", output_file);
        int flags = O_WRONLY | O_CREAT;
        // We check the value of append_mode to toggle it or not
        if (append_mode) {
            // We toggle
            flags |= O_APPEND;
        } else {
            flags |= O_TRUNC;
        }

        int const output_fd = open(output_file, flags, 0644);
        if (output_fd == -1) {
            perror("Error opening output file");
            exit(EXIT_FAILURE);
        }
        // close(STDOUT_FILENO);
        dup2(output_fd, STDOUT_FILENO);
        close(output_fd);
    }
}
/* ---------------- End Redirections ----------------- */