#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 700

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

#define _DEFAULT_SOURCE_
#define BUFLEN 512
#define DEBUG true

// Colors definition
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define BLUE "\x1b[34m"
#define GRAY "\x1b[90m"
#define NC "\x1b[0m"

#define YES_NO(i) ((i) ? "Y" : "N")

void exeSimpleCommand(struct line li, struct sigaction* sigaction_action);
void printCommandLine(struct line li);
int detectInternCommand(struct cmd cmd);
int exitFish(struct cmd command);
void handle_redirections(char *input_file, char *output_file, int const append_mode);
// void sigint_handler(int const signum);
struct sigaction sigint_handler();
void sigint_default(struct sigaction sigint_default);

void sigchld_handler(int const signum);

// TODO : Make a header file for functions declarations and structures
pid_t foreground_pid = -1; // Used to store the pid of the foreground process

int main() {

    char buf[BUFLEN];

    struct line li;
    line_init(&li);

    struct sigaction sigaction_action = sigint_handler();

    for (;;) {
        // We handle the signal for SIGCHLD
        struct sigaction sa; // Declaration of signaction struct to handle the SIGACTION Signal
        sa.sa_handler = sigchld_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        if(sigaction(SIGCHLD, &sa, 0) == -1) {
            perror("sigaction");
            exit(EXIT_FAILURE);
        }
        /*
        sa.sa_handler = sigint_handler;
        // C
        // lear the sa_mask to avoid blocking any signals while handling SIGINT
        sigemptyset(&sa.sa_mask);
        // Set flags to 0
        sa.sa_flags = 0;

        if (sigaction(SIGINT, &sa, NULL) == -1) {
            perror("Sigaction");
            exit(EXIT_FAILURE);
        }

        */
        char pwd[1024];
        getcwd(pwd, 1024);
        fprintf(stdout, "%s%s%s\n", GRAY, pwd, NC);
        fprintf(stdout, "%sFish> %s", BLUE, NC);
        fgets(buf, BUFLEN, stdin);

        int err = line_parse(&li, buf);
        if (err) {
            // The command line entered by the user isn't valid
            line_reset(&li);
            continue;
        }
        printCommandLine(li);


        // case where li is a simple command with or without arguments, but no pipes '|'
        if (li.n_cmds == 1 && li.cmds[0].n_args == 1) {
            if (DEBUG) printf("%sSimple command!%s\n", GREEN, NC);
            exeSimpleCommand(li, &sigaction_action);
        }
        else if (li.n_cmds == 1 && li.cmds[0].n_args > 1) {
            // Case where li is a simple command with arguments
            if (DEBUG) printf("%sSimple command WITH arguments!%s\n", GREEN, NC);
            exeSimpleCommand(li, &sigaction_action);
        }

        /* No entry redirection, output redirection TRUC MODE
        char *args[] = {"ls", NULL};
        handle_redirections(NULL, "output.txt", 0);
        execvp(args[0], args);
        */

        /* Entry redirection from input.txt, redirection APPEND mode
        char *args[] = {"cat", NULL};
        handle_redirections("input.txt", "output.txt", 1);
        execvp(args[0], args);
        */

        /* Redirection entry from input.txt, no output redirection
        char *args[] = {"grep", "pattern", NULL};
        handle_redirections("input.txt", NULL, 0);
        execvp(args[0], args);
        */

        line_reset(&li);
    }
    return 0;
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
    if (command.n_args == 1) exit(0);

    // Check the validity of the parameters given
    if (command.n_args != 2) {
        fprintf(stderr, "%sexit: Invalid number of arguments%s\n", RED, NC);
    }
    // We check if the second parameter given is not an int
    exitStatus = strtol(command.args[1], &endptr, 10);
    if (endptr == command.args[1] || *endptr != '\0') {
        fprintf(stderr, "%sexit: Invalid argument \"%s\", must be a number%s\n", RED, command.args[1], NC);
    }
    // We exit with the code given by the user
    printf("\n\n\nABOUT TO EXIT\n\n\n\n");
    exit((int)exitStatus);
}

int cd(struct cmd command) {
    char *finalPath = NULL;
    char *first_arg = NULL;
    char first_char;

    // Check if there is no arguments we go to home dir
    if (command.n_args == 1) {
        printf("\n\n\n\nHOME=%s\n\n\n\n", getenv("HOME"));
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
                printf("// Only '~' was given");
                finalPath = getenv("HOME");
            } else {
                finalPath = malloc(strlen(getenv("HOME")) + strlen(first_arg) + 1); // +1 for null char
                if (finalPath == NULL) {
                    perror("Memory allocation error");
                    return -1;
                }
                strcpy(finalPath, getenv("HOME"));
                strcat(finalPath, &first_arg[1]);

                printf("\nFINALPATH=%s\n", finalPath);
            }
        } else {
            // If we are here then we have the correct number of args,
            // and finalPath has been set so we try to chdir
            finalPath = command.args[1];
        }
    }

    if (chdir(finalPath) == -1) {
        // If there is a problem with chdir
        if (DEBUG) printf("\n\n\nCATASTROPHEEEE\n\n\n");
        if (first_char == '~' && first_arg[1] != '\0') {
            // it means we have malloc'ed' finalPath so we must free it
            free(finalPath);
        }
        perror("chdir");
        return -1;
    }

    if (DEBUG) printf("CD INTO %s\n", finalPath);
    if (first_char == '~' && first_arg[1] != '\0') {
        // it means we have malloc'ed' finalPath so we must free it
        free(finalPath);
    }
    return 0;
}
/*
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

/**
 * Executes simple commands with and without arguments
 * \param li (struct line) the line to execute
 * */
void exeSimpleCommand(struct line const li, struct sigaction* sigaction_action) {
    // We check if the command is an intern command
    int const internCommand = detectInternCommand(li.cmds[0]);
    if (internCommand == 0) {
        if (DEBUG) printf("CD\n");
        cd(li.cmds[0]);
        return;
    } else if (internCommand == 1) {
        printf("%sexiting fish...%s\n", RED, NC);
        exitFish(li.cmds[0]);
    } else if (DEBUG) printf("NO CD NO EXIT\n");
    if (DEBUG) printf("\n\n\n%sFILE INPUT = '%s', FILE OUTPUT = '%s'%s\n\n\n", RED, li.file_input, li.file_output, NC);

    // We detect if the command has a redirection of input
    int inRedir, outRedir, append, trunc = 0;
    if (li.file_input != NULL) {
        if (DEBUG) printf("TREATING INPUT\n");
        inRedir = 1;
        if (DEBUG) printf("REDIRECTION INPUT\n\n");
    } else {
        if (DEBUG) printf("NO INPUT REDIRECTION\n\n");
    }

    // We detect if the command has a redirection of output
    if (li.file_output != NULL) {
        if (DEBUG) printf("TREATING OUTPUT\n");
        outRedir = 1;
        // We treat the append or trunc
        if (li.file_output_append) {
            if (DEBUG) printf("APPEND\n\n");
            append = 1;
        } else {
            if (DEBUG) printf("TRUNC\n\n");
            trunc = 1;
        }
        if (DEBUG) printf("REDIRECTION OUTPUT\n\n");
    } else {
        if (DEBUG) printf("NO OUTPUT REDIRECTION\n\n");
    }

    // We set the input and output to standard I/O
    char *input_file = NULL;
    char *output_file = NULL;
    // We redirect the I/O if needed
    if (inRedir == 1) {
        input_file = li.file_output;
    }
    if (outRedir == 1) {
        output_file = li.file_output;
    }

    // If we come across a 'background' command, if the input is not redirected
    // We set the input to /dev/null
    if (li.background == true && inRedir == 0) {
        if(DEBUG) printf("Background command with no input redirection, input = /dev/null\n");
        input_file = "/dev/null";
    }

    int saved_stdout = dup(STDOUT_FILENO); // saving the current stdout
    // We handle the redirections
    if (trunc == 1) {
        if (DEBUG) printf("%sTRUNC MODE ACTIVATED !%s\n\n\n", GRAY, NC);
        handle_redirections(input_file, output_file, 0); // trunc mode
    } else if (append == 1) {
        if (DEBUG) printf("%sAPPEND MODE ACTIVATED !%s\n\n\n", GRAY, NC);
        handle_redirections(input_file, output_file, 1); // append mode
    }
    else {
        if (DEBUG) printf("%sNO TRUC NOR APPEND MODE !%s\n\n\n", GRAY, NC);
    }

    // If the command is not a background command, we execute the sigaction function
    if(!li.background) {
        printf("The value of sigaction_action is : %p\n", sigaction_action);
        printf("The flag of sigaction_action is : %d\n", sigaction_action->sa_flags);
        // We have set the value of sigaction_action to ignore the SIGINT signal
        // But we are in a foreground process so we must set it to the default value
        // This way it will kill foreground processes when we send a SIGINT signal
        // But the background processes won't be affected

        // sigint_default(sigaction_action);

        /*
        if(sigaction(SIGINT, sigaction_action, NULL) == -1) {
            // We control the return value of sigaction
            perror("sigaction");
            exit(EXIT_FAILURE);
        }
        */

        struct sigaction sigint_default;
        sigemptyset(&sigint_default.sa_mask);
        sigint_default.sa_flags = SA_RESTART;
        sigint_default.sa_handler = SIG_DFL; // We set the handler to the default value

        if(sigaction(SIGINT, &sigint_default, NULL) == -1) {
            // We control the return value of sigaction
            perror("sigaction");
            exit(EXIT_FAILURE);
        }
    }

    // Creation of a child processus
    pid_t const pid = fork();
    // TODO : Handle the case where the process runs in the background ->
    // If a process runs in the background, we must not wait for it to finish
    // We loop the for(;;) loop and display the prompt again
    // The way the background process finishes will be displayed
    // Once the current foreground process finishes or when it finishes if no
    // foreground process is running
    if (pid < 0) {
        perror("Error while creating child process");
    } else if (pid == 0) {
        // This is the child process
        if (execvp(li.cmds[0].args[0], li.cmds[0].args) == -1) {

            if (errno == ENOENT) {
                // The command was not found
                fprintf(stderr, "%sCommand not found%s\n", RED, NC);
            } else {
                // The command was found but there was an error while executing it
                perror("Error while executing command\n");
                exit(-1);
            }
        }
    } else {
        // Parent process :
        int status;
        if(li.background) {
            // We don't wait for the child process to finish
            printf("BG : The command %s is running in the background\n", li.cmds[0].args[0]);
            return;
        }
        // Parent process, we must wait for the child process to finish
        waitpid(pid, &status, 0);

        dup2(saved_stdout, STDOUT_FILENO); // Restore standard output to last state
        close(saved_stdout);

        // We check the exit status of the process child
        if (WIFEXITED(status)) {
            const int exit_status = WEXITSTATUS(status);
            if (exit_status == 127) {
                if (DEBUG) printf("%sUnknown command !%s\n", RED, NC);
            } else if (exit_status != 0) {
                if (DEBUG) fprintf(stderr, "%sCould not run command !%s\n", RED, NC);
            } else {
                if (DEBUG) printf("%sSuccess !%s\n", GREEN, NC);

                // We determine if the process was running in the BG of FG for the display
                char *state;
                if (li.background == true) {
                    state = "BG";
                } else {
                    state = "FG";
                }
                fprintf(stderr, "%s%s : %d exited, status = %d%s\n", BLUE, state, pid, status, NC);
            }
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Child process stopped by signal :%d\n", WTERMSIG(status));
        }
    }
}

/*
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

// TODO : On est pas obligé de renvoyer SIGINT a tous les process enfants,
// Car quand on envoie CTRL+C dans fish, fish et tous ces enfants reçoivent le même signal SIGINT
// Signal handler function

// TODO : Create documentation
struct sigaction sigint_handler() {
    struct sigaction sigaction_action;
    // We set sigaction_action to send the Ignore signal
    sigemptyset(&sigaction_action.sa_mask); // We empty the mask
    sigaction_action.sa_flags = SA_RESTART; // We set the flags to SA_RESTART
    // The SA_RESTART flag is used to restart the system call interrupted by the signal
    sigaction_action.sa_handler = SIG_IGN; // We set the handler to SIG_IGN
    // The SIG_IGN flag is used to ignore the signal (IGN = Ignore)

    // the sigaction function is used to change the action taken by a process on receipt of a specific signal
    // Here We set tge action of the SIGINT signal
    if(sigaction(SIGINT, &sigaction_action, NULL) == -1) {
        // We control the return value of sigaction
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    return sigaction_action;
}

// This functions returns a sigaction struct with the default values
void sigint_default(struct sigaction sigint_default) {
    sigemptyset(&sigint_default.sa_mask);
    sigint_default.sa_flags = SA_RESTART;
    sigint_default.sa_handler = SIG_DFL; // We set the handler to the default value
    sigint_default.sa_restorer = NULL; // We set the restorer to NULL
}
/**
 * Handles the SIGCHLD signal sent by child processes when they terminate.
 * This function is a signal handler for the SIGCHLD signal. When a child process
 * terminates, it sends a SIGCHLD signal to the parent process. This function catches that signal,
 * and properly handles the termination of the child process, including collecting its exit status.
 *
 * @param signum The signal number. Should always be SIGCHLD in this context.
 */
void sigchld_handler(int const signum) {
    if(DEBUG) printf("%sSIGCHLD signal received%s\n", RED, NC);
    int status;
    pid_t pid;
    printf("%d : %sCaught SIGCHLD signal code : %d%s\n", getpid(), GREEN, signum, NC);

    // We collect the zombie processes
    while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            int const exit_status = WEXITSTATUS(status);
            printf("Background process %d exited with status %d\n", pid, exit_status);
            if (exit_status == 127) {
                if (DEBUG)
                    printf("%sUnknown command !%s\n", RED, NC);
            } else if (exit_status != 0) {
                if (DEBUG)
                    fprintf(stderr, "%sCould not run command !%s\n", RED, NC);
            } else {
                if (DEBUG)
                    printf("%sSuccess !%s\n", GREEN, NC);
            }
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Process %d stopped by signal :%d\n", pid, WTERMSIG(status));
        }
    }
}