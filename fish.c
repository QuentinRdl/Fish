#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>

#include "cmdline.h"

#define _DEFAULT_SOURCE_
#define BUFLEN 512
#define DEBUG false 

// Colors definition
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define BLUE    "\x1b[34m"
#define GRAY    "\x1b[90m"
#define NC   "\x1b[0m"

#define YES_NO(i) ((i) ? "Y" : "N")

void exeSimpleCommand(struct line li);
void printCommandLine(struct line li);
int detectInternCommand(struct cmd cmd);
int exitFish(struct cmd command);
void handle_redirections(char *input_file, char *output_file, int append_mode);

int main() {
  struct line li;
  char buf[BUFLEN];

  line_init(&li);

  for (;;) {
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

    /* do something with li */

    // case where li is a simple command with or without arguments, but no pipes '|'
    if(li.n_cmds == 1 && li.cmds[0].n_args == 1) {
      if(DEBUG)printf("%sSimple command!%s\n", GREEN, NC);
      exeSimpleCommand(li);
    } else if(li.n_cmds == 1 && li.cmds[0].n_args > 1) {
      // Case where li is a simple command with arguments
      if(DEBUG) printf("%sSimple command WITH arguments!%s\n", GREEN, NC);
      exeSimpleCommand(li);
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

/*
 * Detects if the command entered by the user is an intern command
 * \param struct line li
 *
 * \param int result | 0 for 'cd', 1 for 'exit' and -1 for the rest 
 */
int detectInternCommand(struct cmd cmd) {
  char* command = cmd.args[0];
  int len = strlen(command);
  if(DEBUG) printf("LEN == %d\n", len);
  if(len != 2 && len != 4) return -1; // because len("cd") == 2 and len("exit") == 4
  else if (strcmp("cd", command) == 0) return 0;
  else if (strcmp("exit", command) == 0) return 1;
  return -1;
}

/*
 * Exits fish
 * \param struct cmd command
 * \return int -1 if execution failed, nothing if the exit works
 */
int exitFish(struct cmd command) {
  if(DEBUG) printf("EXIT FISHHHH\n\n\n\n");
  long exitStatus = 0;
  char *endptr;

  // No parameters given, we exit with the code 0
  if(command.n_args == 1) exit(0);

  // Check the validity of the parameters given
  if(command.n_args != 2) {
    fprintf(stderr, "%sexit: Invalid number of arguments%s\n", RED, NC);
  }
  // We check if the second parameter given is not an int
  exitStatus = strtol(command.args[1], &endptr, 10);
  if(endptr == command.args[1] || *endptr != '\0') {
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
  if(command.n_args == 1) {
    printf("\n\n\n\nHOME=%s\n\n\n\n", getenv("HOME"));
    finalPath = getenv("HOME");
  } else if(command.n_args != 2) { // Check if there is too many args
    fprintf(stderr, "%sErrror !%s Too many arguments for %s'cd'%s command\n", RED, NC, GREEN, NC);
    return -1;
  } else {
    // Check for the ~ shortcut
    first_arg = command.args[1];
    first_char = first_arg[0];

    if(first_char == '~') {
      // We check if only '~' was given
      if(first_arg[1] == '\0') {
        // Only '~' was given
        printf("// Only '~' was given");
        finalPath = getenv("HOME");
      } else {
        /*
        finalPath = getenv("HOME");
        strcat(finalPath, "/");
        strcat(finalPath, &first_arg[1]);
        */

        finalPath = malloc(strlen(getenv("HOME")) + strlen(first_arg) + 1); // +1 for null char 
        if (finalPath == NULL) {
          perror("Memory allocation error");
          return -1;
        }
        strcpy(finalPath, getenv("HOME"));
        strcat(finalPath, &first_arg[1]);

        printf("\n\n\n\nFINALPATH=%s\n\n\n\n", finalPath);
      }

    } else {
      // If we are here then we have the correct number of args,
      // and finalPath has been set so we try to chdir
      finalPath = command.args[1];
    }
  }

  if(chdir(finalPath) == -1) {
    // If there is a problem with chdir
    if(DEBUG) printf("\n\n\nCATASTROPHEEEE\n\n\n");
    if (first_char == '~' && first_arg[1] != '\0') {
      // it means we have malloc'ed' finalPath so we must free it
      free(finalPath);
    }
    perror("chdir");
    return -1;
  }

  if(DEBUG) printf("CD INTO %s\n\n\n", finalPath);
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
  if(!DEBUG) return;
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

/*
 * Executes simple commands with and without arguments
 * \param struct line li the line to execute
* */
void exeSimpleCommand(struct line li) {
  // We check if the command is an intern command
  int internCommand = detectInternCommand(li.cmds[0]);
  if(internCommand == 0) {
    if(DEBUG) printf("CD\n");
    cd(li.cmds[0]);
    return;
  } else if(internCommand == 1) {
    printf("%sexiting fish...%s\n", RED, NC);
    exitFish(li.cmds[0]);
  } else if(DEBUG)printf("NO CD NO EXIT\n");

  if(DEBUG) printf("\n\n\n%sFILE INPUT = '%s', FILE OUTPUT = '%s'%s\n\n\n", RED, li.file_input, li.file_output, NC);

  // We detect if the command has a redirection of input
  int inRedir, outRedir, append, trunc = 0;
  if(li.file_input != NULL) {
    if(DEBUG) printf("TREATING INPUT\n");
    inRedir = 1;
    if(DEBUG) printf("REDIRECTION INPUT\n\n");
  } else {
    if(DEBUG) printf("NO INPUT REDIRECTION\n\n");
  }

  // We detect if the command has a redirection of output
  if(li.file_output != NULL) {
    if(DEBUG) printf("TREATING OUTPUT\n");
    outRedir = 1;
    // We treat the append or trunc 
    if(li.file_output_append) {
      if(DEBUG) printf("APPEND\n\n");
      append = 1;
    } else {
      if(DEBUG) printf("TRUNC\n\n");
      trunc = 1;
    }
    if(DEBUG) printf("REDIRECTION OUTPUT\n\n");
  } else {
    if(DEBUG) printf("NO OUTPUT REDIRECTION\n\n");
  }

  // We set the input and output to standard I/O
  char* input_file = NULL;
  char* output_file = NULL;
  // We redirect the I/O if needed
  if(inRedir == 1) {
    input_file = li.file_output;
  }
  if(outRedir == 1) {
    output_file = li.file_output;
  }

  int saved_stdout = dup(STDOUT_FILENO); // saving the current stdout
  // We handle the redirections
  if(trunc == 1) {
    if(DEBUG) printf("%sTRUNC MODE ACTIVATED !%s\n\n\n", GRAY, NC);
    handle_redirections(input_file, output_file, 0); // trunc mode
  } else if(append == 1){
    if(DEBUG) printf("%sAPPEND MODE ACTIVATED !%s\n\n\n", GRAY, NC);
    handle_redirections(input_file, output_file, 1); // append mode
  } else {
    if(DEBUG) printf("%sNO TRUC NOR APPEND MODE !%s\n\n\n", GRAY, NC);
  }

  // Creation of a child processus
  pid_t pid = fork();

  if(pid < 0) {
    perror("Error while creating child process");
  } else if(pid == 0) {
    // This is the child process
    execvp(li.cmds[0].args[0], li.cmds[0].args);
    // If the program gets here, it means execvp returned something
    // which means there was an error while executing the command
    perror("Error while executing command\n");
    exit(-1);
  } else {
    // Parent process, we must wait for the child process to finish
    int status;
    waitpid(pid, &status, 0);

    dup2(saved_stdout, STDOUT_FILENO); // Restore standard output to last state
    close(saved_stdout);

    // We check the exit status of the process child 
    if(WIFEXITED(status)) {
      int exit_status = WEXITSTATUS(status);
      if(exit_status == 127) {
        if(DEBUG) printf("%sUnknown command !%s\n", RED, NC);
      } else if(exit_status != 0) {
        if(DEBUG) fprintf(stderr, "%sCould not run command !%s\n", RED, NC);
      } else {
        if(DEBUG) printf("%sSuccess !%s\n", GREEN, NC);

        // We determine if the process was running in the BG of FG for the display
        char* state;
        if(li.background == true) {
          state = "BG";
        } else {
          state = "FG";
        }
        fprintf(stderr, "%s%s : %d exited, status = %d%s\n",BLUE, state, pid, status, NC);
      }
    } else if(WIFSIGNALED(status)) {
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
void handle_redirections(char *input_file, char *output_file, int append_mode) {
  // We handle the case where we have an input file
  if(input_file) {
    printf("TREATING INPUT FILE which is : '%s'\n", input_file);
    int input_fd = open(input_file, O_RDONLY);
    if(input_fd == -1) {
      perror("Error while opening input file");
      exit(EXIT_FAILURE);
    }

    dup2(input_fd, STDIN_FILENO);
    close(input_fd);
  }

  // We handle the case where we have an output file
  if(output_file) {
    printf("TREATING OUTPUT FILE which is : '%s'\n", output_file);
    int flags = O_WRONLY | O_CREAT;
    // We check the value of append_mode to toggle it or not
    if(append_mode) {
      // We toggle
      flags |= O_APPEND;
    } else {
      flags |= O_TRUNC;
    }

    int output_fd = open(output_file, flags, 0644);
    if(output_fd == -1) {
      perror("Error opening output file");
      exit(EXIT_FAILURE);
    }
    // close(STDOUT_FILENO);
    dup2(output_fd, STDOUT_FILENO);
    close(output_fd);
  }
}

/*
int detect_append_mode(struct cmd commad) {
  
}
*/

