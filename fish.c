#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "cmdline.h"

#define _DEFAULT_SOURCE_
#define BUFLEN 512
#define DEBUG true 

// Colors definition
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define BLUE    "\x1b[34m"
#define NC   "\x1b[0m"

#define YES_NO(i) ((i) ? "Y" : "N")

void exeSimpleCommand(struct line li);
void printCommandLine(struct line li);
void exitFish(int exitStatus);

int main() {
  struct line li;
  char buf[BUFLEN];

  line_init(&li);

  for (;;) {
    printf("%sFish> %s", BLUE, NC);
    fgets(buf, BUFLEN, stdin);

    int err = line_parse(&li, buf);
    if (err) { 
      // The command line entered by the user isn't valid
      line_reset(&li);
      continue;
    }
    printCommandLine(li);

    /* do something with li */

    /* case where li is a simple command with no arguments, no '|' and no redirection */
    if(li.n_cmds == 1 && li.cmds[0].n_args == 1) {
      if(DEBUG)printf("%sSimple command!%s\n", GREEN, NC);
      exeSimpleCommand(li);
    } else if(li.n_cmds == 1 && li.cmds[0].n_args > 1) {
      // Case where li is a simple command with arguments
      if(DEBUG) printf("%sSimple command WITH arguments!%s\n", GREEN, NC);
      exeSimpleCommand(li);
    }

    line_reset(&li);
  }
  return 0;
}

/*
 * Detects if the command entered by the user is an intern command
 * \param struct line li
 */
bool detectInternCommand(struct line li) {
  if(li.n_cmds == 0) return true;
  return false;
}

void exitFish(int exitStatus) {
  exit(exitStatus);
}
/*
 * Prints the whole struct line
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

    // We check the exit status of the process child 
    if(WIFEXITED(status)) {
      int exit_status = WEXITSTATUS(status);
      if(exit_status == 127) {
        if(DEBUG) printf("%sUnknown command !%s\n", RED, NC);
      } else if(exit_status != 0) {
        if(DEBUG)fprintf(stderr, "%sCould not run command !%s\n", RED, NC);
        exit(-1);
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
    } else if(WIFSIGNALED(status)){
      fprintf(stderr, "Child process stopped by signal :%d\n", WTERMSIG(status));
    }
  }
}
