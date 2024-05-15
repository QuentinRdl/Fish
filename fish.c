#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "cmdline.h"

#define BUFLEN 512
#define DEBUG true 

// Colors definition
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define BLUE    "\x1b[34m"
#define NC   "\x1b[0m"


#define YES_NO(i) ((i) ? "Y" : "N")

void exeSimpleCommand(struct line li);

int main() {
  struct line li;
  char buf[BUFLEN];

  line_init(&li);

  for (;;) {
    printf("%sfish> %s\n", BLUE, NC);
    fgets(buf, BUFLEN, stdin);

    int err = line_parse(&li, buf);
    if (err) { 
      //the command line entered by the user isn't valid
      line_reset(&li);
      continue;
    }

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

    /* do something with li */

    /* case where li is a simple command with no arguments, no '|' and no redirection */
    if(li.n_cmds == 1 && li.cmds[0].n_args == 1) {
      if(DEBUG )printf("%sCommande simple !%s\n", GREEN, NC);
      exeSimpleCommand(li);
    } else if(li.n_cmds == 1 && li.cmds[0].n_args > 1) {
      // Case where li is a simple command with arguments
      if(DEBUG) printf("%sCommande simple AVEC arguments!%s\n", GREEN, NC);
      exeSimpleCommand(li);
    }
  

    line_reset(&li);
  }

  return 0;
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
    char *args[] = {li.cmds[0].args[0], NULL}; // No arguments
    if(li.cmds[0].n_args > 1) {
      // With arguments
      // char *args[] = {li.cmds[0].args, NULL}; // Incompatible pointer types error
      char *args[li.cmds[0].n_args + 2]; // + 2 for name of command and NULL and the end of the structure
      args[0] = li.cmds[0].args[0]; // Name of the comnmand

      // Copy the args
      for(size_t i = 0; i < li.cmds[0].n_args; i++) {
        args[i+1] = li.cmds[0].args[i];
      }
      args[li.cmds[0].n_args + 1] = NULL;
      
      execvp(li.cmds[0].args[0], args);
    } else {
      execvp(li.cmds[0].args[0], args);
    }
    
    // If the program gets here, it means execvp returned something
    // which means there was an error while executing the command
    perror("Error while executing command\n");
  } else {
    // Parent process, we must wait for the child process to finish
    int status;
    waitpid(pid, &status, 0);

    // We check the exit status of the process child 
    if(WIFEXITED(status)) {
      int exit_status = WEXITSTATUS(status);
      if(exit_status == 127) {
        printf("%sUnknown command !%s\n", RED, NC);
      } else if(exit_status != 0) {
        printf("%s Could not run command !%s\n", RED, NC);
      } else {
        printf("%sRéussite !%s\n", GREEN, NC);
      }
    }
  }
}
