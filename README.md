# Fish

**Fish** is a simple Unix shell implemented in C as a student project. It supports basic command execution, piping, redirection, and background processes.

## Features

- Execute commands with arguments  
- Piped commands (e.g., `ls -l | grep txt`)  
- Input/output redirection using `<` and `>`  
- Background execution with `&`  
- Basic command-line parsing

## Project Structure

- `fish.c` / `fish.h`: Main shell implementation  
- `cmdline.c` / `cmdline.h`: Command-line parsing utilities  
- `cmdline_test.c`: Test cases for command-line parsing  
- `Makefile`: Build automation  
- `projet-fish.pdf`: Project documentation (in French)

## Installation

### Prerequisites

- GCC compiler  
- Make utility
