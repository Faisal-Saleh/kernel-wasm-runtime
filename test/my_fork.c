#include <stdio.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        // Error occurred
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // Child process
        printf("This is the child process.\n");
    } else {
        // Parent process
        printf("This is the parent process. Child PID: %d\n", pid);
    }

    return 0;
}
