#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <unistd.h>


pid_t vpn_pid = -1;

// Start the client
void start_client() {
    vpn_pid = fork();

    if (vpn_pid == 0) {
        // Child process
        execlp("sudo", "sudo", "./client", NULL);
        perror("execlp failed");
        exit(1);
    }
    else if (vpn_pid > 0) {
        printf("[+] Client started with PID: %d\n", vpn_pid);
    }
    else {
        perror("fork failed");
    }
}

// Stop the client using SIGINT (like Ctrl+C)
void stop_client() {
    if (vpn_pid > 0) {
        printf("[+] Sending SIGINT to client...\n");
        kill(vpn_pid, SIGINT);   // same as Ctrl+C
    } else {
        printf("[-] No client running\n");
    }
}

int main() {
    for(int i=0;i<220;i++){
        start_client();
        sleep(1);
        stop_client();
    }


    return 0;
}
