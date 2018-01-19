/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 2, file_read.c
// Exmples from the following link used for reference:
// http://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html
//
//////////////////////////////////////////////
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

// Handler to catch any system calls and indicate they were caught
int main(int argc, char *argv[]) 
{
	/////////////////////////////////////////////////////////////////////////
	//	Prepare Seccomp Filter For Least Priviledging
	/////////////////////////////////////////////////////////////////////////

	// Prepare filter context
	scmp_filter_ctx filter;
	filter = seccomp_init(SCMP_ACT_TRAP);
	if (filter == NULL)
		goto out;

	// Add seccomp rule to allow the read call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
                goto out;

	// Add seccomp rule to allow the socket call
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0) < 0)
		goto out;

	// Add seccomp rule to allow the bind call with the localhost address
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0) < 0) // 1, SCMP_A2(SCMP_CMP_MASKED_EQ, serverAddr2, serverAddr2)) < 0)
		goto out;
    
	// Add seccomp rule to allow sendto call
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto out;

	// Add seccomp rule to allow recvfrom call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) < 0)
                goto out;

	// Add seccomp rule to allow exit_group call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY)) < 0)
                goto out;

	// Add seccomp rule to allow close call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
                goto out;

	// Add seccomp rule to allow fstat call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
                goto out;

        // Add seccomp rule to allow getuid call
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) < 0)
		goto out;

	// Add seccomp rule to allow setreuid call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(setreuid), 0) < 0)
                goto out;

	// Add seccomp rule to allow setresuid call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(setresuid), 0) < 0)
                goto out;

        // Add seccomp rule to allow prctl call for secondary seccomp filter
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0) < 0)
                goto out;

	// Load the filter
	if (seccomp_load(filter) < 0)
		goto out;

	/////////////////////////////////////////////////////////////////////////
	//	Initialize Variables and Bind to the Address and Port
	/////////////////////////////////////////////////////////////////////////

	// Switch to the calling processes uid to be used as a default
	// - Use seteuid because saved uid persists 
	seteuid(getuid());

	// Create the UDP socket and configure the UDP connection
	int udpSocket = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_storage serverStorage;
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(7892);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	socklen_t addr_size = sizeof serverStorage;

	// Bind the process to the socket
	bind(udpSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));


	/////////////////////////////////////////////////////////////////////////
	//	Apply Secondary Seccomp Filter For Least Priviledging of Repeating
	// 	- part of the function. Essentially takes away bind and socket.
	/////////////////////////////////////////////////////////////////////////

	// Prepare filter context
	scmp_filter_ctx filter_read;
	filter_read = seccomp_init(SCMP_ACT_TRAP);
	if (filter_read == NULL)
		goto out_read;

	// Add seccomp rule to allow the read call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
                goto out_read;

	// Add seccomp rule to allow sendto call
	if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto out_read;

	// Add seccomp rule to allow recvfrom call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) < 0)
                goto out_read;

	// Add seccomp rule to allow exit_group call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
                goto out_read;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY)) < 0)
                goto out_read;

	// Add seccomp rule to allow close call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
                goto out_read;

	// Add seccomp rule to allow fstat call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
                goto out_read;

                // Add seccomp rule to allow getuid call
	if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) < 0)
		goto out_read;

	// Add seccomp rule to allow setreuid call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(setreuid), 0) < 0)
                goto out_read;

	// Add seccomp rule to allow setresuid call
        if (seccomp_rule_add(filter_read, SCMP_ACT_ALLOW, SCMP_SYS(setresuid), 0) < 0)
                goto out_read;

	// Load the filter
	if (seccomp_load(filter_read) < 0)
		goto out_read;


	/////////////////////////////////////////////////////////////////////////
	//	Start The Main Service Function 
	//	- Listen, Read, Respond
	/////////////////////////////////////////////////////////////////////////

	while(1) {

		// Prepare incoming buffers
		char buffer[1024];
		memset(buffer, '\0', 1024);
		int incomming;

		// printf("** Waiting for connection.\n");
		int incoming = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);

		// printf("** Recieved request for: %s\n", filename);

		// Check for errors on the request
		if (incoming == -1) {
			
			// Send error response
			printf("Error recieving message.\n");
			continue;
		}

		// Try to open the file with the current permissions
		int fd;
		if ((fd = open(buffer, O_RDONLY)) == -1) {

			// If the current user does not have access, escalate privileges and try again
			if (errno == EACCES) {

				// Setreuid so the real id stays as the calling user
				// - Authorized using the saved uid
				setreuid(getuid(), 0);
				fd = open(buffer, O_RDONLY);
			}

			// If the error was other then permissions or root was also unable to open, return error
			if (fd == -1) {

				// print error response
				printf("Error opening the file - not permissions.");
				continue;
			}
		}

		// Now that the file has been opened at the proper permissions, read and send the file

		// Get the length of the file
		struct stat fs;
		if (fstat(fd, &fs) == -1) {

			// pirnt error
			printf("Error: could not get the file length.\n");
			continue;
		}

		// Read the file
		memset(buffer, '\0', 1024);
		if (read(fd, buffer, fs.st_size) == -1) {

			// print error
			printf("Error: could not read file.\n");
			continue;
		}

		// Send the file
		if (sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size) ==  -1) {

			// print error
			printf("Error: could not send file.\n");
			continue;
		}

		// File has been sent, close file and reset permissions
		close(fd);
		seteuid(getuid());
	}

out_read:
	seccomp_release(filter_read);

out:
        seccomp_release(filter);
	return 0;
}
