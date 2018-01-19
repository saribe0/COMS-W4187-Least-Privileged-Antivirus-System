/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 2, main.c
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


int main(int argc, char *argv[]) 
{
	/////////////////////////////////////////////////////////////////////////
	//	Prepare Seccomp Filter For Least Priviledging
	//	- This one is very libral to enable the exec/fork sequence
	/////////////////////////////////////////////////////////////////////////

	// Prepare filter context
	scmp_filter_ctx filter;
	filter = seccomp_init(SCMP_ACT_TRAP);
	if (filter == NULL)
		goto out;

	// Add seccomp rule to allow the write call
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
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

	// Add seccomp rule to allow nanosleep call
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0) < 0)
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

	// Add seccomp rule to allow connect call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT)) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY)) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_CLOEXEC, O_CLOEXEC)) < 0)
                goto out;

	// Add seccomp rule to allow lseek call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1, SCMP_A2(SCMP_CMP_EQ, SEEK_END)) < 0)
                goto out;

	// Add seccomp rule to allow close call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
                goto out;

	// Add seccomp rule to allow fstat call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
                goto out;

	// Add seccomp rule to allow execve call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0) < 0)
                goto out;

        // Add seccomp rule to allow clone call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0) < 0)
                goto out;

	// Add seccomp rule to allow brk call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) < 0)
                goto out;

        // Add seccomp rule to allow access call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(access), 0) < 0)
                goto out;

        // Add seccomp rule to allow mmap call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)
                goto out;

        // Add seccomp rule to allow mprotect call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0) < 0)
                goto out;

        // Add seccomp rule to allow arch_prctl call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0) < 0)
                goto out;

        // Add seccomp rule to allow munmap call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)
                goto out;

        // Add seccomp rule to allow prctl call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0) < 0)
                goto out;

	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0) < 0)
		goto out;

	// Load the filter
	if (seccomp_load(filter) < 0)
		goto out;

	/////////////////////////////////////////////////////////////////////////
	//	Start any services that aren't running
	/////////////////////////////////////////////////////////////////////////

	if (argc < 2) {
		printf("No files to be scanned.\n");
		exit(1);
	}

	// Create the UDP socket and configure the connection address
	int clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(7891);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	socklen_t addr_size = sizeof serverAddr;

	char*const* argv_execs = {NULL};

	// Check if the threat update service is running, if not, start the threat update service
	pid_t pid_update;
	if (bind(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0)
	{
		close(clientSocket);
		pid_update = fork();
		if (pid_update == 0)
		{
			execvp("./database_update", argv_execs);
			printf("ERROR: Failed to start database update service.\n");
			exit(1);
		}
		printf("Update service started with PID: %d\n", pid_update);
	}
	else
	{
		printf("Update service is already running.\n");
	}

	// Reset the socket variables
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
        serverAddr.sin_port = htons(7892);
        memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	// Check if the read file service is running, if not, exit
	// - Read service must be started by hand so it can access files owned by root
	if (bind(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0)
	{
		close(clientSocket);
		printf("Please start read service then start main again. Exiting.\n");
		goto out;
	}
	else
	{
		printf("Read service is already running.\n");
	}

	// Reset the socket variables
	pid_t pid_scan;
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr.sin_port = htons(7893);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	// Check if the scan threat service is running, if not, start the scan service
	if (bind(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0)
	{
		close(clientSocket);
		pid_scan = fork();
		if (pid_scan == 0)
		{
			execvp("./scan_threat", argv_execs);
			printf("ERROR: Failed to start scan threat service.\n");
			exit(1);
		}
		printf("Scan service started with PID: %d\n", pid_scan);
	}
	else
	{
		printf("Scan service is already running.\n");
	}

	// Sleep for one second to allow all services to be ready
	usleep(500000);

	// Reset the socket and prepare buffer
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr.sin_port = htons(7891);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	char buffer[1024];
	memset(buffer, '\0', 1024);
	strcpy(buffer, "update");
	int len;

	/////////////////////////////////////////////////////////////////////////
	//	Prepare Second Seccomp Filter For Main Function Only Least Priviledging
	// 	- Blocks off many of the calls allowed above that are needed for forking
	//	- and execing. This filter is added right before starting service 
	//	- communication for security.
	/////////////////////////////////////////////////////////////////////////

	// Prepare filter context
	scmp_filter_ctx filter_main_only;
	filter_main_only = seccomp_init(SCMP_ACT_TRAP);
	if (filter_main_only == NULL)
		goto out_main;

	// Add seccomp rule to allow the write call only to stdout
	// - Since dup is not allowed, this is fairly good at restricting write's access
	if (seccomp_rule_add(filter_main_only, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1)) < 0)
		goto out_main;

	// Add seccomp rule to allow the sendto call needed for service commmunication
	if (seccomp_rule_add(filter_main_only, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto out_main;

	// Add seccomp rule to allow the recvfrom call needed for service commmunication
	if (seccomp_rule_add(filter_main_only, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) < 0)
		goto out_main;

	// Add seccomp rule to allow the exitgroup for smooth exiting
	if (seccomp_rule_add(filter_main_only, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
		goto out_main;

	// Load the filter
	if (seccomp_load(filter_main_only) < 0)
		goto out_main;

	/////////////////////////////////////////////////////////////////////////
	//	Iterate through and scan files for infections
	/////////////////////////////////////////////////////////////////////////

	// Send the update request
	sendto(clientSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverAddr, addr_size);

	// Recieve response
	memset(buffer, '\0', 1024);
	len = recvfrom(clientSocket, buffer, 1024, 0, NULL, NULL);

	if (0 != strcmp("success", buffer)) 
	{
		printf("%s.\n", buffer);
	}

	printf("Testing input files for infections...\n");

	// Iterate over each of the files to be scanned
	for (int ii = 1; ii < argc; ii++) 
	{

		// Try to send the file name to the file_read function
		serverAddr.sin_port = htons(7892);
		memset(buffer, '\0', 1024);
		strcpy(buffer, argv[ii]);

		// Send the get file request
		sendto(clientSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverAddr, addr_size);
		
		// Recieve the file contents and print them
		memset(buffer, '\0', 1024);
		len = recvfrom(clientSocket, buffer, 1024, 0, NULL, NULL);

		// Prepare the scan request
		serverAddr.sin_port = htons(7893);

		// Send the contents of the file to be scanned
		sendto(clientSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverAddr, addr_size);

		// Recieve the decision of the scanner
		memset(buffer, '\0', 1024);
		len = recvfrom(clientSocket, buffer, 1024, 0, NULL, NULL);

		// Print the output of the scan
		printf("%s - %s\n", argv[ii], buffer);
	}

out_main:
	seccomp_release(filter_main_only);

out:
	seccomp_release(filter);
	return 0;
}
