/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 2, scan_threat.c
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
	// 	- These take over for scan specific calls on top of the overarching
	//	- rules put in place by main. Primarily, these restrict the fork/exec 
	//	- sequence and narrows down on the other calls.
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

        // Add seccomp rule to allow prctl call for secondary seccomp filter
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0) < 0)
                goto out;

	// Load the filter
	if (seccomp_load(filter) < 0)
		goto out;

	/////////////////////////////////////////////////////////////////////////
	//	Initialize Variables and Bind to the Address and Port
	/////////////////////////////////////////////////////////////////////////

	// Create the UDP socket and configure the UDP connection
	int udpSocket = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_storage serverStorage;
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(7893);
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
	scmp_filter_ctx filter_scan;
	filter_scan = seccomp_init(SCMP_ACT_TRAP);
	if (filter_scan == NULL)
		goto out_scan;

	// Add seccomp rule to allow the read call
        if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
                goto out_scan;
    
	// Add seccomp rule to allow sendto call
	if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto out_scan;

	// Add seccomp rule to allow recvfrom call
        if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) < 0)
                goto out_scan;

	// Add seccomp rule to allow exit_group call
        if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
                goto out_scan;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDONLY, O_RDONLY)) < 0)
                goto out_scan;

	// Add seccomp rule to allow close call
        if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
                goto out_scan;

        // Add seccomp rule to allow fstat call
        if (seccomp_rule_add(filter_scan, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
                goto out_scan;

	// Load the filter
	if (seccomp_load(filter_scan) < 0)
		goto out_scan;


	/////////////////////////////////////////////////////////////////////////
	//	Start The Main Service Function 
	//	- Listen, Scan, Respond
	/////////////////////////////////////////////////////////////////////////

	while(1) {

		// Prepare incoming buffers
		char buffer[1024];
		memset(buffer, '\0', 1024);
		int incomming;

		int incoming = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);

		// Check for errors on the request
		if (incoming == -1) {
			
			// Send error response
			printf("Error: did not recieve a valid message.\n");
			continue;
		}

		// Open the database file
		FILE *fp;
		if ((fp = fopen("database_file.txt", "r")) == NULL) {

			// Send error response
			printf("Error: Could not open file.\n");
			continue;
		}

		// Iterate over each line of the file
		char threat[10];
		int found = 0;
		while (fgets(threat, sizeof threat, fp)) {

			// Remove the new line at the end of each string
			threat[4] = '\0';

			// Check to see if the passed through file contains the threat
			if (strstr(buffer, threat) != NULL) {
			
				// If a threat is found, record it and stop searching the for more threats
				found = 1;
				break;
			}
		}

		// File has been scanned, close file
		fclose(fp);

		// Return the outcome of the file to the user
		if (found == 1) {
			sprintf(buffer, "infected");
			sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
		}
		else {
			sprintf(buffer, "clean");
			sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
		}
	}
	

out_scan:
	seccomp_release(filter_scan);

out:
        seccomp_release(filter);
	return 0;
}
