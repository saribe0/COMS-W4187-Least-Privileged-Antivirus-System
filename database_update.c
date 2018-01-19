/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 2, database_update.c
// Exmples from the following link used for reference:
// http://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html
//
//////////////////////////////////////////////

#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>


int main(int argc, char *argv[]) 
{
	/////////////////////////////////////////////////////////////////////////
	//	Prepare Seccomp Filter For Least Priviledging
	// 	- These take over for database update specific on top of the overarching
	//	- rules put in place by main. Primarily, these restrict the fork/exec 
	//	- sequence and narrows down on the other calls.
	/////////////////////////////////////////////////////////////////////////

	// Prepare filter context
	scmp_filter_ctx filter;
	filter = seccomp_init(SCMP_ACT_TRAP);
	if (filter == NULL)
		goto out;

	// Add seccomp rule to allow the write call
	if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
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

	// Add seccomp rule to allow connect call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
                goto out;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT)) < 0)
                goto out;

	// Add seccomp rule to allow lseek call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1, SCMP_A2(SCMP_CMP_EQ, SEEK_END)) < 0)
                goto out;

	// Add seccomp rule to allow close call
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
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
	serverAddr.sin_port = htons(7891);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	socklen_t addr_size = sizeof serverStorage;

	// Bind the process to the socket
	bind(udpSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

	/////////////////////////////////////////////////////////////////////////
	//	Apply Secondary Seccomp Filter For Least Priviledging of Repeating
	// 	- part of the function. Essentially takes away bind in this case.
	/////////////////////////////////////////////////////////////////////////

	// Prepare filter context
	scmp_filter_ctx filter_update;
	filter_update = seccomp_init(SCMP_ACT_TRAP);
	if (filter_update == NULL)
		goto out_update;

	// Add seccomp rule to allow the write call
	if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
		goto out_update;

	// Add seccomp rule to allow the socket call
	if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0) < 0)
		goto out_update;
    
	// Add seccomp rule to allow sendto call
	if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto out_update;

	// Add seccomp rule to allow recvfrom call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) < 0)
                goto out_update;

	// Add seccomp rule to allow exit_group call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
                goto out_update;

	// Add seccomp rule to allow connect call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
                goto out_update;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
                goto out_update;

	// Add seccomp rule to allow open call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT)) < 0)
                goto out_update;

	// Add seccomp rule to allow lseek call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1, SCMP_A2(SCMP_CMP_EQ, SEEK_END)) < 0)
                goto out_update;

	// Add seccomp rule to allow close call
        if (seccomp_rule_add(filter_update, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
                goto out_update;

	// Load the filter
	if (seccomp_load(filter_update) < 0)
		goto out_update;

	/////////////////////////////////////////////////////////////////////////
	//	Start The Main Service Function 
	//	- Listen, Update, Respond
	/////////////////////////////////////////////////////////////////////////

	while(1) 
	{
		// Prepare incoming buffers
		char buffer[1024];
		memset(buffer, '\0', 1024);
		int incomming;

		int incoming = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);

		// If an update has been requested
		if (0 == strcmp(buffer, "update"))
		{
			// First prepare hints for the type of IP interface we're looking for
			struct addrinfo hints;
			memset(&hints, 0, sizeof hints);
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			
			// Get the available hosts based on the hints given and address and port
			struct addrinfo *servinfo, *p;
			int rv;
			if((rv = getaddrinfo("127.0.0.1", "3490", &hints, &servinfo)) != 0) 
			{
				fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));

				// Send error response
				memset(buffer, '\0', 1024);
				strcpy(buffer, "error: could not find any connections");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}

			// Iterate through the results and connect to one
			// - On each interface, tries to connect to get the socket and connect to it
			int sockfd;
			for(p = servinfo; p != NULL; p = p->ai_next) {
				if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
					continue;
				}

				if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
					close(sockfd);
					continue;
				}

				break;	// Only called if a socket was successfully connected to
			}

			// If the end of the loop has been found and there was no interface, send error to the requesting server
			if (p == NULL) {
				fprintf(stderr, "client: failed to connect\n");
				
				// Send error response
				strcpy(buffer, "error: no connections available");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}

			// Since a connection has been found and connected to, we no longer need the list of available connections
			// - The connection can be referenced by the socked file descriptor
			freeaddrinfo(servinfo);

			// Send a request to the server through the socket
			char *request = "get_update";
			if(send(sockfd, request, strlen(request), 0) == -1) {

				// Send error response
				strcpy(buffer, "error: unable to send request over socket");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}

			// Recieve the server's response
			int resbytes;
			char server_buf[5];
			if ((resbytes = recv(sockfd, server_buf, 5, 0)) == -1) {

				// Send error response
				strcpy(buffer, "error: error recieving data from server");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}
			server_buf[4] = '\n';

			// Open the file (create if not there) and append the thread string
			int fd;
			if ((fd = open("database_file.txt", O_WRONLY | O_CREAT, S_IRWXU)) == -1 ) {

				// Send error response
				strcpy(buffer, "error: db file could not be opened");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}

			// Go to the end of the file
			if (lseek(fd, 0, SEEK_END) == -1) {
				
				// Send error response
				close(fd);
				strcpy(buffer, "error: could not seek to end of the file");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}

			// Write the new threat to the file
			if (write(fd, server_buf, 5) == -1) {

				// Send error response
				strcpy(buffer, "error: db file could not be written to");
				sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
				continue;
			}

			// Close the file and return success to the caller
			close(fd);

			// Send success response
			memset(buffer, '\0', 1024);
			strcpy(buffer, "success");
			sendto(udpSocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *)&serverStorage, addr_size);
		}
	}
	
out_update:
	seccomp_release(filter_update);

out:
        seccomp_release(filter);
	return 0;
}
