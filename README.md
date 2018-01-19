# coms_w4187_hw2
COMS W4187 Security Architecture and Engineering HW2: Simple threat detection with sandboxing

## Objective:
The objective of this homework was to create three services that would update a threat database from a server, read in a file, and scan the file for threats. It is assumed that each of these services runs internally on specified ports while the server could run outside the local machine. For simplicity for this implementation, it is assumed that the server runs locally on a known port. A main function that takes in files to be checked for "viruses" as command line arguments was also necessary to interface with each of these services. This main function first calls the update service to update the threat database. Then it iterates through the passed in files and passes their names to the file read service. The file read service returns the contents of the files which are then sent to the scanning service to be checked for threats. The scan service returns either "infected" or "clean" depending on whether it sees a virus in the file. For simplicity, viruses are 4 character strings that the server randomly generates.

Each one of these services and the main function have to be sandboxed using the libseccomp library (thus making the processes linux specific). The goal was to allow each of the services and the main program the least privileges necessary to perform their required functions. Essentially this ended up meaning whitelisting certain system calls and, as the program runs, adding more filters to restrict the calls more and more.

### Caveats To The Initial Objective
- If a service is not running, the main program should fork and start it. This follows the standard fork->execve process for generating new processes. If a service is not running, it should not create a new instance. This was accomplished through attempting to bind to the port and address of the process. If the bind is successfull, the process is not running, the socket is closed, and the process fork->execs to start it. If the bind fails, the process continues as normal.
- The file read service must be able to read all files. This means it has to have root permissions however should not use them unless it has to. One fallout of this is that the file read service can not be started by the main program via fork->exec. This is because the main program (along with all the other ones) are assumed to be run as a local user and not root for security. Only the file read service is root. For it to maintain its privileges, the main program is unable to start it and can only check to see if it is running and inform the user. This has to do with how fork->exec affects the real, effective, and saved uids.
- All communications with services were to be done through UDP or datagram (Unix Domain) sockets. In my implementation I used UDP. Communications with the threat signiture server were to use TCP/IP.

## Least Privileging Approach
There are two main least privileging approaches used in my implementation. The first is through the use of libseccomp and the second through the use of linux uid privileges.
#### Libseccomp
The libseccomp sandboxing approach that I used enforces two filters per process. The system calls to restrict and allow were determined by using strace.

In the case of the update database, read file, and scan file services, the first filter is at the start of the service while the second is right before it starts listening for connections. In this way, all the settup system calls that aren't used during the actual processing of data are blocked off. The second filter being right before the service starts listening which is ideal because those calls will happen repeatedly while the setup-only ones *should* only happen once.

For the main program the filters are a bit different. Like with the services, the first one is at the beginning of the program while the second is right before the main loop. Both the first and second have a minor difference though. The first filter is much more liberal than it needs to be for the main function alone. This is because it has to enable allow every call in the update database and read file services as well as the calls required by the OS to start those processes up. This means there are quite a few allowed system calls at this stage. The second filter in the main function is after the initial setup and service checks but right before the first service is called. This call is a few lines before the first loop but is above enough so that the by the time the first service is requested, the security restrictions are in place. I did this instead of putting it right above the iterating-through-files loop so that if any of the services were comprimised, the damage they could do was cut down as much as possible.

#### Linux uid privileges
Since access is to be restricted as much as possible, the majority of the service binaries and the main program must be run and owned by the local user. This causes a bit of dilemma for the read file service which must be able to read all files, even those owned by root. To get around this issue, read file service is own by root and started seperately from the main program and other services. This allows it to read every file while the other services cannot.

Another issue along these lines though is that just because the read file service *can* read every file as root, it doesn't mean that it *should*. It should only read files it can't access as the local user as root. To do this, the read file service must be owned by root but started by the local user. Then once it starts up, it reduces its effective privileges (real and effective uid) to that of the local user. When it encounters a file it cannot read, it escalates privileges using its saved uid, reads in the file, and reduces privileges back to those of the user. By doing this, it uses the root privileges for as little as possible.

Being able to change its effective uid means it must have the set uid bit set by using the command `chmod u+s ./file_read`

## How to Run and Outcome
In my implementation I include a source code for the server, main program and each of the three services, makefiles for the everything, a database_file.txt which contains threat signitures that have accumulated throughout testing, and a host of test files with automated testing through the clients makefile.  It is important to notes that everything must be compiled and run on a linux machine with the seccomp library installed.

#### Preparing the server
To start up the server, first enter the Server directory and run `make`. This will make the server executable. If you would like to run it immediately, it can be done using `./server &`. This will run the server in the background so it is ready to be connected to. All server code for this assignment was provided by the instructors and did not need to be modified.

#### Preparing the services and main program and running them
With the server compiled, navigate back to the root directory then to the Client one. The Makefile for the client offers a multitude of options. To compile and run with arbitrary input files, one would run the following (assuming the threat signiture server is already running:
```
make and_config
./file_read &
./main file1.txt file2.txt ...
```
The first step compiles all the services and the main program and sets the owner of file_read to root and sets the setuid bit for the file_read service. If you would not like to do this together or would like to configure manually, you simply run `make` then the `chown` and `chmod` commands as one normally would. The next line starts the file read service up in the background and the third line starts the main program and passes through the files to be scanned as command line arguments.

###### make
Standard make command. Compiles each of the services and the main program into their respective binaries.

###### make and_config
This make command is explained above. It simply compiles all the services and runs chown and chmod on the file_read service binary so it can read all files and change its effective uid.

###### make and_run
This make command does the same as `make and_config`  except it also starts the server (assuming its still located `./../Server/server` in relation to the Makefile) and file read service in the background and then runs the main program with 10 files as inputs from the test_files/ directory. There should be a mix of ones own by root and by the local user. 3, 8, and 10 should be clean if the threat_database.txt file and the test files are untouched. This does not check if the file_read service or server are running so either kill previous instances or choose another command if they are.

###### make run_main
This make command runs the main program with all the test files from the test_files/ directory as inputs. 3, 8, and 10 should be clean if the threat_database.txt file and the test files are untouched.

###### make run_services
This make command runs each of the service programs in the background. It does not check if they are allready running so either kill previous instances or choose another command if they are.

###### make run_all
This make command starts the server and file read service in the background and then runs the main program with the 10 test files included in test_files/. 3, 8, and 10 should be clean if the threat_database.txt file and the test files are untouched. This does not check if the file_read service or server are running so either kill previous instances or choose another command if they are.

###### make config
This just runs the chown and chmod commands to set the file_read service binary to be owned by root and have the setuid bit set.

###### make clean
This make command removes the binaries for the main program and the three services. May have to run as root or answer prompt to delete the file_read service binary because it is owned by root.

#### Outcomes
Overall, everything is working quite well so far. An output of everything running can be found in the root directory along with this readme. It shows a few things.

First, the program is run on the 10 input files in the test_files/ directory. The text output has been edited a bit since it was run but it should look roughly the same. As it shows, files 3, 8 and 10 should be clean while the rest are infected. This is verified in the program's output. It also shows that the main program recognizes that both the update and read service are already running and starts the scan service which is not. It connects to the server and then scans the files.

Second, it shows the test files directory to verify the ownership and permission of each of the files. The fact that it was able to find threats in some of these files owned by root is an indication that the privilege escalation is working.

Third, it shows the ownership of the service binaries- notable the file_read binary which is owned by root and has the setuid bit enabled.

![screenshot](https://github.com/saribe0/coms_w4187_hw2/screenshot.pngf)

#### Pitfalls
One important thing to note is that the services and server rely on waiting for data to come in before processing and sending data and on being able to connect to their ports. What this means if that a service is accidentally started twice and the bound one is then killed it could cause that service to be unresponsive. What might happen is another service sees it and tries to send data or wait for data but it never gets to its intended recipient. The sysetm assumes that each service and server is never started more than once (or never in the case of scan file and update database) by the user. There is no timeout implemented for simplicity. Also mentioned in assumptions below.

## Assumptions
- Addresses and ports of all services and servers are known and can be hardcoded.
- The server is generally trusted and seccomp filters do not have to be applied to it.
- Only the services and servers we expect to run on an address/port combo will run on it. Therefor we can assume that if an address/port combo cannot be bound to, the service is already running.
- Users know to start the threat signiture server or verify that it is running before starting the main program.
- Similar to the threat signiture server, users known to start the file read service before starting the main program or they at least know how to start it if the main program indicates it must be started.
- Users know how to kill processes and check for them (ps and ps -ax) in order to clean up when they are done with the system.
- It is adequate for the threat database to be a simple text file with one threat signiture on each line.
- All files to be read and scanned (including for the threat database file) are small (<512b). This is for simplicity in programming for demo purposes.
- strace is adequate for determining system calls in use.
- libseccomp is adequate for blocking system calls.
- Only one instance of each service or the server is started at any given time. Though the main program checks before starting a service, users could manually start many at once and start killing ones that are not bound to sockets thus creating undetermined situations. It is assumed that users do not make this mistake.
