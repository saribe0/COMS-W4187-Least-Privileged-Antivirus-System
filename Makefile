all: main database_update file_read scan_threat
	
main: main.c
	gcc -o main main.c -lseccomp

database_update: database_update.c
	gcc -o database_update database_update.c -lseccomp

file_read: file_read.c
	gcc -o file_read file_read.c -lseccomp

scan_threat: scan_threat.c
	gcc -o scan_threat scan_threat.c -lseccomp

and_config: all config

and_run: all config run_all

run_main:
	./main test_files/test.txt1 test_files/test.txt2 test_files/test.txt3 test_files/test.txt4 test_files/test.txt5 test_files/test.txt6 test_files/test.txt7 test_files/test.txt8 test_files/test.txt9 test_files/test.txt10

run_services:
	./file_read &
	./scan_threat &
	./database_update &

run_all:
	./../Server/server &
	./file_read &
	./main test_files/test.txt1 test_files/test.txt2 test_files/test.txt3 test_files/test.txt4 test_files/test.txt5 test_files/test.txt6 test_files/test.txt7 test_files/test.txt8 test_files/test.txt9 test_files/test.txt10

config:
	sudo chown root file_read
	sudo chmod u+s file_read

clean:
	rm main database_update file_read scan_threat
