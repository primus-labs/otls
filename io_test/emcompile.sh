#! /bin/sh
em++ -s WASM=1 test_emp.cpp -o test_emp.html -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD

