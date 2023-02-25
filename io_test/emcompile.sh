#! /bin/sh
echo "compile test emp"
em++ -s WASM=1 test_emp.cpp -o test_emp.html -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD
echo "compile echo server"
g++ echo_server.cpp -o echo_server
echo "compile ech client"
g++ test_emp.cpp -o echo_client

