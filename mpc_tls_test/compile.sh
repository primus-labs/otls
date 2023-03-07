# sudo apt install libssl-dev

OPENSSL_PATH=/home/ubuntu/test_openssl/install_openssl/
OTLS_PATH=/home/ubuntu/test_openssl/otls/
export LD_LIBRARY_PATH=${OPENSSL_PATH}/lib/:/usr/local/lib/
export LIBRARY_PATH=${OPENSSL_PATH}/lib/
export CPLUS_INCLUDE_PATH=${OPENSSL_PATH}/include/
OPENSSL_PATH=${OPENSSL_PATH}/lib/
MPC_TLS_PATH=${OTLS_PATH}/build/mpc_tls/

echo ${LD_LIBRARY_PATH}
echo "compile server"
g++ -ggdb3 server.cpp  -lotls -lssl -lcrypto -pthread -ldl -o server -I../
echo "compile client"
g++  -ggdb3 client.cpp   -lemp-tool -lotls -lssl -lcrypto -pthread -ldl -o client -I../
echo "compile pado"
g++ -ggdb3 pado.cpp  -lemp-tool -lotls -lssl -lcrypto -pthread -ldl -o pado -I../


