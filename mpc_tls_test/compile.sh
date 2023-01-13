# sudo apt install libssl-dev

OPENSSL_PATH=/home/ubuntu/test_openssl/install_openssl/
OTLS_PATH=/home/ubuntu/test_openssl/otls/
export LD_LIBRARY_PATH=${OPENSSL_PATH}/lib/:/usr/local/lib/
export LIBRARY_PATH=${OPENSSL_PATH}/lib/
export CPLUS_INCLUDE_PATH=${OPENSSL_PATH}/include/
OPENSSL_PATH=${OPENSSL_PATH}/lib/
MPC_TLS_PATH=${OTLS_PATH}/build/mpc_tls/

echo ${LD_LIBRARY_PATH}
ll ${MPC_TLS_PATH}
g++ -ggdb3 server.cpp  -lotls -lssl -lcrypto -o server
g++ -L${OPENSSL_PATH} -ggdb3 client.cpp   -lotls -lssl -lcrypto -o client
g++ -ggdb3 pado.cpp  -lotls -lssl -lotls -o pado


#g++ -ggdb3 client.cpp   -lmpc_tls -lssl -lcrypto -o client && echo "AAAAAAAAAAaa"
#g++ -ggdb3 client.cpp   -lmpc_tls -lcrypto -lssl -o client && echo "BBBBBBBBBBBB"
#g++ -ggdb3 client.cpp   -lssl -lmpc_tls -lcrypto -o client && echo "CCCCCCCCCCCC"
#g++ -ggdb3 client.cpp   -lssl -lcrypto -lmpc_tls -o client && echo "DDDDDDDDDDDD"
#g++ -ggdb3 client.cpp   -lcrypto -lmpc_tls -lssl -o client && echo "EEEEEEEEEEEE"
#g++ -ggdb3 client.cpp   -lcrypto -lssl -lmpc_tls -o client && echo "FFFFFFFFFFFF"
