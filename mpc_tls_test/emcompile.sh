# sudo apt install libssl-dev

OPENSSL_PATH=/home/ubuntu/test_openssl/install_emopenssl/
OTLS_PATH=/home/ubuntu/test_openssl/otls/build_wasm
EMP_PATH=/home/ubuntu/test_openssl/pado-emp/build_wasm
export LD_LIBRARY_PATH=${OPENSSL_PATH}/lib/:/usr/local/lib/
export LIBRARY_PATH=${OPENSSL_PATH}/lib/
export CPLUS_INCLUDE_PATH=${OPENSSL_PATH}/include/
# OPENSSL_PATH=${OPENSSL_PATH}/lib/
# MPC_TLS_PATH=${OTLS_PATH}/build/mpc_tls/

CIRCUIT_FILE1="--preload-file ./cipher/circuit_files/aes128_ks.txt"
CIRCUIT_FILE2="--preload-file ./cipher/circuit_files/aes128_with_ks.txt"
CIRCUIT_FILE3="--preload-file ./ca.crt"
CIRCUIT_FILE4="--preload-file ./server.crt"
CIRCUIT_FILE5="--preload-file ./server.key"
CIRCUIT_FILE6="--preload-file ./bristol_fashion/aes_128.txt"
echo ${LD_LIBRARY_PATH}
em++ -s WASM=1 -ggdb3 server.cpp  os.cpp -L${OPENSSL_PATH}/lib -lssl -lcrypto -ldl -o server.html -I../ -I/usr/local/include ${CIRCUIT_FILE4} ${CIRCUIT_FILE5}
em++ -s WASM=1 -ggdb3 client.cpp  os.cpp -L${OPENSSL_PATH}/lib -L${OTLS_PATH}/mpc_tls -L${EMP_PATH}/lib -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sFORCE_FILESYSTEM -sMAIN_MODULE -lotls -lemp-tool -lssl -lcrypto -ldl -lrt -pthread -o client.html -I../ -I/usr/local/include ${CIRCUIT_FILE1} ${CIRCUIT_FILE2} ${CIRCUIT_FILE3} ${CIRCUIT_FILE6}
em++ -s WASM=1 -ggdb3 pado.cpp    os.cpp -L${OPENSSL_PATH}/lib -L${OTLS_PATH}/mpc_tls -L${EMP_PATH}/lib -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sFORCE_FILESYSTEM -sMAIN_MODULE -lotls -lemp-tool -lssl -lcrypto -ldl -lrt -pthread -o pado.html -I../ -I/usr/local/include ${CIRCUIT_FILE1} ${CIRCUIT_FILE2} ${CIRCUIT_FILE6}


