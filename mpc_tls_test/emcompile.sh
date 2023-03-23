# sudo apt install libssl-dev

EMOPENSSL_PATH=/home/ubuntu/test_openssl/otls/pado-emp/deps/install_wasm/
EMOTLS_PATH=/home/ubuntu/test_openssl/otls/build_wasm
EMEMP_PATH=/home/ubuntu/test_openssl/otls/pado-emp/build_wasm

CIRCUIT_FILE1="--preload-file ./cipher/circuit_files/aes128_ks.txt"
CIRCUIT_FILE2="--preload-file ./cipher/circuit_files/aes128_with_ks.txt"
CIRCUIT_FILE3="--preload-file ./ca.crt"
CIRCUIT_FILE4="--preload-file ./server.crt"
CIRCUIT_FILE5="--preload-file ./server.key"
CIRCUIT_FILE6="--preload-file ./bristol_fashion/aes_128.txt"

echo "compile server"
# g++ -ggdb3 server.cpp  -L../build/mpc_tls -L${OPENSSL_PATH}/lib -lotls -lssl -lcrypto -pthread -ldl -o server -I../
echo "compile client"
em++ -s WASM=1 -ggdb3 client.cpp  os.cpp -L${EMOPENSSL_PATH}/lib -L${EMOTLS_PATH}/mpc_tls -L${EMEMP_PATH}/lib -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sFORCE_FILESYSTEM -sMAIN_MODULE -lotls -lemp-tool -lemp-zk -lssl -lcrypto -ldl -lrt -pthread -o client.html -I../ -I${EMOPENSSL_PATH}/include ${CIRCUIT_FILE1} ${CIRCUIT_FILE2} ${CIRCUIT_FILE3} ${CIRCUIT_FILE6} -sSTACK_SIZE=256MB -sINITIAL_MEMORY=512MB -sALLOW_MEMORY_GROWTH
echo "compile pado"
# g++ -ggdb3 pado.cpp  -L../build/mpc_tls -L../../install_openssl/lib -L${EMP_PATH}/lib -lotls -lemp-tool -lemp-zk -lssl -lcrypto -pthread -ldl -o pado -I../ -I${OPENSSL_PATH}/include
