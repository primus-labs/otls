# sudo apt install libssl-dev

PWD=`pwd`
EMOPENSSL_PATH=${PWD}/../pado-emp/deps/install_wasm/
EMOTLS_PATH=${PWD}/../build_wasm
EMEMP_PATH=${PWD}/../pado-emp/build_wasm

AES128_KS_FILE="--preload-file ./cipher/circuit_files/aes128_ks.txt"
AES128_WITH_KS_FILE="--preload-file ./cipher/circuit_files/aes128_with_ks.txt"
CA_FILE="--preload-file ./ca.crt"
AES_128_FILE="--preload-file ./bristol_fashion/aes_128.txt"

echo "compile client"
em++ -s WASM=1 -ggdb3 client.cpp  os.cpp -L${EMOPENSSL_PATH}/lib -L${EMOTLS_PATH}/mpc_tls -L${EMEMP_PATH}/lib -lwebsocket.js -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sFORCE_FILESYSTEM -sMAIN_MODULE -lotls -lemp-tool -lemp-zk -lssl -lcrypto -ldl -lrt -pthread -o client.html -I../ -I${EMOPENSSL_PATH}/include ${AES128_KS_FILE} ${AES128_WITH_KS_FILE} ${AES_128_FILE} ${CA_FILE} -s TOTAL_STACK=128MB -s INITIAL_MEMORY=256MB -s ALLOW_MEMORY_GROWTH=1
