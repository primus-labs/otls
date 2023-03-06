#! /bin/bash
PWD=`pwd`
EMOPENSSL=${PWD}/../../install_emopenssl
OPENSSL=${PWD}/../../install_openssl

g++ client.cpp -o client -g -lssl -lcrypto -ldl -pthread -I${OPENSSL}/include -L${OPENSSL}/lib/
g++ server.cpp -o server -g -lssl -lcrypto -ldl -pthread -I${OPENSSL}/include -L${OPENSSL}/lib/
g++ websocket_server.cpp sha1.cpp -o websocket_server -g -lssl -lcrypto -ldl -pthread -I${OPENSSL}/include -L${OPENSSL}/lib/
g++ wss_server.cpp sha1.cpp wss.cpp -o wss_server -g -lssl -lcrypto -ldl -pthread -I${OPENSSL}/include -L${OPENSSL}/lib/

em++ client.cpp  os.cpp -o client.html -g -lssl -lcrypto -ldl -lwebsocket.js -sWASM=1 -sERROR_ON_UNDEFINED_SYMBOLS=1 -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sMAIN_MODULE -sREVERSE_DEPS=all --preload-file ca.crt -I${EMOPENSSL}/include -L${EMOPENSSL}/lib/
em++ wss_client.cpp  os.cpp sha1.cpp wss.cpp -o wss_client.html -g -lssl -lcrypto -ldl -lwebsocket.js -sWASM=1 -sERROR_ON_UNDEFINED_SYMBOLS=1 -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sMAIN_MODULE -sREVERSE_DEPS=all --preload-file ca.crt -I${EMOPENSSL}/include -L${EMOPENSSL}/lib/

em++ websocket_client.cpp  os.cpp -o websocket_client.html -g -lssl -lcrypto -ldl -lwebsocket.js -sWASM=1 -sERROR_ON_UNDEFINED_SYMBOLS=1 -sPROXY_POSIX_SOCKETS -sUSE_PTHREADS -sPROXY_TO_PTHREAD -sMAIN_MODULE -sREVERSE_DEPS=all --preload-file ca.crt -I${EMOPENSSL}/include -L${EMOPENSSL}/lib/
