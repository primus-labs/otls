#!/bin/bash

# sudo apt install libssl-dev, etc.

g++ tls_server.cpp -o tls_server -lssl -lcrypto
