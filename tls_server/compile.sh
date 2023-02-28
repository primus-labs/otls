#!/bin/bash

# sudo apt install libssl-dev, etc.

g++ server.cpp -o tls_server -lssl -lcrypto
