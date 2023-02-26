#include "backend/commitment.h"

int main() {
    PRG prg;
    Commitment c;
    unsigned char* data = new unsigned char[100];
    unsigned char* com = new unsigned char[c.output_length];
    unsigned char* rnd = new unsigned char[c.rand_length];
    c.commit(com, rnd, data, 100);
    if (c.open(com, rnd, data, 100))
        std::cout << "correct" << endl;
    else
        std::cout << "wrong" << endl;

    delete[] data;
    delete[] com;
    delete[] rnd;
}