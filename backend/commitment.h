#ifndef __COMMITMENT_H__
#define __COMMITMENT_H__

#include "emp-tool/emp-tool.h"

using namespace emp;

/* Define the hash-based commitment*/
class Commitment {
   public:
    Hash hash;
    PRG prg;
    int output_length = Hash::DIGEST_SIZE;
    int rand_length = 16;
    Commitment() {}
    ~Commitment() {}
    inline void commit(unsigned char* com,
                       unsigned char* rnd,
                       unsigned char* data,
                       size_t length) {
        prg.random_data(rnd, rand_length);
        hash.put(data, length);
        hash.put(rnd, rand_length);
        hash.digest(com);
    }
    inline bool open(unsigned char* com,
                     unsigned char* rnd,
                     unsigned char* data,
                     size_t length) {
        hash.put(data, length);
        hash.put(rnd, rand_length);

        unsigned char* comm = new unsigned char[output_length];
        hash.digest(comm);

        bool res = (memcmp(com, comm, output_length) == 0);
        delete[] comm;
        return res;
    }
};

#endif