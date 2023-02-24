#ifndef EMP_IO_CHANNEL_H__
#define EMP_IO_CHANNEL_H__
#include <memory>
#include <cassert>  

namespace emp {
template<typename T> 
class IOChannel { public:
    uint64_t counter = 0;
    void send_data(const void * data, size_t nbyte) {
        counter +=nbyte;
        derived().send_data_internal(data, nbyte);
    }

    void recv_data(void * data, size_t nbyte) {
        derived().recv_data_internal(data, nbyte);
    }


    private:
    T& derived() {
        return *static_cast<T*>(this);
    }
};
}
#endif
