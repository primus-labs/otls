#include "cipher/utils.h"

// FULLPORT (unified model): the single definition of emp-tool's global backend
// pointer (declared extern in emp-tool/execution/backend.h). DynamicContext, the
// GC backends, and the OLE/E2F/AEAD sub-protocols all dispatch through it.
namespace emp {
#ifndef THREADING
Backend* backend = nullptr;
#else
__thread Backend* backend = nullptr;
#endif
}

// FULLPORT (session API): keep the fork's BristolFormat AES circuits, loaded via
// the new emp-tool BristolFormat(const char*) from the SAME .txt files (identical
// gates + I/O convention → invariant I3). The MEM path (std::string circuit data)
// no longer has a matching ctor upstream, so only the file path is supported.
#ifndef THREADING
BristolFormat* aes_ks = nullptr;
BristolFormat* aes_enc_ks = nullptr;
#else
__thread BristolFormat* aes_ks = nullptr;
__thread BristolFormat* aes_enc_ks = nullptr;
#endif

static const char* aes_ks_file = "cipher/circuit_files/aes128_ks.txt";
static const char* aes_enc_file = "cipher/circuit_files/aes128_with_ks.txt";

void init_files() {
    aes_ks = new BristolFormat(aes_ks_file);
    aes_enc_ks = new BristolFormat(aes_enc_file);
}

void uninit_files() {
    delete aes_ks;
    delete aes_enc_ks;
}
