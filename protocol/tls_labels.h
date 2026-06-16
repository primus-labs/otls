#ifndef _TLS_LABELS_H_
#define _TLS_LABELS_H_
#include <cstddef>

// FULLPORT (session API): the TLS-PRF label/length constants, extracted from
// handshake.h so the pure-ZK proxytls PRF path (prove_prf.h) can use them
// WITHOUT pulling in handshake.h's GC/mpctls machinery (e2f.h / backend/switch.h
// / aead*.h). handshake.h includes this same header (single definition).

static unsigned char master_key_label[] = {"master secret"};
static unsigned char key_expansion_label[] = {"key expansion"};
static unsigned char client_finished_label[] = {"client finished"};
static unsigned char server_finished_label[] = {"server finished"};
static unsigned char extended_master_key_label[] = {"extended master secret"};

static size_t master_key_label_length = sizeof(master_key_label) - 1;
static size_t key_expansion_label_length = sizeof(key_expansion_label) - 1;
static size_t client_finished_label_length = sizeof(client_finished_label) - 1;
static size_t server_finished_label_length = sizeof(server_finished_label) - 1;
static size_t extended_master_key_label_length = sizeof(extended_master_key_label) - 1;

static const size_t master_key_length = 384 / 8;
static const size_t expansion_key_length = 320 / 8;
static const size_t finished_msg_length = 96 / 8;
static const size_t tag_length = 16;
static const size_t iv_length = 4;
static const size_t key_length = 128 / 8;
static const size_t extended_master_key_length = 384 / 8;

static const size_t random_length = 256 / 8;
static const size_t session_hash_length = 256 / 8;

#endif  // _TLS_LABELS_H_
