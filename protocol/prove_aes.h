/* 
    This is for the proxy model, which does not need MPC to run the handshake and record phase. 
    The proxy will keep and forward all the TLS transcripts. 
    The client will prove (with interactive zkp) to the proxy (verifier) 
    that he knows the session key (and possibly some private message) encrypted under the given ciphertexts.
*/

#ifndef _AESPROVER_
#define _AESPROVER_

#include "emp-tool/emp-tool.h"
#include "cipher/utils.h"

// FULLPORT (session API): the global backend / setup_zk_bool / finalize_zk_bool
// are gone upstream. setup_proxy_protocol now constructs the single proof-wide
// ZKBoolSession (owned here) and installs it as the active session g_zk that the
// Integer/circuit shim reaches. `expected_cots` sizes the SilentFerret prepay
// (0 = per-round streaming; pass ~AES ANDs to make the proof's COT draws
// wire-free). Single-IO/single-threaded migration (accepted).
// Build the ZK proof engine (SilentFerret + QuickSilver) and install its
// emp::Backend adapter as the global backend (via the keystone setup_zk_bool), so
// the shared Integer/circuit code runs in ZK. `expected_cots` sizes the prepay.
inline void setup_proxy_protocol(emp::BoolIO* io, int party, int64_t expected_cots = 0) {
    init_files();
    emp::setup_zk_bool(io, party, expected_cots);
}

// OPTION-A optimization (single-session proxytls): estimate the SilentFerret COT
// draw so the caller can size the prepay (begin(expected_cots)) and keep the
// proving phase wire-free. Without it (expected_cots = 0) the proof streams COTs
// and pays ~1 blocking round-trip per ~15M-COT refresh, so the proving-phase RTT
// GROWS with record size (measured: 64KB->5, 256KB->29, 1MB->117 proof rounds).
// Passing this estimate concentrates all that COT-correction traffic into ONE
// begin() prepay, collapsing the proving-phase refresh round-trips to ~0 (measured:
// ->1 regardless of size). Soundness-neutral: it does NOT change the proven
// relation (I3) or any invariant — it only re-times when the (identical) COT
// bytes are exchanged. Measured: total comm is essentially unchanged (proof uplink
// identical; downlink can be a few % more, see the upper-bound note below).
//
// TWO usages (same function, different argument semantics):
//
//  (1) ONLINE / per-request EXACT sizing — pass the ACTUAL total ciphertext bytes
//      this proof covers. Setup is then DATA-DEPENDENT (it must know the size),
//      so it canNOT be a generic data-independent offline phase. Minimal waste.
//
//  (2) OFFLINE / data-independent UPPER BOUND — use estimate_proxy_cots_bound()
//      and pass the MAX request size you provision for, BEFORE the data is known.
//      COT is data-independent in nature (random correlations; only the COUNT is
//      data-dependent), so a fixed bound keeps setup data-independent. Online stays
//      wire-free for any request <= bound (measured: prove 64KB under a 1MB-bound
//      prepay still gives proof rounds=1); requests > bound roll over to streaming
//      for the excess. COST: the (bound - actual) gap is extra COT generated in
//      SETUP only (measured: setup downlink 0.9MB -> 9.2MB when over-provisioning
//      64KB to a 1MB bound), entirely OFF the online critical path. Tune the bound
//      to your request-size distribution. (Provisioning ONE pool and amortizing it
//      across many requests instead of per-request is the persistent-COT-state
//      design, which needs an emp-zk lifetime change — out of scope here.)
//
//   bytes = ciphertext bytes (Finished messages + record ciphertexts); the fixed
//   PRF / handshake cost is added on top via fixed_base.
inline int64_t estimate_proxy_cots(size_t total_record_bytes) {
    const int64_t per_byte   = 512;          // generous AES-GCM ZK ANDs/byte (1 COT per AND)
    const int64_t fixed_base = 4'000'000;    // PRF + client/server Finished + AEAD + check overhead
    return (int64_t)total_record_bytes * per_byte + fixed_base;
}

// OFFLINE / data-independent prepay sizing (usage 2 above): pass an UPPER BOUND on
// the request ciphertext bytes you provision for, ahead of the actual data. Keeps
// setup data-independent; online is wire-free for any request <= this bound and
// degrades to streaming only for the excess. Identical math to estimate_proxy_cots
// — the distinct name documents the data-independent / over-provision intent.
inline int64_t estimate_proxy_cots_bound(size_t max_record_bytes) {
    return estimate_proxy_cots(max_record_bytes);
}

// finalize_zk_bool() runs the closing MAC-digest / AND-batch checks; on a cheating
// prover upstream aborts via error()→exit(1) (= reject, soundness/I1 preserved).
// Reaching past finalize means no cheating occurred → cheated flag false.
inline bool finalize_proxy_protocol() {
    emp::finalize_zk_bool();
    uninit_files();
    return false;
}

// The counter blocks infomation to be proved and the length of each counter block is 16 bytes.
// `id` is the counter block index, starting from zero.
// `mask` identify the bytes to be proved in one counter block. If `mask[i]` is 1,
// then the i-th bytes should be proved
struct AESCounterInfo {
    size_t id;
    unsigned char mask[16];
};

/*
    The AES Prover.
*/
class AESProver {
   public:
    // This is the scheduled aes key.
    Integer expanded_key;
    Integer fixed_iv;
    Integer nonce;

    // `key` and `iv` are client(server) write key and iv respectively derived from master secret.
    // Note the length of `key` is 16-bytes and the length of `iv` is 4-bytes.
    inline AESProver(Integer& key, Integer& iv) {
        assert(key.size() == 128);
        expanded_key = computeKS(key);

        assert(iv.size() == 32);
        fixed_iv = iv;
    }
    ~AESProver() {}

    inline Integer inc(Integer& counter, size_t s) {
        if (counter.size() < s) {
            error("invalid length s!");
        }
        Integer msb = counter, lsb = counter;
        msb.bits.erase(msb.bits.begin(), msb.bits.begin() + s);
        lsb.bits.erase(lsb.bits.begin() + s, lsb.bits.end());
        lsb = lsb + Integer(s, 1, PUBLIC);

        concat(msb, &lsb, 1);
        return msb;
    }

    inline void gctr(Integer& res, size_t m) {
        Integer tmp(128, 0, PUBLIC);
        for (size_t i = 0; i < m; i++) {
            Integer content = nonce;
            tmp = computeAES_KS(expanded_key, content);

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    inline void gctr_opt(vector<Integer>& res, const vector<size_t>& ids) {
        if (ids.empty()) return;

        size_t index = 0;
        for (size_t i = 0; ; i++) {
            if (i == ids[index] + 1) {
                Integer content = nonce;
                Integer tmp = computeAES_KS(expanded_key, content);
                res.push_back(tmp);

                index++;
                if (index >= ids.size()) {
                    break;
                }
            }
            nonce = inc(nonce, 32);
        }
    }

    // `iv_len` should be 8, the `iv` derived from master secret
    // will be concated with this iv to form the full iv, the 
    // length of which is 12-bytes.
    inline void set_nonce(const unsigned char* iv,
                          size_t iv_len) {
        assert(iv_len == 8);

        unsigned char* riv = new unsigned char[iv_len];
        memcpy(riv, iv, iv_len);
        reverse(riv, riv + iv_len);
        Integer variable_iv(64, riv, PUBLIC);

        delete[] riv;

        Integer ONE = Integer(32, 1, PUBLIC);

        nonce = fixed_iv;
        concat(nonce, &variable_iv, 1);
        concat(nonce, &ONE, 1);
    }

    inline Integer computeCounter(const unsigned char* iv, size_t iv_len, size_t msg_len) {
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        set_nonce(iv, iv_len);
        Integer Z;
        gctr(Z, 1 + ctr_len);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);
        return Z;
    }

    inline Integer computeCounterOpt(const vector<AESCounterInfo>& counterInfos,
                                             const unsigned char* iv,
                                             size_t iv_len) {
        vector<size_t> ids;
        for (size_t i = 0; i < counterInfos.size(); i++) {
            ids.push_back(counterInfos[i].id);
        }

        vector<Integer> counters;
        set_nonce(iv, iv_len);
        gctr_opt(counters, ids);

        Integer izk_counter;
        for (size_t i = 0; i < counterInfos.size(); i++) {
            const AESCounterInfo& c = counterInfos[i];
            const Integer& oneCounter = counters[i];
            int begin = -1;
            int j = 0;

            for (; j < 16; j++) {
                if (c.mask[j]) {
                    if (begin == -1) {
                        begin = j;
                    }
                }
                else {
                    if (begin != -1) {
                        izk_counter.bits.insert(izk_counter.bits.begin(), oneCounter.bits.end() - j * 8, oneCounter.bits.end() - begin * 8);
                        begin = -1;
                    }
                }
            }
            if (begin != -1) {
                izk_counter.bits.insert(izk_counter.bits.begin(), oneCounter.bits.end() - j * 8, oneCounter.bits.end() - begin * 8);
                begin = -1;
            }
            
        }

        return izk_counter;
    }


    // This proves AES(k, nounce) xor msgs = ctxts in blocks, where msgs is public.
    // Note the msgs and ctxts should be continuous and no block can be omitted.
    inline bool prove_public_msgs(const unsigned char* iv,
                                  size_t iv_len,
                                  const unsigned char* msgs,
                                  const unsigned char* ctxts,
                                  size_t msg_len) {
        Integer c = computeCounter(iv, iv_len, msg_len);

        unsigned char* c_xor_m = new unsigned char[msg_len];
        for (size_t i = 0; i < msg_len; ++i) {
            c_xor_m[msg_len - 1 - i] = msgs[i] ^ ctxts[i];
        }

        unsigned char* expected = new unsigned char[msg_len];

        c.reveal((unsigned char*)expected, PUBLIC);  // FULLPORT: upstream reveal(void*,party) is not a template
        bool res = memcmp(expected, c_xor_m, msg_len) == 0;

        delete[] c_xor_m;
        delete[] expected;
        return res;
    }

    // This proves AES(k, nounces) xor msgs = ctxts in blocks, where msgs is private.
    // Note the msgs and ctxts should be continuous and no block can be omitted.
    inline bool prove_private_msgs(const unsigned char* iv,
                                   size_t iv_len,
                                   const Integer& msgs,
                                   const unsigned char* ctxts,
                                   size_t msg_len) {
        assert(msgs.size() == 8 * msg_len);

        Integer c = computeCounter(iv, iv_len, msg_len);

        c ^= msgs;

        unsigned char* expected = new unsigned char[msg_len];

        c.reveal((unsigned char*)expected, PUBLIC);  // FULLPORT: upstream reveal(void*,party) is not a template
        reverse(expected, expected + msg_len);
        bool res = memcmp(expected, ctxts, msg_len) == 0;

        delete[] expected;
        return res;
    }

    // This proves AES(k, nounce) xor msgs = ctxts in blocks, where msgs is public.
    // Note the msgs and ctxts can be discreate and their positions can be identified by `counterInfos`.
    inline bool prove_public_msgs_opt(const vector<AESCounterInfo>& counterInfos,
                                       const unsigned char* iv,
                                       size_t iv_len, 
                                       const unsigned char* msgs,
                                       const unsigned char* ctxts,
                                       size_t msg_len) {
        Integer c = computeCounterOpt(counterInfos, iv, iv_len);

        unsigned char* c_xor_m = new unsigned char[msg_len];
        for (size_t i = 0; i < msg_len; ++i) {
            c_xor_m[msg_len - 1 - i] = msgs[i] ^ ctxts[i];
        }

        unsigned char* expected = new unsigned char[msg_len];

        c.reveal((unsigned char*)expected, PUBLIC);  // FULLPORT: upstream reveal(void*,party) is not a template
        bool res = memcmp(expected, c_xor_m, msg_len) == 0;

        delete[] c_xor_m;
        delete[] expected;
        return res;
    }

    // This proves AES(k, nounces) xor msgs = ctxts in blocks, where msgs is private.
    // Note the msgs and ctxts can be discreate and their positions can be identified by `counterInfos`.
    inline bool prove_private_msgs_opt(const vector<AESCounterInfo>& counterInfos,
                                       const unsigned char* iv,
                                       size_t iv_len, 
                                       const Integer& msgs,
                                       const unsigned char* ctxts,
                                       size_t msg_len) {
        assert(msgs.size() == 8 * msg_len);

        Integer c = computeCounterOpt(counterInfos, iv, iv_len);

        c ^= msgs;

        unsigned char* expected = new unsigned char[msg_len];

        c.reveal((unsigned char*)expected, PUBLIC);  // FULLPORT: upstream reveal(void*,party) is not a template
        reverse(expected, expected + msg_len);
        bool res = memcmp(expected, ctxts, msg_len) == 0;

        delete[] expected;
        return res;
    }
};

#endif
