#ifndef PRIMUS_COM_COV_H
#define PRIMUS_COM_COV_H
#include <openssl/bn.h>
#include <string.h>

#include "backend/bn_utils.h"
#include "backend/ole.h"

/* Define the Pederson commitment */
class PedersenComm {
   public:
    EC_GROUP* group = nullptr;
    EC_POINT* h;
    UniquePoint p_h;
    BN_CTX* ctx;
    UniqueCtx p_ctx;

    // h should be chosen very carefully, without any trapdoor.
    PedersenComm(EC_POINT* h, EC_GROUP* group) {
        ctx = BN_CTX_new();
        p_ctx.reset(ctx);
        this->group = group;
        this->h = EC_POINT_new(group);
        p_h.reset(this->h);
        EC_POINT_copy(this->h, h);
    }

    ~PedersenComm() {
    }

    inline void commit(EC_POINT* com, BIGNUM* rnd, const BIGNUM* msg) {
        BN_rand_range(rnd, EC_GROUP_get0_order(group));
        EC_POINT_mul(group, com, msg, h, rnd, ctx);
    }

    inline bool open_check(const EC_POINT* com, const BIGNUM* rnd, const BIGNUM* msg) {
        EC_POINT* expected_com = EC_POINT_new(group);
        UniquePoint p_expected_com(expected_com);
        EC_POINT_mul(group, expected_com, msg, h, rnd, ctx);
        bool res = (EC_POINT_cmp(group, com, expected_com, ctx) == 0);

        return res;
    }

    inline void linear_comb_com(EC_POINT* res,
                                const vector<EC_POINT*>& coms,
                                const vector<BIGNUM*>& coef) {
        assert(coms.size() == coef.size());
        EC_POINT_set_to_infinity(group, res);
        EC_POINT* tmp = EC_POINT_new(group);
        UniquePoint p_tmp(tmp);
        for (size_t i = 0; i < coef.size(); i++) {
            EC_POINT_mul(group, tmp, NULL, coms[i], coef[i], ctx);
            EC_POINT_add(group, res, res, tmp, ctx);
        }

    }

    inline void linear_comb_rand(BIGNUM* res,
                                 const vector<BIGNUM*>& rnds,
                                 const vector<BIGNUM*>& coef) {
        assert(rnds.size() == coef.size());
        BIGNUM* tmp = BN_new();
        UniqueBN p_tmp(tmp);
        BN_set_word(res, 0);
        for (size_t i = 0; i < coef.size(); i++) {
            BN_mod_mul(tmp, rnds[i], coef[i], EC_GROUP_get0_order(group), ctx);
            BN_mod_add(res, res, tmp, EC_GROUP_get0_order(group), ctx);
        }

    }
};

/* Convert IT-MACed messages into Pedersen commitment */
template <typename IO>
class ComConv {
   public:
    IO* io;
    block bDelta = zero_block;
    BIGNUM* aDelta = nullptr;
    UniqueBN p_aDelta;
    CCRH ccrh;
    unsigned char com[Hash::DIGEST_SIZE];
    unsigned char msg_com[Hash::DIGEST_SIZE];
    Hash chi_hash;
    // q is the order of the ECC group.
    BIGNUM* q;
    UniqueBN p_q;
    BN_CTX* ctx;
    UniqueCtx p_ctx;
    BIGNUM* r = nullptr;
    UniqueBN p_r;
    block com_seed;
    OLE<IO>* ole;
    std::unique_ptr<OLE<IO>> p_ole;
    vector<BIGNUM*> exp;
    vector<UniqueBN> p_exp;

    ComConv(IO* io, COT<IO>* ot, BIGNUM* q2, block bDelta) : io(io) {
        q = BN_new();
        p_q.reset(q);
        BN_copy(this->q, q2);
        ctx = BN_CTX_new();
        p_ctx.reset(ctx);
        ole = new OLE<IO>(io, ot, q2, BN_num_bits(q2));
        p_ole.reset(ole);

        exp.resize(BN_num_bits(q2));
        p_exp.resize(BN_num_bits(q2));
        for (int i = 0; i < BN_num_bits(q2); ++i) {
            exp[i] = BN_new();
            p_exp[i].reset(exp[i]);
            BN_set_bit(exp[i], i);
            BN_mod(exp[i], exp[i], q, ctx);
        }
        this->bDelta = bDelta;
    }
    ~ComConv() {
    }

    void compute_hash(unsigned char res[Hash::DIGEST_SIZE],
                      block seed,
                      block bDelta,
                      BIGNUM* aDelta) {
        Hash hash;
        hash.put(&seed, sizeof(block));
        hash.put(&bDelta, sizeof(block));
        unsigned char arr[1000];
        int length = BN_bn2bin(aDelta, arr);
        hash.put(&length, sizeof(int));
        hash.put(arr, length);
        hash.digest(res);
    }

    void commitDelta(BIGNUM* aDelta = nullptr) {
        if (aDelta != nullptr) {
            PRG prg;
            prg.random_data(&com_seed, sizeof(block));
            compute_hash(com, com_seed, bDelta, aDelta);
            io->send_data(com, Hash::DIGEST_SIZE);
            this->aDelta = BN_new();
            p_aDelta.reset(this->aDelta);
            BN_copy(this->aDelta, aDelta);
            chi_hash.put(com, Hash::DIGEST_SIZE);
        } else {
            io->recv_data(com, Hash::DIGEST_SIZE);
            chi_hash.put(com, Hash::DIGEST_SIZE);
        }
    }

    void convert_recv(vector<BIGNUM*>& aMACs, vector<block>& bMACs) {
        Hash hash;
        vector<BIGNUM*> msg;
        vector<UniqueBN> p_msg;
        msg.resize(bMACs.size());
        p_msg.resize(bMACs.size());
        for (size_t i = 0; i < bMACs.size(); ++i) {
            msg[i] = BN_new();
            p_msg[i].reset(msg[i]);
            recv_bn(io, msg[i], &hash);
        }
        hash.digest(msg_com);
        chi_hash.put(msg_com, Hash::DIGEST_SIZE);

        for (size_t i = 0; i < bMACs.size(); ++i) {
            H(aMACs[i], bMACs[i], q, ctx, ccrh);
            if (getLSB(bMACs[i])) {
                BN_sub(aMACs[i], msg[i], aMACs[i]);
                BN_mod_add(aMACs[i], aMACs[i], q, q, ctx);
            }
        }
    }

    void convert_send(vector<BIGNUM*>& aKEYs, vector<block>& bKEYs) {
        Hash hash;
        vector<BIGNUM*> msg;
        vector<UniqueBN> p_msg;
        msg.resize(bKEYs.size());
        p_msg.resize(bKEYs.size());
        for (size_t i = 0; i < bKEYs.size(); ++i) {
            msg[i] = BN_new();
            p_msg[i].reset(msg[i]);
        }

        convert(msg, aKEYs, bKEYs, bDelta, aDelta);
        for (size_t i = 0; i < msg.size(); ++i)
            send_bn(io, msg[i], &hash);

        hash.digest(msg_com);
        chi_hash.put(msg_com, Hash::DIGEST_SIZE);

    }

    void convert(vector<BIGNUM*>& msg,
                 vector<BIGNUM*>& aKEYs,
                 vector<block>& bKEYs,
                 block local_bDelta,
                 BIGNUM* local_aDelta) {
        assert(aKEYs.size() == bKEYs.size());
        for (size_t i = 0; i < aKEYs.size(); ++i) {
            H(aKEYs[i], bKEYs[i], q, ctx, ccrh);
            H(msg[i], bKEYs[i] ^ local_bDelta, q, ctx, ccrh);
            BN_add(msg[i], msg[i], aKEYs[i]);
            BN_mod_add(msg[i], msg[i], local_aDelta, q, ctx);
        }
    }

    void open() {
        io->send_data(&com_seed, sizeof(block));
        io->send_data(&bDelta, sizeof(block));
        send_bn(io, aDelta);
    }
    bool open(vector<block>& bMACs) {
        bool ret = true;
        block tmp_seed, tmp_bDelta;
        BIGNUM* tmp_aDelta = BN_new();
        UniqueBN p_tmp_aDelta(tmp_aDelta);
        io->recv_data(&tmp_seed, sizeof(block));
        io->recv_data(&tmp_bDelta, sizeof(block));
        recv_bn(io, tmp_aDelta);
        unsigned char tmp_com[Hash::DIGEST_SIZE];
        compute_hash(tmp_com, tmp_seed, tmp_bDelta, tmp_aDelta);
        ret = ret and (std::strncmp((char*)tmp_com, (char*)com, Hash::DIGEST_SIZE) == 0);

        vector<BIGNUM*> msg;
        vector<UniqueBN> p_msg;
        msg.resize(bMACs.size());
        p_msg.resize(bMACs.size());
        vector<BIGNUM*> tmp_akeys;
        vector<UniqueBN> p_tmp_akeys;
        tmp_akeys.resize(bMACs.size());
        p_tmp_akeys.resize(bMACs.size());
        vector<block> tmp_bkeys(bMACs);
        for (size_t i = 0; i < bMACs.size(); ++i) {
            tmp_akeys[i] = BN_new();
            p_tmp_akeys[i].reset(tmp_akeys[i]);
            msg[i] = BN_new();
            p_msg[i].reset(msg[i]);
            if (getLSB(tmp_bkeys[i]))
                tmp_bkeys[i] = tmp_bkeys[i] ^ tmp_bDelta;
        }
        convert(msg, tmp_akeys, tmp_bkeys, tmp_bDelta, tmp_aDelta);
        Hash hash;
        unsigned char arr[1000];
        for (size_t i = 0; i < bMACs.size(); ++i) {
            uint32_t length = BN_bn2bin(msg[i], arr);
            hash.put(arr, length);
        }
        hash.digest(tmp_com);

        ret = ret and (std::strncmp((char*)tmp_com, (char*)msg_com, Hash::DIGEST_SIZE) == 0);
        return ret;
    }

    inline void mask_mac(BIGNUM* rMAC) {
        this->r = BN_new();
        BN_rand_range(this->r, q);
        vector<BIGNUM*> out, in;
        out.push_back(rMAC);
        in.push_back(this->r);
        ole->compute(out, in);
    }

    inline void mask_key(BIGNUM* rKEY) {
        vector<BIGNUM*> out, in;
        out.push_back(rKEY);
        in.push_back(this->aDelta);
        ole->compute(out, in);
        BN_sub(rKEY, q, rKEY);
    }

    inline void gen_chi(vector<BIGNUM*>& chi, block seed) {
        PRG prg(&seed);
        unsigned char tmp[BN_num_bytes(q)];
        for (size_t i = 0; i < chi.size(); i++) {
            prg.random_data(tmp, BN_num_bytes(q));
            BN_bin2bn(tmp, BN_num_bytes(q), chi[i]);
            BN_mod(chi[i], chi[i], q, ctx);
        }
    }

    bool compute_com_send(vector<EC_POINT*>& com,
                          vector<block> bKEYs,
                          PedersenComm& pc,
                          uint64_t batch_size) {
        BIGNUM* bs_int = BN_new();
        UniqueBN p_bs_int(bs_int);
        BIGNUM* ONE = BN_new();
        UniqueBN p_ONE(ONE);

        BN_set_bit(bs_int, batch_size);
        BN_set_word(ONE, 1);
        // 2^{bs} - 1
        BN_sub(bs_int, bs_int, ONE);
        int check = BN_cmp(bs_int, q);
        if (check != -1)
            error("batch size is too large!\n");

        bool res = true;
        // choose random arithmetic Delta (aDelta), commit bDelta and aDelta.
        BIGNUM* Delta = BN_new();
        UniqueBN p_Delta(Delta);
        BN_rand_range(Delta, this->q);
        commitDelta(Delta);

        // generate IT-MAC key for random r;
        BIGNUM* rKEY = BN_new();
        UniqueBN p_rKEY(rKEY);
        mask_key(rKEY);

        // convert boolean IT-MAC key to arithmetic IT-MAC key.
        vector<BIGNUM*> aKEYs(bKEYs.size());
        vector<UniqueBN> p_aKEYs(bKEYs.size());
        for (size_t i = 0; i < aKEYs.size(); i++) {
            aKEYs[i] = BN_new();
            p_aKEYs[i].reset(aKEYs[i]);
        }
        convert_send(aKEYs, bKEYs);
        //  separate input bits into chunks with batch_size bits each.
        size_t chunk_len = (bKEYs.size() + batch_size - 1) / batch_size;
        BIGNUM* tmp = BN_new();
        UniqueBN p_tmp(tmp);
        vector<BIGNUM*> batch_aKEYs(chunk_len);
        vector<UniqueBN> p_batch_aKEYs(chunk_len);
        for (size_t i = 0; i < chunk_len; i++) {
            batch_aKEYs[i] = BN_new();
            p_batch_aKEYs[i].reset(batch_aKEYs[i]);
            BN_set_word(batch_aKEYs[i], 0);
        }

        for (size_t i = 0; i < chunk_len; i++) {
            for (size_t j = 0; (j < batch_size) && (i * batch_size + j < bKEYs.size()); j++) {
                BN_mod_mul(tmp, exp[j], aKEYs[i * batch_size + j], q, ctx);
                BN_mod_add(batch_aKEYs[i], batch_aKEYs[i], tmp, q, ctx);
            }
        }

        // receive commitments of chunks from Pb.
        // could use compressed point.
        unsigned char* buf = new unsigned char[65];
        std::unique_ptr<unsigned char[]> p_buf(buf);
        for (size_t i = 0; i < chunk_len; i++) {
            io->recv_data(buf, 65);
            chi_hash.put(buf, 65);
            EC_POINT_oct2point(pc.group, com[i], buf, 65, ctx);
        }
        // receive commitment of r.
        EC_POINT* comm_r = EC_POINT_new(pc.group);
        UniquePoint p_comm_r(comm_r);
        io->recv_data(buf, 65);
        chi_hash.put(buf, 65);
        EC_POINT_oct2point(pc.group, comm_r, buf, 65, ctx);
        // generate and send chi's.
        vector<BIGNUM*> chi(chunk_len);
        vector<UniqueBN> p_chi(chunk_len);
        for (size_t i = 0; i < chunk_len; i++) {
            chi[i] = BN_new();
            p_chi[i].reset(chi[i]);
        }

        unsigned char chi_digest[Hash::DIGEST_SIZE];
        chi_hash.digest(chi_digest);
        block seed = zero_block;
        memcpy(&seed, chi_digest, sizeof(block));
        gen_chi(chi, seed);

        // generate linear combination of IT-MAC keys.
        BIGNUM* yKEY = rKEY;
        BIGNUM* tmpm = BN_new();
        UniqueBN p_tmpm(tmpm);
        for (size_t i = 0; i < chunk_len; i++) {
            BN_mod_mul(tmpm, chi[i], batch_aKEYs[i], q, ctx);
            BN_mod_add(yKEY, yKEY, tmpm, q, ctx);
        }

        // generate com_y
        vector<EC_POINT*> comms(com);
        comms.push_back(comm_r);

        vector<BIGNUM*> scales(chi);
        BIGNUM* one = BN_new();
        UniqueBN p_one(one);
        BN_set_word(one, 1);
        scales.push_back(one);

        EC_POINT* com_y = EC_POINT_new(pc.group);
        UniquePoint p_com_y(com_y);

        pc.linear_comb_com(com_y, comms, scales);

        // receive yMAC_com
        unsigned char yMAC_com[Hash::DIGEST_SIZE];
        io->recv_data(yMAC_com, Hash::DIGEST_SIZE);

        // receive opening of com_y;
        BIGNUM* rnd_y = BN_new();
        UniqueBN p_rnd_y(rnd_y);
        BIGNUM* msg_y = BN_new();
        UniqueBN p_msg_y(msg_y);
        recv_bn(io, rnd_y);
        recv_bn(io, msg_y);

        res = res and pc.open_check(com_y, rnd_y, msg_y);

        open();

        // check open of com_y
        block yMAC_seed = zero_block;
        io->recv_block(&yMAC_seed, 1);
        BIGNUM* yMAC = BN_new();
        UniqueBN p_yMAC(yMAC);
        recv_bn(io, yMAC);

        unsigned char yMAC_com_comp[Hash::DIGEST_SIZE];
        Hash hash;
        hash.put(&yMAC_seed, sizeof(block));
        unsigned char arr[1000];
        int length = BN_bn2bin(yMAC, arr);
        hash.put(arr, length);
        hash.digest(yMAC_com_comp);

        res = res and (memcmp(yMAC_com, yMAC_com_comp, Hash::DIGEST_SIZE) == 0);

        // check M[y] = K[y] + y* aDelta
        BN_mod_mul(msg_y, msg_y, aDelta, q, ctx);
        BN_mod_add(yKEY, yKEY, msg_y, q, ctx);

        res = res and (BN_cmp(yMAC, yKEY) == 0);

        return res;
    }

    bool compute_com_recv(vector<EC_POINT*>& com,
                          vector<BIGNUM*>& rnds,
                          vector<block> bMACs,
                          PedersenComm& pc,
                          uint64_t batch_size) {
        BIGNUM* bs_int = BN_new();
        UniqueBN p_bs_int(bs_int);
        BIGNUM* ONE = BN_new();
        UniqueBN p_ONE(ONE);

        BN_set_bit(bs_int, batch_size);
        BN_set_word(ONE, 1);
        // 2^{bs} - 1
        BN_sub(bs_int, bs_int, ONE);
        int check = BN_cmp(bs_int, q);
        if (check != -1)
            error("batch size is too large!\n");

        bool res = true;
        // receive commitment of bDelta and aDelta.
        commitDelta();

        // generate IT-MAC mac for random r;
        BIGNUM* rMAC = BN_new();
        UniqueBN p_rMAC(rMAC);
        mask_mac(rMAC);

        // convert boolean IT-MAC mac to arithmetic IT-MAC mac.
        vector<BIGNUM*> aMACs(bMACs.size());
        vector<UniqueBN> p_aMACs(bMACs.size());
        for (size_t i = 0; i < aMACs.size(); i++) {
            aMACs[i] = BN_new();
            p_aMACs[i].reset(aMACs[i]);
        }
        convert_recv(aMACs, bMACs);
        //  separate input bits into chunks with batch_size bits each.
        size_t chunk_len = (bMACs.size() + batch_size - 1) / batch_size;

        // compute commitment and randomness of chunks.
        vector<BIGNUM*> msg(chunk_len);
        vector<UniqueBN> p_msg(chunk_len);
        vector<BIGNUM*> batch_aMACs(chunk_len);
        vector<UniqueBN> p_batch_aMACs(chunk_len);
        for (size_t i = 0; i < chunk_len; i++) {
            batch_aMACs[i] = BN_new();
            p_batch_aMACs[i].reset(batch_aMACs[i]);
            msg[i] = BN_new();
            p_msg[i].reset(msg[i]);
            BN_set_word(batch_aMACs[i], 0);
            BN_set_word(msg[i], 0);
        }

        BIGNUM* tmp = BN_new();
        UniqueBN p_tmp(tmp);
        for (size_t i = 0; i < chunk_len; i++) {
            for (size_t j = 0; (j < batch_size) && (i * batch_size + j < bMACs.size()); j++) {
                if (getLSB(bMACs[i * batch_size + j]))
                    BN_mod_add(msg[i], msg[i], exp[j], q, ctx);

                BN_mod_mul(tmp, exp[j], aMACs[i * batch_size + j], q, ctx);
                BN_mod_add(batch_aMACs[i], batch_aMACs[i], tmp, q, ctx);
            }
            pc.commit(com[i], rnds[i], msg[i]);
        }


        // compute commitment and randomness of r.
        EC_POINT* comm_r = EC_POINT_new(pc.group);
        UniquePoint p_comm_r(comm_r);
        BIGNUM* rnd_r = BN_new();
        UniqueBN p_rnd_r(rnd_r);
        pc.commit(comm_r, rnd_r, this->r);

        // send commitments of chunks to Pa.
        // could use compressed point.
        unsigned char* buf = new unsigned char[65];
        std::unique_ptr<unsigned char[]> p_buf(buf);
        for (size_t i = 0; i < chunk_len; i++) {
            EC_POINT_point2oct(pc.group, com[i], POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
            io->send_data(buf, 65);
            chi_hash.put(buf, 65);
        }

        // send commitment of r.
        EC_POINT_point2oct(pc.group, comm_r, POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        io->send_data(buf, 65);
        chi_hash.put(buf, 65);

        // receive chi's.
        vector<BIGNUM*> chi(chunk_len);
        vector<UniqueBN> p_chi(chunk_len);
        for (size_t i = 0; i < chunk_len; i++) {
            chi[i] = BN_new();
            p_chi[i].reset(chi[i]);
        }

        unsigned char chi_digest[Hash::DIGEST_SIZE];
        chi_hash.digest(chi_digest);
        block seed = zero_block;
        memcpy(&seed, chi_digest, sizeof(block));

        gen_chi(chi, seed);

        // generate linear combination of IT-MAC macs.
        BIGNUM* yMAC = rMAC;
        BIGNUM* tmpm = BN_new();
        UniqueBN p_tmpm(tmpm);
        for (size_t i = 0; i < chunk_len; i++) {
            BN_mod_mul(tmpm, chi[i], batch_aMACs[i], q, ctx);
            BN_mod_add(yMAC, yMAC, tmpm, q, ctx);
        }

        // compute linear combination of randomness and message.
        vector<BIGNUM*> scales(chi);
        vector<BIGNUM*> crnds(rnds);
        vector<BIGNUM*> msgs(msg);
        crnds.push_back(rnd_r);
        msgs.push_back(this->r);
        BIGNUM* one = BN_new();
        UniqueBN p_one(one);
        BN_set_word(one, 1);
        scales.push_back(one);

        BIGNUM* rnd_y = BN_new();
        UniqueBN p_rnd_y(rnd_y);
        BIGNUM* msg_y = BN_new();
        UniqueBN p_msg_y(msg_y);
        pc.linear_comb_rand(rnd_y, crnds, scales);
        pc.linear_comb_rand(msg_y, msgs, scales);

        // commit yMAC
        unsigned char yMAC_com[Hash::DIGEST_SIZE];
        PRG prg;
        block yMAC_seed = zero_block;
        prg.random_block(&yMAC_seed);
        Hash hash;
        hash.put(&yMAC_seed, sizeof(block));
        unsigned char arr[1000];
        int length = BN_bn2bin(yMAC, arr);
        hash.put(arr, length);
        hash.digest(yMAC_com);

        // send the commitment of yMAC
        io->send_data(yMAC_com, Hash::DIGEST_SIZE);
        // send the open of com_y (randomness and messages);
        send_bn(io, rnd_y);
        send_bn(io, msg_y);

        res = res and open(bMACs);

        io->send_block(&yMAC_seed, 1);
        send_bn(io, yMAC);

        return res;
    }
};

#endif // PRIMUS_COM_COV_H
