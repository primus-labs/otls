#ifndef UPSTREAM_GC_H__
#define UPSTREAM_GC_H__
// ============================================================================
// FULLPORT Phase 1B: otls GC 后端在上游 emp Backend 上的重写（非 offline 路径）。
// 上游把旧 CircuitExecution(门) + ProtocolExecution(feed/reveal) 合并成单 Backend；
// 且上游 emp-tool 的 HalfGate 只有 garbling, 无 2PC feed/reveal(OT 输入)——那部分
// 原在 emp-sh2pc / otls PrimusGen,此处用上游 IKNP(COT) 重写。
// garbling 复用上游 halfgates_garble/eval(+MITCCRH), 保电路语义等价(I3)。
// 安全 I1: IKNP malicious=true; OT delta = GC delta(COT 关联与 garbling 对齐)。
// ============================================================================
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "compat/primus_compat.h"

namespace otls_gc {
using namespace emp;

// otls 常量块约定: 全 0 = 公开 false, 全 1(minusone) = 公开 true。
inline bool gc_isZero(const block* b){ return cmpBlock(b, &zero_block, 1); }
inline bool gc_isOne (const block* b){ static const block one = all_one_block; return cmpBlock(b, &one, 1); }
// 上游 bool_to_block 用 bools_to_bits; 其逆是 bits_to_bools → OT delta 与 GC delta 一致(I1)
inline void gc_block_to_bool(bool* data, block b){ bits_to_bools(data, &b, 128); }

// ---- Generator (ALICE) ----------------------------------------------------
class PrimusGenBackend : public Backend {
 public:
  IOChannel* io;
  IKNP* ot;                 // 上游 IKNP COT (malicious)
  block delta, constant[2];
  MITCCRH<8> mitccrh;
  PRG shared_prg;
  block* buf; int top; int batch_size = 1024*16;
  int64_t gid = 0;
  Hash hash;
  bool own_ot;

  explicit PrimusGenBackend(IOChannel* io_, IKNP* in_ot=nullptr)
      : Backend(ALICE), io(io_) {
    // 1) delta(LSB=1) + 常量标签 + MITCCRH 种子 (= 上游 HalfGateGen 设置)
    block tmp[2]; PRG().random_block(tmp, 2);
    delta = set_bit(tmp[0], 0);
    PRG().random_block(constant, 2);
    io->send_block(constant, 2);
    constant[1] = constant[1] ^ delta;
    io->send_block(tmp+1, 1);
    mitccrh.setS(tmp[1]);
    // 2) OT sender, delta 对齐
    own_ot = (in_ot==nullptr);
    if (own_ot) { ot = new IKNP(ALICE, io, true);
      bool db[128]; gc_block_to_bool(db, delta); db[0]=true; ot->set_delta(db);
    } else ot = in_ot;
    buf = new block[batch_size];
    ot->send_cot(buf, batch_size); top = 0;
    // 3) shared_prg 种子
    block seed; PRG().random_block(&seed,1); io->send_block(&seed,1); shared_prg.reseed(&seed);
  }
  ~PrimusGenBackend(){ delete[] buf; if(own_ot) delete ot; }

  size_t wire_bytes() const override { return sizeof(block); }
  void public_label(void* out, bool b) override { *(block*)out = constant[b]; }
  void xor_gate(void* out, const void* l, const void* r) override { *(block*)out = *(const block*)l ^ *(const block*)r; }
  void not_gate(void* out, const void* in) override { *(block*)out = *(const block*)in ^ delta; }

  void and_gate(void* out, const void* l, const void* r) override {
    block a=*(const block*)l, b=*(const block*)r;
    // 常量优化 (otls OptHalfGateGen)
    if (gc_isZero(&a) || gc_isZero(&b)) { *(block*)out = zero_block; return; }
    if (gc_isOne(&a))  { *(block*)out = b; return; }
    if (gc_isOne(&b))  { *(block*)out = a; return; }
    block table[2];
    block res = halfgates_garble(a, a^delta, b, b^delta, delta, table, &mitccrh);
    io->send_block(table, 2);
    gid++;
    *(block*)out = res;
  }
  uint64_t num_and() override { return gid; }

  void refill(){ ot->send_cot(buf, batch_size); top=0; }

  void feed(void* out_, int party, const bool* b, size_t length) override {
    block* label = (block*)out_;
    if (party == ALICE) {
      shared_prg.random_block(label, length);
      for (size_t i=0;i<length;++i) if (b[i]) label[i] = label[i]^delta;
    } else {
      if ((int)length > batch_size) { ot->send_cot(label, length); }
      else {
        bool* tmp = new bool[length];
        if ((int)length > batch_size - top) {
          int filled = batch_size - top;
          memcpy(label, buf+top, filled*sizeof(block));
          refill();
          memcpy(label+filled, buf, (length-filled)*sizeof(block));
          top = length-filled;
        } else { memcpy(label, buf+top, length*sizeof(block)); top += length; }
        io->recv_data(tmp, length);
        for (size_t i=0;i<length;++i) if (tmp[i]) label[i]=label[i]^delta;
        delete[] tmp;
      }
    }
  }

  void reveal(bool* b, int party, const void* in_, size_t length) override {
    const block* label = (const block*)in_;
    for (size_t i=0;i<length;++i) {
      if (gc_isOne(&label[i])) b[i]=true;
      else if (gc_isZero(&label[i])) b[i]=false;
      else {
        bool lsb = getLSB(label[i]);
        if (party==BOB || party==PUBLIC) { io->send_data(&lsb,1); b[i]=false; }
        else { bool t; io->recv_data(&t,1); b[i]=(t!=lsb); }
      }
    }
    if (party==PUBLIC) {
      io->recv_data(b, length);
      unsigned char td[Hash::DIGEST_SIZE], rh[Hash::DIGEST_SIZE];
      io->recv_data(rh, Hash::DIGEST_SIZE);
      for (size_t i=0;i<length;i++){
        block blk = (gc_isZero(&label[i])||gc_isOne(&label[i])) ? label[i]
                    : (b[i] ? label[i]^delta : label[i]);
        hash.put_block(&blk,1);
      }
      hash.digest(td);
      if (memcmp(td, rh, Hash::DIGEST_SIZE)!=0) error("Evaluator cheated in revealing msgs!");
    }
  }
};

// ---- Evaluator (BOB) ------------------------------------------------------
class PrimusEvaBackend : public Backend {
 public:
  IOChannel* io;
  IKNP* ot;
  block constant[2];
  MITCCRH<8> mitccrh;
  PRG shared_prg;
  block* buf; bool* sel; int top; int batch_size = 1024*16;
  int64_t gid = 0;
  Hash hash;
  bool own_ot;

  explicit PrimusEvaBackend(IOChannel* io_, IKNP* in_ot=nullptr)
      : Backend(BOB), io(io_) {
    io->recv_block(constant, 2);
    block s; io->recv_block(&s, 1); mitccrh.setS(s);
    own_ot = (in_ot==nullptr);
    if (own_ot) ot = new IKNP(BOB, io, true); else ot = in_ot;
    buf = new block[batch_size]; sel = new bool[batch_size];
    PRG().random_bool(sel, batch_size); ot->recv_cot(buf, sel, batch_size); top = 0;
    block seed; io->recv_block(&seed,1); shared_prg.reseed(&seed);
  }
  ~PrimusEvaBackend(){ delete[] buf; delete[] sel; if(own_ot) delete ot; }

  size_t wire_bytes() const override { return sizeof(block); }
  void public_label(void* out, bool b) override { *(block*)out = constant[b]; }
  void xor_gate(void* out, const void* l, const void* r) override { *(block*)out = *(const block*)l ^ *(const block*)r; }
  void not_gate(void* out, const void* in) override { *(block*)out = *(const block*)in; }

  void and_gate(void* out, const void* l, const void* r) override {
    block a=*(const block*)l, b=*(const block*)r;
    if (gc_isZero(&a) || gc_isZero(&b)) { *(block*)out = zero_block; return; }
    if (gc_isOne(&a))  { *(block*)out = b; return; }
    if (gc_isOne(&b))  { *(block*)out = a; return; }
    block table[2]; io->recv_block(table, 2);
    *(block*)out = halfgates_eval(a, b, table, &mitccrh);
    gid++;
  }
  uint64_t num_and() override { return gid; }

  void refill(){ PRG().random_bool(sel, batch_size); ot->recv_cot(buf, sel, batch_size); top=0; }

  void feed(void* out_, int party, const bool* b, size_t length) override {
    block* label = (block*)out_;
    if (party == ALICE) {
      shared_prg.random_block(label, length);  // Alice 输入: Bob 用同 prg 占位(实际值由 garbling 流转)
    } else {
      // Bob 私有输入: OT 取标签, 差异向量发给 Alice
      bool* d = new bool[length];
      if ((int)length > batch_size) {
        bool* bits = new bool[length]; PRG().random_bool(bits, length);
        ot->recv_cot(label, bits, length);
        for (size_t i=0;i<length;++i){ d[i]=bits[i]^b[i]; }
        delete[] bits;
      } else {
        bool* bits = new bool[length];
        if ((int)length > batch_size - top) {
          int filled = batch_size - top;
          memcpy(label, buf+top, filled*sizeof(block)); memcpy(bits, sel+top, filled);
          refill();
          memcpy(label+filled, buf, (length-filled)*sizeof(block)); memcpy(bits+filled, sel, length-filled);
          top = length-filled;
        } else { memcpy(label, buf+top, length*sizeof(block)); memcpy(bits, sel+top, length); top += length; }
        for (size_t i=0;i<length;++i) d[i]=bits[i]^b[i];
        delete[] bits;
      }
      io->send_data(d, length);
      delete[] d;
    }
  }

  void reveal(bool* b, int party, const void* in_, size_t length) override {
    const block* label = (const block*)in_;
    for (size_t i=0;i<length;++i) {
      if (gc_isOne(&label[i])) b[i]=true;
      else if (gc_isZero(&label[i])) b[i]=false;
      else {
        bool lsb = getLSB(label[i]);
        if (party==BOB || party==PUBLIC) { bool t; io->recv_data(&t,1); b[i]=(t!=lsb); }
        else { io->send_data(&lsb,1); b[i]=false; }
      }
    }
    if (party==PUBLIC) {
      io->send_data(b, length);
      unsigned char td[Hash::DIGEST_SIZE];
      for (size_t i=0;i<length;i++){ block blk=label[i]; hash.put_block(&blk,1); }
      hash.digest(td);
      io->send_data(td, Hash::DIGEST_SIZE);
    }
  }
};

}  // namespace otls_gc
#endif
