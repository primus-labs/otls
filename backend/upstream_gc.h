#ifndef UPSTREAM_GC_H__
#define UPSTREAM_GC_H__
// ============================================================================
// FULLPORT Phase 1B: rewrite of the otls GC backend on top of the upstream emp
// Backend (non-offline path).
// Upstream merges the old CircuitExecution (gates) + ProtocolExecution
// (feed/reveal) into a single Backend; and the upstream emp-tool HalfGate only
// does garbling, with no 2PC feed/reveal (OT inputs) -- that part originally
// lived in emp-sh2pc / otls PrimusGen, and is rewritten here using upstream
// IKNP (COT).
// garbling reuses the otls garble_gate_*_halfgates (PRP fixed-key, gid-keyed),
// byte-identical to the fork OptHalfGate -- NOT the upstream MITCCRH path, whose
// batched state diverged gen/eva on some circuits (e.g. div_full). Preserves
// circuit semantics equivalence (I3).
// Security I1: IKNP malicious=true; OT delta = GC delta (COT correlation aligned
// with garbling).
// ============================================================================
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "compat/primus_compat.h"
#include "backend/bn_utils.h"   // garble_gate_garble/eval_halfgates (fixed key + explicit gid, independent of offline/online phase)

namespace otls_gc {
using namespace emp;

// otls constant-block convention: all 0 = public false, all 1 (minusone) = public true.
// Public constant wires use a sentinel (zero/all_one), and every gate (and/xor/not/reveal)
// special-cases them -> public computation stays in sentinel space and never collides
// with a random private label. This is the core design of otls OptHalfGate (I3).
inline bool gc_isZero(const block* b){ return cmpBlock(b, &zero_block, 1); }
inline bool gc_isOne (const block* b){ static const block one = all_one_block; return cmpBlock(b, &one, 1); }
// Upstream bool_to_block uses bools_to_bits; its inverse is bits_to_bools -> OT delta matches GC delta (I1)
inline void gc_block_to_bool(bool* data, block b){ bits_to_bools(data, &b, 128); }
// Substitute used when a private-wire XOR accidentally lands on a sentinel (zero/delta): a fixed non-sentinel block, identical on both gen/eva sides.
static const block kFixPoint = makeBlock(0x9e3779b97f4a7c15LL, 0x1234567890abcdefLL);

// ---- Generator (ALICE) ----------------------------------------------------
class PrimusGenBackend : public Backend {
 public:
  IOChannel* io;
  IKNP* ot;                 // upstream IKNP COT (malicious)
  block delta, constant[2];
  block fix_point = kFixPoint;
  PRP prp;   // FULLPORT: garbling hash = otls OptHalfGateGen's PRP (fixed key), NOT upstream MITCCRH — must be byte-identical to the fork's garble_gate_*_halfgates for gen/eva label consistency.
  PRG shared_prg;
  block* buf; int top; int batch_size = 1024*16;
  int64_t gid = 0;
  Hash hash;
  bool own_ot;

  explicit PrimusGenBackend(IOChannel* io_, IKNP* in_ot=nullptr)
      : Backend(ALICE), io(io_) {
    // 1) delta (LSB=1) + constant labels (= otls OptHalfGateGen setup; PRP is fixed-key, no seed exchange)
    block tmp[2]; PRG().random_block(tmp, 2);
    delta = set_bit(tmp[0], 0);
    PRG().random_block(constant, 2);
    io->send_block(constant, 2);
    constant[1] = constant[1] ^ delta;
    // 2) OT sender, delta aligned
    own_ot = (in_ot==nullptr);
    if (own_ot) { ot = new IKNP(ALICE, io, true);
      bool db[128]; gc_block_to_bool(db, delta); db[0]=true; ot->set_delta(db);
    } else ot = in_ot;
    buf = new block[batch_size];
    ot->send_cot(buf, batch_size); top = 0;
    // 3) shared_prg seed
    block seed; PRG().random_block(&seed,1); io->send_block(&seed,1); shared_prg.reseed(&seed);
  }
  ~PrimusGenBackend(){ delete[] buf; if(own_ot) delete ot; }

  size_t wire_bytes() const override { return sizeof(block); }
  // FULLPORT: public constant = sentinel (otls OptHalfGateGen), not/xor/and all special-cased, see kFixPoint comment.
  bool isDelta(const block& b){ __m128i n = b ^ delta; return _mm_testz_si128(n, n); }
  void public_label(void* out, bool b) override { *(block*)out = b ? all_one_block : zero_block; }

  void not_gate(void* out, const void* in) override {
    block a = *(const block*)in;
    if (gc_isZero(&a))      *(block*)out = all_one_block;  // !false = true
    else if (gc_isOne(&a))  *(block*)out = zero_block;     // !true  = false
    else                    *(block*)out = a ^ delta;
  }

  void xor_gate(void* out, const void* l, const void* r) override {
    block a = *(const block*)l, b = *(const block*)r;
    if (gc_isOne(&a))       { not_gate(out, &b); return; }
    else if (gc_isOne(&b))  { not_gate(out, &a); return; }
    else if (gc_isZero(&a)) { *(block*)out = b; return; }
    else if (gc_isZero(&b)) { *(block*)out = a; return; }
    block res = a ^ b;
    if (gc_isZero(&res))    { *(block*)out = fix_point; return; }       // private wire hits 0 -> substitute
    if (isDelta(res))       { *(block*)out = fix_point ^ delta; return; }   // mirror for the delta sentinel
    *(block*)out = res;
  }

  void and_gate(void* out, const void* l, const void* r) override {
    block a=*(const block*)l, b=*(const block*)r;
    // constant optimization (otls OptHalfGateGen)
    if (gc_isZero(&a) || gc_isZero(&b)) { *(block*)out = zero_block; return; }
    if (gc_isOne(&a))  { *(block*)out = b; return; }
    if (gc_isOne(&b))  { *(block*)out = a; return; }
    block out2[2], table[2];   // byte-identical to otls OptHalfGateGen::and_gate
    garble_gate_garble_halfgates(a, a^delta, b, b^delta, &out2[0], &out2[1], delta, table, gid++, &prp.aes);
    io->send_block(table, 2);
    *(block*)out = out2[0];
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
  block fix_point = kFixPoint;
  PRP prp;   // FULLPORT: same fixed-key PRP as the gen (otls OptHalfGateEva), NOT MITCCRH.
  PRG shared_prg;
  block* buf; bool* sel; int top; int batch_size = 1024*16;
  int64_t gid = 0;
  Hash hash;
  bool own_ot;

  explicit PrimusEvaBackend(IOChannel* io_, IKNP* in_ot=nullptr)
      : Backend(BOB), io(io_) {
    io->recv_block(constant, 2);
    own_ot = (in_ot==nullptr);
    if (own_ot) ot = new IKNP(BOB, io, true); else ot = in_ot;
    buf = new block[batch_size]; sel = new bool[batch_size];
    PRG().random_bool(sel, batch_size); ot->recv_cot(buf, sel, batch_size); top = 0;
    block seed; io->recv_block(&seed,1); shared_prg.reseed(&seed);
  }
  ~PrimusEvaBackend(){ delete[] buf; delete[] sel; if(own_ot) delete ot; }

  size_t wire_bytes() const override { return sizeof(block); }
  // FULLPORT: public constant = sentinel (otls OptHalfGateEva); on the eva side not does not flip (identity), and public AND goes through bitwise AND.
  void public_label(void* out, bool b) override { *(block*)out = b ? all_one_block : zero_block; }

  void not_gate(void* out, const void* in) override {
    block a = *(const block*)in;
    if (gc_isZero(&a))      *(block*)out = all_one_block;
    else if (gc_isOne(&a))  *(block*)out = zero_block;
    else                    *(block*)out = a;   // eva: no flip (the difference is encoded by gen flipping the 0-label)
  }

  void xor_gate(void* out, const void* l, const void* r) override {
    block a = *(const block*)l, b = *(const block*)r;
    if (gc_isOne(&a))       { not_gate(out, &b); return; }
    else if (gc_isOne(&b))  { not_gate(out, &a); return; }
    else if (gc_isZero(&a)) { *(block*)out = b; return; }
    else if (gc_isZero(&b)) { *(block*)out = a; return; }
    block res = a ^ b;
    if (gc_isZero(&res))    { *(block*)out = fix_point; return; }
    *(block*)out = res;
  }

  void and_gate(void* out, const void* l, const void* r) override {
    block a=*(const block*)l, b=*(const block*)r;
    // public input: bitwise AND (zero&x=zero, all_one&x=x) = otls OptHalfGateEva
    if (gc_isZero(&a) || gc_isOne(&a) || gc_isZero(&b) || gc_isOne(&b)) {
      *(block*)out = _mm_and_si128(a, b); return;
    }
    block out2, table[2]; io->recv_block(table, 2);   // byte-identical to otls OptHalfGateEva::and_gate
    garble_gate_eval_halfgates(a, b, &out2, table, gid++, &prp.aes);
    *(block*)out = out2;
  }
  uint64_t num_and() override { return gid; }

  void refill(){ PRG().random_bool(sel, batch_size); ot->recv_cot(buf, sel, batch_size); top=0; }

  void feed(void* out_, int party, const bool* b, size_t length) override {
    block* label = (block*)out_;
    if (party == ALICE) {
      shared_prg.random_block(label, length);  // Alice input: Bob uses the same prg as a placeholder (the actual value flows through garbling)
    } else {
      // Bob private input: fetch labels via OT, send the difference vector to Alice
      if ((int)length > batch_size) {
        // large path: OT directly on the REAL choice bits and send NO correction --
        // mirrors PrimusGenBackend::feed's send_cot-only large path (otls primus_eva.h
        // line 35-36 / primus_gen.h line 40-42). Using random bits + send_data here
        // would desync the channel (gen never recv_data's) and give Bob labels for the
        // wrong bits.
        ot->recv_cot(label, b, length);
      } else {
        bool* d = new bool[length];
        bool* bits = new bool[length];
        if ((int)length > batch_size - top) {
          int filled = batch_size - top;
          memcpy(label, buf+top, filled*sizeof(block)); memcpy(bits, sel+top, filled);
          refill();
          memcpy(label+filled, buf, (length-filled)*sizeof(block)); memcpy(bits+filled, sel, length-filled);
          top = length-filled;
        } else { memcpy(label, buf+top, length*sizeof(block)); memcpy(bits, sel+top, length); top += length; }
        for (size_t i=0;i<length;++i) d[i]=bits[i]^b[i];
        io->send_data(d, length);   // correction only in the buffered (small) path
        delete[] bits;
        delete[] d;
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

// Fixed seed: both gen/eva sides use the same value to deterministically derive public constant labels (consistent without communication), replacing the fork's fix_key.
static const block kFixKey = makeBlock(0x2018120720190101LL, 0x70616462656e6368LL);

// ===========================================================================
// offline / online split (mpctls: garble the whole circuit offline, replay with real inputs online).
// garbling uses otls garble_gate_*_halfgates with fixed key + explicit gid (phase-independent, not the upstream MITCCRH);
// constants use PRG(fix_key) -> the offline and online phases agree without communication.
// ===========================================================================

// ---- Offline Generator (ALICE): garble the whole circuit, store out_labels, send tables ----
class OfflineGenBackend : public Backend {
 public:
  IOChannel* io; int64_t gid=0; block delta, constant[2]; PRP prp;
  std::vector<block> out_labels; block seed; PRG prg;
  explicit OfflineGenBackend(IOChannel* io_): Backend(ALICE), io(io_){
    block t; PRG().random_block(&t,1); delta = _mm_or_si128(makeBlock(0L,1L), t);
    PRG pg(&otls_gc::kFixKey); pg.random_block(constant,2); constant[1]^=delta;
    PRG().random_block(&seed,1); prg=PRG(&seed);
  }
  size_t wire_bytes() const override { return sizeof(block); }
  void public_label(void* o, bool b) override { *(block*)o = b?constant[1]:constant[0]; }
  void xor_gate(void* o, const void* l, const void* r) override { *(block*)o=*(const block*)l ^ *(const block*)r; }
  void not_gate(void* o, const void* i) override { *(block*)o=*(const block*)i ^ delta; }
  void and_gate(void* o, const void* l, const void* r) override {
    block a=*(const block*)l, b=*(const block*)r, out[2], table[2];
    garble_gate_garble_halfgates(a, a^delta, b, b^delta, &out[0], &out[1], delta, table, gid++, &prp.aes);
    io->send_block(table,2); out_labels.push_back(out[0]); *(block*)o=out[0];
  }
  uint64_t num_and() override { return gid; }
  // FULLPORT: upstream Integer(.,PUBLIC) also goes through feed(), but public wires must use public labels and **must not consume prg**
  // (otherwise the offline/online public feed counts differ -> prg gets misaligned). Only private (ALICE/BOB) inputs fetch a prg 0-label.
  void feed(void* o, int party, const bool* b, size_t length) override {
    block* L=(block*)o;
    if (party==PUBLIC){ for (size_t i=0;i<length;++i) L[i]=b[i]?constant[1]:constant[0]; return; }
    prg.random_block(L, length);
  }
  void reveal(bool*, int party, const void* in_, size_t length) override {
    if (party==PUBLIC){ const block* L=(const block*)in_;
      for (size_t i=0;i<length;++i){ bool lsb=getLSB(L[i]); io->send_data(&lsb,1);} }
  }
};

// ---- Offline Evaluator (BOB): recv + store GC tables, recv pub LSBs ----
class OfflineEvaBackend : public Backend {
 public:
  IOChannel* io; int64_t gid=0; std::vector<block> GC; std::vector<bool> pub_values;
  explicit OfflineEvaBackend(IOChannel* io_): Backend(BOB), io(io_){}
  size_t wire_bytes() const override { return sizeof(block); }
  void public_label(void* o, bool) override { *(block*)o=zero_block; }
  void xor_gate(void* o, const void*, const void*) override { *(block*)o=zero_block; }
  void not_gate(void* o, const void*) override { *(block*)o=zero_block; }
  void and_gate(void* o, const void*, const void*) override {
    block table[2]; io->recv_block(table,2); GC.push_back(table[0]); GC.push_back(table[1]); gid++; *(block*)o=zero_block;
  }
  uint64_t num_and() override { return gid; }
  void feed(void*, int, const bool*, size_t) override {}
  void reveal(bool*, int party, const void*, size_t length) override {
    if (party==PUBLIC) for (size_t i=0;i<length;++i){ bool t=false; io->recv_data(&t,1); pub_values.push_back(t);}
  }
};

// ---- Online Generator (ALICE): replay out_labels, real inputs via standard OT ----
class OnlineGenBackend : public Backend {
 public:
  IOChannel* io; IKNP* ot; int64_t gid=0; block delta, constant[2];
  std::vector<block> out_labels; PRG prg; Hash hash; bool own_ot;
  explicit OnlineGenBackend(IOChannel* io_, IKNP* in_ot=nullptr): Backend(ALICE), io(io_){
    PRG pg(&otls_gc::kFixKey); pg.random_block(constant,2);  // same as offline (constant[1]^=delta applied after sync)
    own_ot=(in_ot==nullptr); ot = own_ot? new IKNP(ALICE,io,true): in_ot;
  }
  ~OnlineGenBackend(){ if(own_ot) delete ot; }
  void set_seed(block s){ prg=PRG(&s); }
  void set_delta(block d){ delta=d; constant[1]^=delta; }  // called once after sync
  size_t wire_bytes() const override { return sizeof(block); }
  void public_label(void* o, bool b) override { *(block*)o=b?constant[1]:constant[0]; }
  void xor_gate(void* o, const void* l, const void* r) override { *(block*)o=*(const block*)l ^ *(const block*)r; }
  void not_gate(void* o, const void* i) override { *(block*)o=*(const block*)i ^ delta; }
  void and_gate(void* o, const void*, const void*) override { *(block*)o=out_labels[gid++]; }
  uint64_t num_and() override { return gid; }
  void feed(void* o, int party, const bool* b, size_t length) override {
    block* label=(block*)o;
    // FULLPORT: public wires use public labels and neither consume prg nor go through OT (aligned with offline, see OfflineGen.feed).
    if (party==PUBLIC){ for (size_t i=0;i<length;++i) label[i]=b[i]?constant[1]:constant[0]; return; }
    block* l2=new block[length];
    prg.random_block(label,length);
    for (size_t i=0;i<length;++i) l2[i]=label[i]^delta;
    if (party==ALICE){ for (size_t i=0;i<length;++i) io->send_block(b[i]?l2+i:label+i,1); }
    else ot->send(label, l2, length);   // standard 1-out-of-2 OT
    delete[] l2;
  }
  void reveal(bool* b, int party, const void* in_, size_t length) override {
    const block* L=(const block*)in_;
    for (size_t i=0;i<length;++i){ bool lsb=getLSB(L[i]);
      if (party==BOB){ io->send_data(&lsb,1); b[i]=false; }
      else if (party==ALICE){ bool t; io->recv_data(&t,1); b[i]=(t!=lsb); } }
    if (party==PUBLIC){ io->recv_data(b,length);
      unsigned char td[Hash::DIGEST_SIZE], rh[Hash::DIGEST_SIZE]; io->recv_data(rh,Hash::DIGEST_SIZE);
      for (size_t i=0;i<length;i++){ block blk=b[i]?L[i]^delta:L[i]; hash.put_block(&blk,1);}
      hash.digest(td);      if (memcmp(td,rh,Hash::DIGEST_SIZE)!=0) error("Evaluator cheated in revealing msgs!"); }
  }
};

// ---- Online Evaluator (BOB): evaluate using GC tables, real inputs via standard OT, reveal using pub_values ----
class OnlineEvaBackend : public Backend {
 public:
  IOChannel* io; IKNP* ot; int64_t gid=0; PRP prp; block constant[2];
  std::vector<block> GC; std::vector<bool> pub_values; uint64_t reveal_counter=0; Hash hash; bool own_ot;
  explicit OnlineEvaBackend(IOChannel* io_, IKNP* in_ot=nullptr): Backend(BOB), io(io_){
    PRG pg(&otls_gc::kFixKey); pg.random_block(constant,2);
    own_ot=(in_ot==nullptr); ot = own_ot? new IKNP(BOB,io,true): in_ot;
  }
  ~OnlineEvaBackend(){ if(own_ot) delete ot; }
  size_t wire_bytes() const override { return sizeof(block); }
  void public_label(void* o, bool b) override { *(block*)o=b?constant[1]:constant[0]; }
  void xor_gate(void* o, const void* l, const void* r) override { *(block*)o=*(const block*)l ^ *(const block*)r; }
  void not_gate(void* o, const void* i) override { *(block*)o=*(const block*)i; }
  void and_gate(void* o, const void* l, const void* r) override {
    block a=*(const block*)l, b=*(const block*)r, out, table[2];
    table[0]=GC[gid*2]; table[1]=GC[gid*2+1];
    garble_gate_eval_halfgates(a, b, &out, table, gid++, &prp.aes); *(block*)o=out;
  }
  uint64_t num_and() override { return gid; }
  void feed(void* o, int party, const bool* b, size_t length) override {
    block* label=(block*)o;
    // FULLPORT: public wires use public labels and do not go through OT (aligned with OnlineGen.feed).
    if (party==PUBLIC){ for (size_t i=0;i<length;++i) label[i]=b[i]?constant[1]:constant[0]; return; }
    if (party==ALICE) io->recv_block(label,length);
    else ot->recv(label, b, length);
  }
  void reveal(bool* b, int party, const void* in_, size_t length) override {
    const block* L=(const block*)in_;
    for (size_t i=0;i<length;++i){ bool lsb=getLSB(L[i]), t;
      if (party==BOB){ io->recv_data(&t,1); b[i]=(t!=lsb); }
      else if (party==ALICE){ io->send_data(&lsb,1); b[i]=false; }
      else if (party==PUBLIC){ b[i]=(pub_values[reveal_counter++]!=lsb); } }
    if (party==PUBLIC){      io->send_data(b,length);
      unsigned char td[Hash::DIGEST_SIZE]; hash.hash_once(td, L, length*sizeof(block)); io->send_data(td,Hash::DIGEST_SIZE); }
  }
};

// Move the offline precomputed state into the online backend
inline void sync_offline_online(Backend* offline, Backend* online, int party){
  if (party==ALICE){
    auto* off=(OfflineGenBackend*)offline; auto* on=(OnlineGenBackend*)online;
    on->set_seed(off->seed); on->set_delta(off->delta); on->out_labels = off->out_labels;  } else {
    auto* off=(OfflineEvaBackend*)offline; auto* on=(OnlineEvaBackend*)online;
    on->GC = off->GC; on->pub_values = off->pub_values;  }
}

}  // namespace otls_gc
#endif
