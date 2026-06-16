#ifndef PRIMUS_COMPAT_H
#define PRIMUS_COMPAT_H
// ============================================================================
// Compat shim — SESSION-API era (branch emp-zk-fullport).
//
// Upstream emp-zk-bool dropped the global backend (CircuitExecution /
// ProtocolExecution / `backend`) in favour of a ZKBoolSession that owns the
// engine and is the I/O boundary, and dropped UnsignedInt_T<block> /
// BristolFormat for the context-bound typed layer (UInt_T<Ctx,N> /
// execute_program). The fork's otls code is written against free-standing
// `Integer(width,value,party)` + `.bits` + `.reveal()` + a global backend, so
// this shim bridges the two with:
//
//   * g_zk  — a thread-local "active" ZKBoolSession*, the migration stand-in for
//             the removed global backend. setup_proxy_protocol() installs it;
//             every Integer/circuit op reaches the engine through it. Mirrors
//             the fork's single global backend (single-threaded migration).
//   * Integer — a subclass of UInt_T<ZKBoolContext,0> (runtime width, full
//             arithmetic) whose construction / reveal / .bits route through the
//             active session (input_bits / reveal_bits). LSB-first byte/bit
//             ordering is preserved → proven relation unchanged (invariant I3).
//
// Circuit evaluation (AES key-schedule / AES-enc) moves from BristolFormat to
// execute_program over builtin .empbc circuits — handled in cipher/utils.h.
// ============================================================================
#include "emp-tool/emp-tool.h"
#include "emp-tool/execution/backend.h"   // emp::Backend + global `extern Backend* backend`
#include "emp-zk/emp-zk.h"
#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <functional>
#include <type_traits>
#include <cmath>       // ceil, log2 — fork secret-shift loop bound (integer.hpp:317/324)
#include <algorithm>   // std::min — fork secret-shift loop bound

namespace emp {

// ============================================================================
// UNIFIED execution model: one Integer, runtime-swappable backend (GC or ZK).
//
// The new emp-tool's legacy "<block>-wire" UnsignedInt_T is dead (renamed
// UInt_T<Ctx,N>, block aliases dangle), so we rebuild the fork's "switch the
// backend under one Integer" model on the surviving CONTEXT layer: a
// DynamicContext (a BooleanContext) whose gate ops dispatch to the GLOBAL
// emp::backend (emp::Backend*) — the single pointer that switch.h / backend.h /
// upstream_gc.h / the OLE/E2F/AEAD sub-protocols all already share. GC backends
// are emp::Backend subclasses (upstream_gc.h); ZK is the ZKBackend adapter below.
// switch_to_gc/zk swap emp::backend. Integer = UInt_T<DynamicContext,0>.
// (Measured: per-gate virtual dispatch costs ~0 vs an inlined context.)
// ============================================================================

inline thread_local ZKBoolBase* g_zk_engine = nullptr;       // ZK engine (for check_zero's auth_hash); null under GC

// DynamicContext — a BooleanContext (Wire = ZKWire = one block) forwarding every
// gate to the global emp::backend (out-param void* dispatch). Single instance.
struct DynamicContext {
    using Wire = ZKWire;
    Wire public_bit(bool b)       { ZKWire o; backend->public_label(&o.label, b);                 return o; }
    Wire and_gate(Wire a, Wire b) { ZKWire o; backend->and_gate(&o.label, &a.label, &b.label);    return o; }
    Wire xor_gate(Wire a, Wire b) { ZKWire o; backend->xor_gate(&o.label, &a.label, &b.label);    return o; }
    Wire not_gate(Wire a)         { ZKWire o; backend->not_gate(&o.label, &a.label);              return o; }
};
static_assert(BooleanContext<DynamicContext>, "DynamicContext must model emp::BooleanContext");
inline DynamicContext g_dyn_ctx;
inline DynamicContext& zk_ctx() { return g_dyn_ctx; }
inline uint64_t num_and() { return backend ? backend->num_and() : 0; }
// The active ZK engine, exposing auth_hash (the output-MAC transcript) for check_zero.
inline ZKBoolBase* get_bool_backend() { return g_zk_engine; }

// ZK backend adapter: makes the new emp-zk-bool ZKBoolBase look like an
// emp::Backend, so the unified Integer/circuit code runs in ZK. Forwards to the
// live engine (SilentFerret COT + QuickSilver soundness preserved).
struct ZKBackend : public Backend {
    ZKBoolBase* e;
    ZKBackend(ZKBoolBase* e_, int party) : Backend(party), e(e_) {}
    size_t wire_bytes() const override { return sizeof(block); }
    void and_gate(void* o, const void* l, const void* r) override { *(block*)o = e->and_block(*(const block*)l, *(const block*)r); }
    void xor_gate(void* o, const void* l, const void* r) override { *(block*)o = e->xor_block(*(const block*)l, *(const block*)r); }
    void not_gate(void* o, const void* i)                override { *(block*)o = e->not_block(*(const block*)i); }
    void public_label(void* o, bool b)                   override { *(block*)o = e->public_block(b); }
    void feed(void* o, int p, const bool* in, size_t n)  override { e->feed_bits((block*)o, p, in, n); }
    void reveal(bool* o, int p, const void* in, size_t n)override { e->reveal_bits(o, p, (const block*)in, n); }
    uint64_t num_and() override { return e->num_and(); }
};

// FULLPORT: fork get_bool_delta() -> the active ZK engine's Δ (ZKBoolBase::delta;
// verifier-side global secret). Used by aead_izk's verifier path. ZK only.
inline block get_bool_delta() { return g_zk_engine ? g_zk_engine->delta : zero_block; }

// FULLPORT: fork emp-tool FunctionWrapperV3 (emp-tool/utils/function_wrapper.{h,cpp}).
// Upstream emp-tool dropped function_wrapper, so reproduce its EXACT control flow here.
// Fork FunctionSafeRun did:
//   try { execute(); }                              // execute() == tryFn()
//   catch (std::exception& e) { catchException(e.what()); }    // catchException(m)==catchFn(m)
//   catch (...)                { catchException("[OtherError]unknown reason"); }
// catchFn is invoked from INSIDE the active catch handler, so a bare `throw;` inside the
// caller's catch lambda re-propagates the ORIGINAL exception (parser.cpp:658/:709 rethrow
// unless the message contains "[FindKeyError]"). Byte-identical control flow & messages.
struct FunctionWrapperV3 {
    std::function<void()>            tryFn;
    std::function<void(const char*)> catchFn;
    FunctionWrapperV3(std::function<void()> t, std::function<void(const char*)> c)
        : tryFn(std::move(t)), catchFn(std::move(c)) {}
    void operator()() {
        try {
            tryFn();
        } catch (std::exception& e) {
            catchFn(e.what());
        } catch (...) {
            catchFn("[OtherError]unknown reason");
        }
    }
};

// FULLPORT: fork emp-tool FunctionWrapperV2 (emp-tool/utils/function_wrapper.h:38-82
// + static member def function_wrapper.cpp:4 + FunctionSafeRun function_wrapper.cpp:9-20).
// STATEFUL exception-capturing wrapper used by mpc_tls finalize path:
//   * execute(): runs fn() ONLY if no prior exception message was recorded.
//   * catchException(): records the message (does NOT rethrow).
//   * operator(): try{execute()} catch(std::exception&e){catchException(e.what())}
//                 catch(...){catchException("[OtherError]unknown reason")}  (FunctionSafeRun inlined).
//   * static getExceptionMsg(): reads the recorded message; check_exception_msg() lazily
//     new std::string("") so the pointer is never null.
// Native port is single-threaded (no THREADING) -> plain inline static (not __thread).
// Static member defined inline so it links without the dropped function_wrapper.cpp.
// (Like the V3 shim above, this is a plain struct: upstream dropped AbstractFunctionWrapper,
//  so operator() inlines FunctionSafeRun's try/catch directly instead of virtual dispatch.)
struct FunctionWrapperV2 {
   public:
    FunctionWrapperV2(std::function<void()> f) { fn = f; }
    void operator()() {
        try {
            execute();
        } catch (std::exception& e) {
            catchException(e.what());
        } catch (...) {
            catchException("[OtherError]unknown reason");
        }
    }

    void execute() {
        check_exception_msg();
        if (this->exceptionMsg->empty()) {
            fn();
        }
    }

    void catchException(const char* e) {
        check_exception_msg();
        *exceptionMsg = e;
    }

    static std::string getExceptionMsg() {
        check_exception_msg();
        return *exceptionMsg;
    }
    static void setExceptionMsgPtr(std::string* ptr) { exceptionMsg = ptr; }

   private:
    static void check_exception_msg() {
        if (exceptionMsg == nullptr) {
            exceptionMsg = new std::string("");
        }
    }

    std::function<void()> fn;
    static inline std::string* exceptionMsg = nullptr;
};

#define SET_FINALIZE_IO_EXCEPTION(exceptionMsg)                                 \
    do {                                                                        \
        FunctionWrapperV2([](){}).catchException(exceptionMsg);                 \
    } while(false);

// FULLPORT: fork emp-tool CHECK_FINALIZE_IO_EXCEPTION (function_wrapper.h:125-131).
// Reads the FunctionWrapperV2 static exception message and rethrows it as a
// runtime_error if non-empty (the finalize-path error surfacing pado.cpp:182 /
// client.cpp:1123 / client_api.cpp:43 use). Byte-identical control flow; std::-
// qualified so it does not depend on a `using namespace std` at the call site.
#define CHECK_FINALIZE_IO_EXCEPTION()                                           \
    do {                                                                        \
        std::string exceptionMsg = FunctionWrapperV2::getExceptionMsg();        \
        if (!exceptionMsg.empty()) {                                            \
            throw std::runtime_error(exceptionMsg);                             \
        }                                                                       \
    } while(false)

// ZK backend lifecycle shims (the removed emp-zk setup_zk_bool/finalize_zk_bool/
// sync_zk_bool). setup installs the ZKBackend as the global backend; switch.h and
// setup_proxy_protocol both go through these.
inline thread_local ZKBoolSession* g_zk_owned = nullptr;
inline void setup_zk_bool(BoolIO* io, int party, int64_t expected_cots = 0) {
    g_zk_owned   = new ZKBoolSession(io, party, expected_cots);
    g_zk_engine  = &g_zk_owned->engine();
    backend      = new ZKBackend(g_zk_engine, party);
}
inline void finalize_zk_bool() {
    if (g_zk_owned) {
        g_zk_owned->finalize();
        delete g_zk_owned;   g_zk_owned = nullptr;
        delete backend;      backend = nullptr;
        g_zk_engine = nullptr;
    }
}
inline void sync_zk_bool() { if (g_zk_owned) g_zk_owned->flush(); }

// Single authenticated bit (fork's block-layer Bit), over the DynamicContext.
// Operators return Bit (not the base) so chained results keep reveal()/.bit;
// converts to ZKWire so Integer.bits.push_back(Bit) works.
class Bit : public Bit_T<DynamicContext> {
    using Base = Bit_T<DynamicContext>;
   public:
    Bit() : Base(g_dyn_ctx, ZKWire{}) {}
    Bit(const Base& b) : Base(b) {}
    Bit(const ZKWire& zw) : Base(g_dyn_ctx, zw) {}                 // wrap a raw authenticated wire (fork Bit was block-constructible)
    Bit(bool v, int party = PUBLIC) : Base(g_dyn_ctx, ZKWire{}) { // default party=PUBLIC (fork Bit(bool,party=PUBLIC))
        if (party == PUBLIC) backend->public_label(&w.label, v);
        else { block o; backend->feed(&o, party, &v, 1); w = ZKWire{ o }; }
    }
    operator ZKWire() const { return w; }                       // Integer.bits.push_back(Bit)
    Bit operator&(const Base& o) const { return Bit(Base::operator&(o)); }
    Bit operator^(const Base& o) const { return Bit(Base::operator^(o)); }
    Bit operator|(const Base& o) const { return Bit(Base::operator|(o)); }
    Bit operator!() const              { return Bit(Base::operator!()); }
    template <class T = bool>
    T reveal(int party = PUBLIC) const {
        bool r; backend->reveal(&r, party, &w.label, 1);
        if constexpr (std::is_same_v<T, std::string>) return r ? "true" : "false";
        else return (T)r;
    }
};

// ---- keystone: runtime-width Integer over the DynamicContext ----
// IS-A UInt_T<DynamicContext,0> so all arithmetic/bitwise/shift/mux operators and
// the runtime-width storage come for free; this layer only re-adds the fork's
// construction-from-clear, reveal-to-clear, and the `.bits` spelling of `.w`.
class Integer : public UInt_T<DynamicContext, 0> {
    using Base = UInt_T<DynamicContext, 0>;
    // Feed `n` LSB-first clear bits owned by `party` (PUBLIC constant or ALICE
    // witness) into authenticated wires via the active engine.
    static void feed_into_(Base& dst, int party, const bool* b, int n) {
        if (party == PUBLIC) {
            for (int i = 0; i < n; ++i) backend->public_label(&dst.w[i].label, b[i]);
        } else {                                   // private witness (verifier feeds dummy)
            std::vector<block> tmp((size_t)n);
            backend->feed(tmp.data(), party, b, (size_t)n);
            for (int i = 0; i < n; ++i) dst.w[i] = ZKWire{ tmp[(size_t)i] };
        }
    }
   public:
    using Base::w;                                  // expose storage

    // `.bits` was the fork's member name for the wire vector; bind it to the
    // base's `.w` so all bulk ops (data/size/assign/resize/insert/begin/end/[])
    // compile unchanged. A reference member deletes the implicit copy/move, so
    // those are defined explicitly below (each rebinds `bits` to its own `w`).
    typename Base::storage& bits;

    Integer() : Base(zk_ctx()), bits(w) {}
    Integer(int width) : Base(zk_ctx(), width), bits(w) {}
    Integer(const Base& b) : Base(b), bits(w) {}                                  // wrap an operator result
    Integer(const Integer& o) : Base(static_cast<const Base&>(o)), bits(w) {}
    Integer(Integer&& o) noexcept : Base(std::move(static_cast<Base&>(o))), bits(w) {}
    Integer& operator=(const Integer& o) { Base::operator=(static_cast<const Base&>(o)); return *this; }
    Integer& operator=(Integer&& o) noexcept { Base::operator=(std::move(static_cast<Base&>(o))); return *this; }
    Integer& operator=(const Base& b) { Base::operator=(b); return *this; }

    // (width, arithmetic value, party=PUBLIC): value taken LSB-first, zero-extended
    // past bit 63. Accepts integral AND floating-point: the fork ctor is
    // `Integer(int,int64_t,party=PUBLIC)` and fork call sites pass doubles (e.g.
    // `Integer scale(64, pow(10,p))`) that truncate to int64_t — we mirror that exact
    // double→int64_t truncation so the bit pattern is fork-identical (I3). The party
    // default matches the fork. Arithmetic-constrained so a pointer arg SFINAEs out of
    // here and a literal `0` (an int, not a pointer) selects THIS ctor, never the
    // byte-pointer one below (whose `const T*` fails deduction on `0`).
    template <class T, std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
    Integer(int width, T value, int party = PUBLIC) : Base(zk_ctx(), width), bits(w) {
        const unsigned long long uv = (unsigned long long)(long long)value;   // fork: double/int → int64_t
        auto b = std::make_unique<bool[]>((size_t)width);
        for (int i = 0; i < width; ++i)
            b[(size_t)i] = (i < 64) ? ((uv >> i) & 1) != 0 : false;
        feed_into_(*this, party, b.get(), width);
    }
    // (width, byte buffer, party=PUBLIC): LSB-first within each byte (fork to_bool order).
    // Templated on the pointee (mirrors fork `Integer(int,T*,party=PUBLIC)`) so a literal
    // `0` fails `const T*` deduction and drops out, leaving the arithmetic ctor.
    template <class T>
    Integer(int width, const T* bytes, int party = PUBLIC) : Base(zk_ctx(), width), bits(w) {
        const uint8_t* p = (const uint8_t*)bytes;
        auto b = std::make_unique<bool[]>((size_t)width);
        for (int i = 0; i < width; ++i) b[(size_t)i] = (p[i / 8] >> (i % 8)) & 1;
        feed_into_(*this, party, b.get(), width);
    }

    int size() const { return (int)w.size(); }     // fork Integer::size() == bit width

    // Compound bitwise assignment (fork Integer had these; UInt_T only has the
    // binary forms). Operate through the inherited operators.
    Integer& operator^=(const Base& o) { *this = static_cast<const Base&>(*this) ^ o; return *this; }
    Integer& operator&=(const Base& o) { *this = static_cast<const Base&>(*this) & o; return *this; }
    Integer& operator|=(const Base& o) { *this = static_cast<const Base&>(*this) | o; return *this; }

    // fork Integer::geq(o) == (*this >= o) == !(*this < o), returning a Bit. SIGNED
    // to match the fork's signed Integer (geq sign-extends + subtracts + sign bit);
    // the upstream Base::operator< is UNSIGNED. (Only addmod uses it, on operands
    // padded to MSB=0 where signed==unsigned, so this is fidelity not a bug fix — but
    // keeps any future sign-straddling caller correct by construction.)
    Bit geq(const Base& o) const { return Bit(!(static_cast<const Base&>(*this).as_signed() < o.as_signed())); }

    // Operators that return Integer (not the base) so chained results keep the
    // wrapper's reveal()/.bits/.size — e.g. (a + b).reveal<uint32_t>().
    Integer operator+(const Base& o) const { return Integer(Base::operator+(o)); }
    Integer operator-(const Base& o) const { return Integer(Base::operator-(o)); }
    Integer operator*(const Base& o) const { return Integer(Base::operator*(o)); }
    // SIGNED division/modulus (the fork's Integer semantics; new UInt_T's / % are
    // unsigned). as_signed()/as_unsigned() are zero-gate wire reinterpretations.
    // Correct under BOTH ZK and GC. (A GC false-reject on / and % was fixed by making
    // backend/upstream_gc.h's main garbler byte-identical to the fork OptHalfGate —
    // PRP+garble_gate_*_halfgates instead of the upstream MITCCRH path; see FULLPORT_LOG.)
    Integer operator/(const Base& o) const { return Integer((static_cast<const Base&>(*this).as_signed() / o.as_signed()).as_unsigned()); }
    Integer operator%(const Base& o) const { return Integer((static_cast<const Base&>(*this).as_signed() % o.as_signed()).as_unsigned()); }
    Integer operator&(const Base& o) const { return Integer(Base::operator&(o)); }
    Integer operator|(const Base& o) const { return Integer(Base::operator|(o)); }
    Integer operator^(const Base& o) const { return Integer(Base::operator^(o)); }
    Integer operator~()              const { return Integer(Base::operator~()); }
    Integer operator<<(int s)        const { return Integer(Base::operator<<(s)); }
    Integer operator>>(int s)        const { return Integer(Base::operator>>(s)); }
    // SECRET-amount shifts (fork emp-tool integer.hpp:315-327). Upstream's
    // UInt_T::operator<<(const UInt_T&)/>>(const UInt_T&) are `requires (N>0)`
    // (unsigned_int.h:118-135) — DISABLED for our runtime-width N=0 Integer — and
    // additionally zero the result on overflow (an `overflow` mux the fork lacks),
    // which would CHANGE the proven relation. So we replicate the FORK exactly:
    // a log-depth barrel over only the low min(ceil(log2(size())), shamt_w-1) bits
    // of shamt, with NO overflow-zeroing. select(cond,t) is `cond ? t : res`
    // (keystone select -> Base::select -> kernel::mux = sel?t:f, byte-identical to
    // the fork's Bit::select picking the ARGUMENT on cond-true: bit.hpp:7-12,
    // integer.hpp:164-170), so the shift direction is NOT inverted (I3).
    Integer operator<<(const Base& shamt) const {
        Integer res(*this);
        const size_t shamt_w = shamt.w.size();                               // fork shamt.size()
        const size_t bound = std::min((size_t)std::ceil(std::log2((double)size())), shamt_w - 1);
        for (size_t i = 0; i < bound; ++i)
            res = res.select(shamt[(int)i], res << (1 << i));                 // shamt[i] -> Bit_T<DynamicContext>
        return res;
    }
    Integer operator>>(const Base& shamt) const {
        Integer res(*this);
        const size_t shamt_w = shamt.w.size();                               // fork shamt.size()
        const size_t bound = std::min((size_t)std::ceil(std::log2((double)size())), shamt_w - 1);
        for (size_t i = 0; i < bound; ++i)
            res = res.select(shamt[(int)i], res >> (1 << i));
        return res;
    }
    Bit     operator<(const Base& o) const { return Bit(static_cast<const Base&>(*this).as_signed() < o.as_signed()); }  // SIGNED (fork Integer semantics)
    Bit     operator==(const Base& o)const { return Bit(Base::operator==(o)); }
    // Explicit != (returns Bit, like fork). REQUIRED: C++20 will not synthesize `!=`
    // from a rewritten `==` because our `operator==` returns Bit, not bool — without
    // this, `a != b` is a hard error ("return type ... not 'bool'").
    Bit     operator!=(const Base& o)const { return !operator==(o); }
    Integer select(const Bit_T<DynamicContext>& sel, const Base& t) const { return Integer(Base::select(sel, t)); }

    // Open to `party`, writing clear bytes LSB-first (fork from_bool order).
    void reveal(void* out, int party) const {
        const int n = (int)w.size();
        auto b = std::make_unique<bool[]>((size_t)n);
        backend->reveal(b.get(), party, (const void*)w.data(), (size_t)n);  // ZKWire layout-compatible with block
        uint8_t* p = (uint8_t*)out;
        const int nbytes = (n + 7) / 8;
        for (int i = 0; i < nbytes; ++i) p[i] = 0;
        for (int i = 0; i < n; ++i) p[i / 8] |= (uint8_t)(b[(size_t)i] ? 1 : 0) << (i % 8);
    }
    // Templated BUFFER reveal (fork Integer::reveal<T>(T* output, party)): write the full
    // ceil(width/8) clear bytes LSB-first into `output`. Delegates to the void* packer so
    // the byte layout is byte-identical to the fork (I3). Distinct from the value-returning
    // overload below: this one takes a pointer arg, so `reveal<uchar>(buf, party)` (2 args)
    // binds here while `reveal<uint32_t>()` / `reveal<uint32_t>(party)` binds below.
    template <typename T>
    void reveal(T* output, int party = PUBLIC) const { reveal((void*)output, party); }
    // Templated clear reveal (fork Integer::reveal<T>()): low min(width,bits(T)) bits, LSB-first.
    template <typename T>
    T reveal(int party = PUBLIC) const {
        const int n = (int)w.size();
        auto b = std::make_unique<bool[]>((size_t)n);
        backend->reveal(b.get(), party, (const void*)w.data(), (size_t)n);  // ZKWire layout-compatible with block
        if constexpr (std::is_same_v<T, std::string>) {
            uint64_t v = 0;
            for (int i = 0; i < n && i < 64; ++i) v |= (uint64_t)(b[(size_t)i] ? 1 : 0) << i;
            return std::to_string(v);
        } else {
            T v = 0;
            for (int i = 0; i < n && i < (int)(sizeof(T) * 8); ++i)
                v |= (T)(b[(size_t)i] ? 1 : 0) << i;
            return v;
        }
    }
};

// FULLPORT: fork emp's fixed PRG seed constant (removed upstream). Reproducible randomness only.
static const block fix_key = makeBlock(0x2018120720190101LL, 0x70616462656e6368LL);

// FULLPORT: fork emp-tool's NETWORK_BUFFER_SIZE (removed upstream; pado's ws.h / net IO use it).
static const int NETWORK_BUFFER_SIZE = 1024 * 1024;

// FULLPORT: fork emp-tool bit-conversion helpers (upstream keeps only bits_to_bools/bools_to_bits).
// Replicated verbatim to keep LSB-first ordering (I3).
template <typename T>
inline void int_to_bool(bool* data, T input, int len) {
    for (int i = 0; i < len; ++i) { data[i] = (input & 1) == 1; input >>= 1; }
}
template <typename T>
inline void to_bool(bool* data, const T* input, const int len, const bool reverse = false) {
    for (int i = 0; i < len; ++i)
        data[reverse ? len - i : i] =
            (bool)((((uint8_t*)input)[i / 8] & (((uint8_t)1) << (i % 8))) != 0);
}
template <typename T>
inline void from_bool(const bool* data, T* output, const int len, const bool reverse = false) {
    for (int i = 0; i < len; ++i) {
        ((uint8_t*)output)[i / 8] &= (~(((uint8_t)1) << (i % 8)));
        ((uint8_t*)output)[i / 8] |= (((uint8_t)data[reverse ? len - i : i]) << (i % 8));
    }
}

}  // namespace emp

// FULLPORT: fork emp-zk-bool's cheating aggregator (upstream now error()→exit(1) hard reject).
// Empty stub: reaching cheated() means no exit occurred → no cheating → false.
class CheatRecord {
   public:
    static inline std::vector<std::string> message;
    static void reset() { message.clear(); }
    static void put(const std::string& s) { message.push_back(s); }
    static bool cheated() { return !message.empty(); }
};

#endif  // PRIMUS_COMPAT_H
