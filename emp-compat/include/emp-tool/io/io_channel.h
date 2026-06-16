#ifndef EMP_IO_CHANNEL_H__
#define EMP_IO_CHANNEL_H__
#include "emp-tool/core/block.h"
#include "emp-tool/crypto/hash.h"
#include "emp-tool/crypto/prg.h"
#include "emp-tool/crypto/ec.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>

namespace emp {

// Polymorphic transport interface. Implementations override send_data_internal
// / recv_data_internal; everything else (block / point / packed-bool helpers,
// byte counters, optional Fiat-Shamir transcript) is inherited.
//
// Fiat-Shamir support: enable_fs(send_first) turns on TWO SHA-256
// transcripts — one absorbing every byte sent (direction self→peer),
// one absorbing every byte received (peer→self). Exactly one party
// passes true.
//
// get_digest() returns the first block of H(d_AB ‖ d_BA), where d_AB
// is the A→B wire digest and d_BA is the B→A digest. Both parties
// produce the same value: the send_first side concatenates my_send
// first, the other side concatenates my_recv first, and the meanings
// swap between the two parties. Hashing per-direction (not per
// call-site) is robust against protocols that batch sends asymmetrically.
//
// Off by default.

class IOChannel {
public:
	uint64_t send_counter = 0;  // bytes sent
	uint64_t recv_counter = 0;  // bytes received

	// Communication-round counter: number of maximal runs of same-direction
	// traffic. Each switch between sending and receiving opens a new round,
	// so back-to-back sends collapse into one (send/send/send == 1) while an
	// alternating exchange counts every turn (send/recv/send == 3). Useful as
	// a transport-agnostic proxy for protocol latency, which is dominated by
	// the number of direction changes rather than total bytes.
	uint64_t rounds = 0;

	// Number of times the channel drained its outbound buffer to the
	// transport (see flush()). Maintained by buffering implementations;
	// stays 0 for transports with nothing to flush.
	uint64_t flushes_count = 0;

	virtual ~IOChannel() = default;

	// Human-readable one-line-per-field dump of every counter this channel
	// tracks: bytes sent, bytes received, their total, communication rounds
	// (direction changes; see `rounds`), and buffer flushes. Intended for
	// logging / benchmark output, not machine parsing. Reflects this
	// endpoint's view.
	std::string get_statistics_string() const {
		auto with_units = [](uint64_t bytes) {
			static const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
			double v = static_cast<double>(bytes);
			int i = 0;
			while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
			char buf[64];
			std::snprintf(buf, sizeof(buf), "%llu B (%.2f %s)",
			              static_cast<unsigned long long>(bytes), v, u[i]);
			return std::string(buf);
		};
		std::string s = "Network statistics:\n";
		s += "  sent:   " + with_units(send_counter) + "\n";
		s += "  recv:   " + with_units(recv_counter) + "\n";
		s += "  total:  " + with_units(send_counter + recv_counter) + "\n";
		s += "  rounds: " + std::to_string(rounds) + "\n";
		s += "  flushes:" + std::to_string(flushes_count) + "\n";
		return s;
	}

	virtual void send_data_internal(const void *data, int64_t nbyte) = 0;
	virtual void recv_data_internal(void *data, int64_t nbyte) = 0;

	// Drain any outbound buffer to the underlying transport. Default
	// is a no-op for transports with nothing to flush.
	virtual void flush() {}

	// Optional wire-level handshake (e.g. 1-byte ping/pong). Default
	// no-op for transports that don't need one.
	virtual void sync() {}

	// Turn on Fiat-Shamir transcript hashing. `send_first` selects which
	// of the two H(_‖H(_)) formulas this side computes, so both parties
	// produce the same digest value — exactly one party should pass true.
	// Idempotent assert: calling twice is a bug.
	void enable_fs(bool send_first) {
		assert(!fs_send_.has_value() && "enable_fs called twice");
		fs_send_first_ = send_first;
		fs_send_.emplace();
		fs_recv_.emplace();
	}

	bool fs_enabled() const { return fs_send_.has_value(); }

	// Per-direction transcript snapshots, intended for diagnostics
	// (e.g. dumping a per-protocol wire-bytes hash across a refactor).
	// Each returns the first 16 B of the SHA-256 over all bytes that
	// have crossed in that direction since enable_fs. Non-destructive;
	// the running transcripts continue absorbing after the snapshot.
	block get_send_digest() {
		assert(fs_send_.has_value() && "get_send_digest: enable_fs first");
		char buf[Hash::DIGEST_SIZE];
		fs_send_->digest(buf, /*reset_after=*/false);
		block out;
		std::memcpy(&out, buf, sizeof(block));
		return out;
	}
	block get_recv_digest() {
		assert(fs_recv_.has_value() && "get_recv_digest: enable_fs first");
		char buf[Hash::DIGEST_SIZE];
		fs_recv_->digest(buf, /*reset_after=*/false);
		block out;
		std::memcpy(&out, buf, sizeof(block));
		return out;
	}

	// Snapshot the running transcripts as one block (first 16 B of a
	// 32-B SHA-256 digest). Does not reset — call repeatedly across
	// protocol stages to derive sub-challenges. Asserts FS is on.
	//
	// Output: H(d_AB ‖ d_BA)[0..16). Send-first side concatenates
	// my_send first, the other side concatenates my_recv first.
	block get_digest() {
		assert(fs_send_.has_value() && "get_digest: enable_fs first");
		constexpr int N = Hash::DIGEST_SIZE;        // 32
		char buf[2 * N];
		fs_send_->digest(buf + (fs_send_first_ ? 0 : N), /*reset_after=*/false);
		fs_recv_->digest(buf + (fs_send_first_ ? N : 0), /*reset_after=*/false);
		alignas(block) char out_buf[N];
		Hash::hash_once(out_buf, buf, sizeof(buf));
		block out;
		std::memcpy(&out, out_buf, sizeof(block));
		return out;
	}

	void send_data(const void *data, int64_t nbyte) {
		send_counter += nbyte;
		if (last_dir_ != Dir::SEND) { ++rounds; last_dir_ = Dir::SEND; }
		if (fs_send_) fs_send_->put(data, nbyte);
		send_data_internal(data, nbyte);
	}

	void recv_data(void *data, int64_t nbyte) {
		recv_counter += nbyte;
		if (last_dir_ != Dir::RECV) { ++rounds; last_dir_ = Dir::RECV; }
		recv_data_internal(data, nbyte);
		if (fs_recv_) fs_recv_->put(data, nbyte);
	}

	void send_block(const block *data, int64_t nblock) {
		send_data(data, nblock * sizeof(block));
	}

	void recv_block(block *data, int64_t nblock) {
		recv_data(data, nblock * sizeof(block));
	}

	void send_pt(Point *A, int64_t num_pts = 1) {
		for (int64_t i = 0; i < num_pts; ++i) {
			const size_t len = A[i].size();
			assert(len <= MAX_POINT_BYTES);
			const uint32_t len_wire = static_cast<uint32_t>(len);
			A[i].group()->resize_scratch(len);
			unsigned char *tmp = A[i].group()->scratch();
			send_data(&len_wire, sizeof(len_wire));
			A[i].to_bin(tmp, len);
			send_data(tmp, len);
		}
	}

	void recv_pt(ECGroup *g, Point *A, int64_t num_pts = 1) {
		for (int64_t i = 0; i < num_pts; ++i) {
			uint32_t len_wire = 0;
			recv_data(&len_wire, sizeof(len_wire));
			assert(len_wire <= MAX_POINT_BYTES);
			const size_t len = len_wire;
			g->resize_scratch(len);
			unsigned char *tmp = g->scratch();
			recv_data(tmp, len);
			A[i].from_bin(g, tmp, len);
		}
	}

	// Pack 8 bools per wire byte via bools_to_bits / bits_to_bools (LSB-first
	// within each byte, see utils/block.h). Streamed in 8 KiB-of-bools chunks
	// so the staging buffer fits comfortably on the stack regardless of the
	// caller's buffer size.
	//
	// Security: bools_to_bits is a read-modify-write on the tail byte and
	// preserves any high padding bits that come along (positions
	// [batch%8 .. 8) in the last destination byte). With an uninitialized
	// stack `buf`, those bits would leak stack contents onto the wire and
	// make Fiat-Shamir transcripts non-deterministic for non-multiple-of-8
	// lengths. Zero the one byte that bools_to_bits leaves partially-
	// written before each pack. Whole-byte bytes get fully overwritten by
	// the SIMD/memcpy path inside bools_to_bits, so they don't need a clear.
	void send_bool(const bool *data, int64_t length) {
		if (length <= 0) return;
		uint8_t buf[IO_BOOL_CHUNK_SIZE / 8];
		while (length > 0) {
			int64_t batch = length < IO_BOOL_CHUNK_SIZE ? length : IO_BOOL_CHUNK_SIZE;
			int64_t bytes = (batch + 7) / 8;
			if (batch % 8 != 0) buf[bytes - 1] = 0;
			bools_to_bits(buf, data, batch);
			send_data(buf, bytes);
			data += batch;
			length -= batch;
		}
	}

	void recv_bool(bool *data, int64_t length) {
		if (length <= 0) return;
		uint8_t buf[IO_BOOL_CHUNK_SIZE / 8];
		while (length > 0) {
			int64_t batch = length < IO_BOOL_CHUNK_SIZE ? length : IO_BOOL_CHUNK_SIZE;
			int64_t bytes = (batch + 7) / 8;
			recv_data(buf, bytes);
			bits_to_bools(data, buf, batch);
			data += batch;
			length -= batch;
		}
	}

private:
	// Last traffic direction, for the `rounds` counter. NONE until the first
	// send/recv so the opening transfer in either direction opens round 1.
	enum class Dir { NONE, SEND, RECV };
	Dir last_dir_ = Dir::NONE;

	// Per-direction FS transcripts. Both nullopt = off (default).
	// fs_send_ absorbs my outgoing wire bytes, fs_recv_ my incoming
	// ones. Hash is non-copyable but std::optional only requires
	// emplace-construction. fs_send_first_ records the role-bool
	// passed to enable_fs so get_digest produces a value matching
	// the peer.
	std::optional<Hash> fs_send_;
	std::optional<Hash> fs_recv_;
	bool fs_send_first_ = false;
};

}  // namespace emp
#endif
