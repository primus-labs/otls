#ifndef PRIMUS_COMPAT_H
#define PRIMUS_COMPAT_H
// ============================================================================
// emp-toolkit 全量迁移 compat shim（分支 emp-zk-fullport）。
// 上游 emp 把 fork 的"变宽+算术" Integer 拆成 BitVec_T（变宽,无算术）与
// UnsignedInt_T<Wire,N>（定宽,有算术）。上游 UnsignedInt_T<Wire, N=0> 是
// **运行期可变宽**且继承 BitVec_T → 同时具备：变宽构造、.bits(mutable)、
// 全套算术(+ - * / % << >>)、秘密移位 operator>>(const UnsignedInt_T&)、
// 位运算(& | ^ ~)、reveal。故 `Integer = UnsignedInt_T<block>` 一键还原 fork Integer。
//
// 安全不变量 I3：UnsignedInt_T 与 BitVec_T 同为 LSB-first 位序，构造字节编码
// 与 fork 一致 → 被证关系不变。
// ============================================================================
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"

// 把电路类型绑定到 ZK bool wire = block。Bit/SignedInt 上游 emp-zk-bool 已绑过，
// 此处重复为同一 using 别名（合法,无冲突）。
EMP_USE_CIRCUIT_TYPES(block, Bit, BitVec, UnsignedInt, SignedInt);

namespace emp {
// 键石别名：运行期可变宽 + 算术 + .bits + 秘密移位。
using Integer = UnsignedInt_T<block>;
}

#endif  // PRIMUS_COMPAT_H
