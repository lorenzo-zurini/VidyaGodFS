// A coding description as it is kept: readable data in a node (MetaPackageFormat chapter 22 §22.16), never a binary.
//
//   { "NAME": "…", "ISA": 5, "CODER": "BITS", "WINDOW": 32768, "MAXLEN": 258,
//     "REGISTERS": { "place": 0, "left": 52 },
//     "TABLES": { "lbase": [3, 4, …] }, "ARRAYS": { "lens": { "SIZE": 320 } }, "HUFFS": ["lit", "dist", "cl"],
//     "ENTRY": "@stream",
//     "CODE": [ "# comments", "@stream", "byterun 12", "decode: set left (shr (inleft) 3)", "jz (eq left 0) @done", … ] }
//
// One instruction a string: an optional mode prefix (code:, decode:, price:, joined by +), a mnemonic, its operands.
// Values are numbers, registers (rN or a REGISTERS name) or (op value …); labels are @names on lines of their own.
// Reading builds the expressions canonically (left to right, children first, each distinct expression once, 0 the
// constant 0) and validates the result like any description (descriptions come from peers: untrusted).
#include "coding.h"
#include "zfamily.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <unordered_map>

namespace coding {
namespace {

using ojson = nlohmann::ordered_json;

// ---- operand signatures: what each op's text names, in order (fields not named must be their defaults)
enum Kind : char { kE = 'E', kR = 'R', kN = 'N', kH = 'H', kA = 'A', kF = 'F', kK = 'K', kL = 'L', kB = 'B', kT = 'T' };   // kT: a table name (imm)
struct Arg { char kind, field; bool opt = false; };  // field: x v m t(tgt) n(nb) i(imm) l(target); opt: may be left out (0)
struct Sig { const char *name; std::vector<Arg> args; bool freeable; };
const std::vector<Sig> &Sigs() {
    static const std::vector<Sig> s = {
        {"bit", {{kE, 'x'}, {kE, 'v'}, {kR, 't'}}, false},
        {"tree", {{kN, 'n'}, {kE, 'x'}, {kE, 'v'}, {kR, 't'}}, false},
        {"rtree", {{kN, 'n'}, {kE, 'x'}, {kE, 'v'}, {kE, 'm'}, {kR, 't'}}, false},
        {"direct", {{kE, 'x'}, {kE, 'v'}, {kR, 't'}}, false},
        {"mlit", {{kE, 'x'}, {kE, 'v'}, {kE, 'm'}, {kR, 't'}}, false},
        {"raw", {{kE, 'x'}, {kE, 'v'}, {kR, 't'}}, true},
        {"huff", {{kH, 'i'}, {kE, 'v'}, {kR, 't'}}, true},
        {"build", {{kH, 'i'}, {kA, 'n'}, {kE, 'x'}, {kE, 'v'}}, false},
        {"sta", {{kA, 'n'}, {kE, 'x'}, {kE, 'v'}}, false},
        {"set", {{kR, 't'}, {kE, 'v'}}, false},
        {"dec", {{kR, 't'}}, false},
        {"outlit", {{kE, 'v'}}, false},
        {"outcopy", {{kE, 'x'}, {kE, 'v'}}, false},
        {"hmtf", {{kR, 't'}, {kN, 'n'}, {kE, 'v'}}, false},
        {"hpush", {{kR, 't'}, {kN, 'n'}, {kE, 'v'}}, false},
        {"jz", {{kE, 'v'}, {kL, 'l'}}, false},
        {"jmp", {{kL, 'l'}}, false},
        {"call", {{kL, 'l'}}, false},
        {"ret", {}, false},
        {"assert", {{kE, 'v'}}, false},
        {"flush", {}, false},
        {"mark", {}, false},
        {"end", {}, false},
        {"huffrun", {{kH, 'i'}, {kE, 'x'}, {kR, 't'}, {kB, 'n'}, {kE, 'm'}, {kE, 'v', true}}, false},   // (ISA 7: a bound)
        {"byterun", {{kE, 'x'}}, false},
        {"predict", {{kF, 'n'}, {kK, 'i'}, {kR, 't'}, {kE, 'x'}, {kE, 'v'}, {kE, 'm'}}, false},
        {"rawbytes", {{kE, 'x'}, {kE, 'v'}, {kR, 't'}}, true},
        {"e8frame", {{kE, 'x'}, {kE, 'v'}, {kE, 'm'}, {kR, 't'}}, false},
        {"e8end", {{kE, 'v'}}, false},
        {"nearest", {{kR, 't'}, {kE, 'x'}, {kE, 'v'}, {kE, 'm'}}, false},
        {"lzxfolder", {{kE, 'x'}, {kE, 'v'}, {kE, 'm'}, {kK, 'i'}, {kR, 't'}}, false},
        {"lzxend", {{kE, 'v'}}, false},
        {"lzxsize", {{kE, 'x'}, {kR, 't'}}, false},
        {"lzxemit", {{kE, 'x'}, {kR, 't'}}, false},
        // ISA 10: VIEW mode (viewmode.h)
        {"ename", {{kE, 'x'}, {kE, 'v'}}, false},
        {"echar", {{kE, 'v'}}, false},
        {"etab", {{kT, 'i'}}, false},
        {"edir", {}, false},
        {"efinish", {{kE, 'x'}, {kE, 'v'}}, false},
        {"estride", {{kE, 'x'}, {kE, 'v'}, {kK, 'i'}, {kE, 'm'}}, false},
        {"epart", {{kE, 'x'}, {kE, 'v'}}, false},
        {"efin", {}, false},
    };
    return s;
}
static_assert(OP_COUNT == 42, "an op without a text form: add its signature");

struct ExName { const char *name; uint8_t op; int arity; };   // arity -1: (table|arr NAME value)
const std::vector<ExName> &ExNames() {
    static const std::vector<ExName> s = {
        {"add", EX_ADD, 2}, {"sub", EX_SUB, 2}, {"mul", EX_MUL, 2}, {"shl", EX_SHL, 2}, {"shr", EX_SHR, 2},
        {"and", EX_AND, 2}, {"or", EX_OR, 2}, {"xor", EX_XOR, 2}, {"lt", EX_LT, 2}, {"eq", EX_EQ, 2},
        {"ne", EX_NE, 2}, {"ge", EX_GE, 2}, {"byte", EX_BYTE, 1}, {"table", EX_TABLE, -1}, {"arr", EX_ARR, -1},
        {"log2slot", EX_LOG2SLOT, 1}, {"bitpos", EX_BITPOS, 0}, {"dleft", EX_DLEFT, 0}, {"xleft", EX_XLEFT, 0},
        {"inleft", EX_INLEFT, 0}, {"streampos", EX_STREAMPOS, 0},
        {"u16", EX_U16, 1}, {"u32", EX_U32, 1}, {"u16be", EX_U16BE, 1}, {"u32be", EX_U32BE, 1}, {"div", EX_DIV, 2}, {"mod", EX_MOD, 2},
    };
    return s;
}
static_assert(EX_COUNT == 29, "an expression without a text form: add its name");

const char *FamilyName(uint8_t f) { return f == kFamilyLz4hc ? "lz4hc" : f == kFamilyZlib ? "zlib" : nullptr; }

std::string Num(uint32_t v) {
    char b[16];
    if (v < 0x10000) snprintf(b, sizeof b, "%u", v); else snprintf(b, sizeof b, "0x%X", v);
    return b;
}

bool ZeroEx(const Description &D, uint16_t i) { return i < D.ex.size() && D.ex[i].op == EX_CONST && D.ex[i].imm == 0; }

// ================================================================================================ printing
struct Printer {
    Printer(const Description &Of, const TextNames *Names) : D(Of), N(Names) {}
    const Description &D;
    const TextNames *N;
    std::string err;

    std::string reg(uint32_t r) const {
        if (N) { auto it = N->regs.find((int)r); if (it != N->regs.end()) return it->second; }
        return "r" + std::to_string(r);
    }
    // unnamed: t00, a07 … (two digits: a description has at most 16, and the names must sort as the numbers do)
    static std::string named(const std::vector<std::string> *Names, size_t i, const char *pre) {
        if (Names && i < Names->size() && !(*Names)[i].empty()) return (*Names)[i];
        return pre + std::string(i < 10 ? "0" : "") + std::to_string(i);
    }
    std::string table(size_t i) const { return named(N ? &N->tables : nullptr, i, "t"); }
    std::string array(size_t i) const { return named(N ? &N->arrays : nullptr, i, "a"); }
    std::string huff(size_t i) const { return named(N ? &N->huffs : nullptr, i, "h"); }

    // a value's text appended to Out, by an explicit stack (an in-memory description may chain values deeper than any
    // call stack); false once the text passes Cap (a chain every op repeats prints quadratically)
    size_t cap = 64u << 20;
    bool ex(uint16_t root, std::string &Out) {
        struct F { uint16_t i; uint8_t step; };
        std::vector<F> st{{root, 0}};
        while (!st.empty()) {
            F &f = st.back(); const Ex &e = D.ex[f.i];
            if (Out.size() > cap) { err = "a description too large to print"; return false; }
            if (e.op == EX_CONST) { Out += Num(e.imm); st.pop_back(); continue; }
            if (e.op == EX_REG) { Out += reg(e.imm); st.pop_back(); continue; }
            const ExName *n = nullptr; for (const ExName &x : ExNames()) if (x.op == e.op) n = &x;
            const int arity = n->arity < 0 ? 1 : n->arity;
            if (f.step == 0) {
                Out += '('; Out += n->name;
                if (n->arity < 0) { Out += ' '; Out += e.op == EX_TABLE ? table(e.imm) : array(e.imm); }
            }
            if (f.step < arity) {
                const uint16_t c = f.step == 0 ? e.a : e.b;
                ++f.step; Out += ' ';
                st.push_back({c, 0});                                   // (f is not used after the push)
                continue;
            }
            Out += ')'; st.pop_back();
        }
        return true;
    }
};

std::string Quote(const std::string &s) { return ojson(s).dump(); }

}  // namespace

bool Print(const Description &D, std::string &Out, std::string &Err, const TextNames *Names) {
    if (!Validate(D, Err)) return false;
    Printer P(D, Names);
    // labels: every jump's target and the entries
    std::map<int, std::string> lab;
    auto name = [&](int at) {
        if (Names) { auto it = Names->labels.find(at); if (it != Names->labels.end()) return it->second; }
        return "L" + std::to_string(at);
    };
    for (const Op &p : D.ops) if (p.op == OP_JZ || p.op == OP_JMP || p.op == OP_CALL) lab[p.target] = name(p.target);
    lab[D.entryStream] = name(D.entryStream);
    if (D.entryToken >= 0) lab[D.entryToken] = name(D.entryToken);
    if (Names) for (const auto &kv : Names->labels) if (kv.first >= 0 && (size_t)kv.first < D.ops.size()) lab[kv.first] = kv.second;

    std::string o = "{\n";
    auto field = [&](const char *k, const std::string &v) { o += "  \""; o += k; o += "\": "; o += v; o += ",\n"; };
    field("NAME", Quote(D.name));
    field("ISA", std::to_string(D.isa));
    if (D.view) {                                      // ISA 10: a file table, no coder
        static const char *const kNames[] = {"utf-8", "ascii", "latin-1", "utf-16be", "cp932", "cp437"};
        if (D.names > kNamesLast) { Err = "a view's NAMES encoding is unknown"; return false; }
        field("MODE", "\"VIEW\"");
        field("NAMES", Quote(kNames[D.names]));
    }
    else field("CODER", D.coder == kBits ? "\"BITS\"" : D.coder == kBits16M ? "\"BITS16M\"" : "\"RANGE\"");
    if (D.shift != 5) field("SHIFT", std::to_string(D.shift));
    if (D.nslots) field("SLOTS", std::to_string(D.nslots));
    if (D.window) field("WINDOW", std::to_string(D.window));
    if (D.maxlen) field("MAXLEN", std::to_string(D.maxlen));
    if (D.len1slot >= 0) field("LEN1SLOT", std::to_string(D.len1slot));
    if (D.histbase || D.histlen) field("HISTORY", "{ \"FROM\": " + Quote(P.reg(D.histbase)) + ", \"COUNT\": " + std::to_string(D.histlen) + " }");
    if (D.tokK || D.tokL || D.tokSL || D.tokD)
        field("TOKEN", "{ \"KIND\": " + Quote(P.reg(D.tokK)) + ", \"LENGTH\": " + Quote(P.reg(D.tokL)) + ", \"SLOT\": " +
                       Quote(P.reg(D.tokSL)) + ", \"DISTANCE\": " + Quote(P.reg(D.tokD)) + " }");
    if (Names && !Names->regs.empty()) {
        std::string r = "{"; bool first = true;
        for (const auto &kv : Names->regs) { r += first ? " " : ", "; first = false; r += Quote(kv.second) + ": " + std::to_string(kv.first); }
        field("REGISTERS", r + " }");
    }
    if (!D.tables.empty()) {
        o += "  \"TABLES\": {\n";
        for (size_t t = 0; t < D.tables.size(); ++t) {
            o += "    " + Quote(P.table(t)) + ": [";
            for (size_t i = 0; i < D.tables[t].size(); ++i) { if (i) o += i % 24 ? ", " : ",\n      "; o += std::to_string(D.tables[t][i]); }
            o += t + 1 < D.tables.size() ? "],\n" : "]\n";
        }
        o += "  },\n";
    }
    if (!D.arrays.empty()) {
        o += "  \"ARRAYS\": {\n";
        for (size_t a = 0; a < D.arrays.size(); ++a) {
            size_t init = D.arrays[a].size(); while (init && !D.arrays[a][init - 1]) --init;
            o += "    " + Quote(P.array(a)) + ": { \"SIZE\": " + std::to_string(D.arrays[a].size());
            if (init) { o += ", \"INIT\": ["; for (size_t i = 0; i < init; ++i) { if (i) o += i % 24 ? ", " : ",\n      "; o += std::to_string(D.arrays[a][i]); } o += "]"; }
            o += a + 1 < D.arrays.size() ? " },\n" : " }\n";
        }
        o += "  },\n";
    }
    if (D.nhuff) { std::string h = "["; for (int i = 0; i < D.nhuff; ++i) h += (i ? ", " : "") + Quote(P.huff((size_t)i)); field("HUFFS", h + "]"); }
    field("ENTRY", Quote("@" + lab[D.entryStream]));
    if (D.entryToken >= 0) field("TOKEN_ENTRY", Quote("@" + lab[D.entryToken]));
    o += "  \"CODE\": [\n";
    for (size_t i = 0; i < D.ops.size(); ++i) {
        auto L = lab.find((int)i);
        if (L != lab.end()) o += "    " + Quote("@" + L->second) + ",\n";
        const Op &p = D.ops[i];
        const Sig &s = Sigs()[p.op];
        std::string line;
        if (p.modes) {
            bool first = true;
            for (auto [bit, nm] : {std::pair<int, const char *>{kCode, "code"}, {kDecode, "decode"}, {kPrice, "price"}})
                if (p.modes & bit) { line += first ? "" : "+"; line += nm; first = false; }
            line += ": ";
        }
        line += s.name;
        const bool fr = (p.flags & kFree) != 0;
        if (fr) line += " free";
        if ((p.flags & kBounded) && p.op != OP_HUFFRUN) { Err = "a bound on an op that has none"; return false; }
        bool used[7] = {};                               // x v m t n i l
        auto idx = [](char f) { return std::string("xvmtnil").find(f); };
        for (const Arg &a : s.args) {
            if (fr && a.field == 'v') { used[1] = true; if (!ZeroEx(D, p.v)) { Err = "a free op with a value"; return false; } continue; }
            used[idx(a.field)] = true;
            if (a.opt && !(p.flags & kBounded)) continue;                // (the bound: printed only on a bounded run)
            line += " ";
            switch (a.kind) {
                case kE: if (!P.ex(a.field == 'x' ? p.x : a.field == 'v' ? p.v : p.m, line)) { Err = P.err; return false; } break;
                case kR: line += P.reg(p.tgt); break;
                case kB: line += P.reg(p.nb); break;
                case kN: line += std::to_string(p.nb); break;
                case kH: line += P.huff(p.imm); break;
                case kA: line += P.array(p.nb); break;
                case kF: { const char *f = FamilyName(p.nb); if (!f) { Err = "an unknown family"; return false; } line += f; break; }
                case kK: line += Num(p.imm); break;
                case kT: line += P.table(p.imm); break;
                case kL: line += "@" + lab[p.target]; break;
            }
        }
        // whatever the text does not name must be its default, or the text would not say what the op does
        if ((!used[0] && !ZeroEx(D, p.x)) || (!used[1] && !ZeroEx(D, p.v)) || (!used[2] && !ZeroEx(D, p.m)) ||
            (!used[3] && p.tgt) || (!used[4] && p.nb) || (!used[5] && p.imm) || (!used[6] && p.target) || (fr && !s.freeable) ||
            (!(p.flags & kBounded) && p.op == OP_HUFFRUN && !ZeroEx(D, p.v)))
        { Err = "op " + std::to_string(i) + " (" + s.name + ") sets a field its text form does not name"; return false; }
        o += "    " + Quote(line) + (i + 1 < D.ops.size() ? ",\n" : "\n");
        if (o.size() > P.cap) { Err = "a description too large to print"; return false; }
    }
    o += "  ]\n}\n";
    Out = std::move(o);
    return true;
}

// ================================================================================================ reading
namespace {

struct Reader {
    explicit Reader(Description &Into) : D(Into) {}
    Description &D;
    std::string err;
    std::map<std::string, uint32_t> regs, tables, arrays, huffs, labels;
    std::map<std::tuple<uint8_t, uint16_t, uint16_t, uint32_t>, uint16_t> exIndex;
    std::vector<std::pair<size_t, std::string>> fix;     // op index, label

    bool fail(const std::string &m) { if (err.empty()) err = m; return false; }

    uint16_t ex(uint8_t op, uint16_t a, uint16_t b, uint32_t imm) {
        const auto k = std::make_tuple(op, a, b, imm);
        auto it = exIndex.find(k); if (it != exIndex.end()) return it->second;
        if (D.ex.size() >= 65535) { fail("too many expressions"); return 0; }
        D.ex.push_back(Ex{op, a, b, imm});
        return exIndex[k] = (uint16_t)(D.ex.size() - 1);
    }

    // ---- tokens
    std::vector<std::string> tok;
    size_t at = 0;
    bool lex(const std::string &s) {
        tok.clear(); at = 0;
        for (size_t i = 0; i < s.size();) {
            const char c = s[i];
            if (std::isspace((unsigned char)c)) { ++i; continue; }
            if (c == '(' || c == ')') { tok.emplace_back(1, c); ++i; continue; }
            size_t j = i; while (j < s.size() && !std::isspace((unsigned char)s[j]) && s[j] != '(' && s[j] != ')') ++j;
            tok.push_back(s.substr(i, j - i)); i = j;
        }
        return true;
    }
    bool more() const { return at < tok.size(); }
    const std::string &peek() const { static const std::string e; return at < tok.size() ? tok[at] : e; }

    static bool number(const std::string &s, uint32_t &v) {
        if (s.empty()) return false;
        uint64_t x = 0; size_t i = 0; int base = 10;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; i = 2; }
        for (; i < s.size(); ++i) {
            const char c = s[i]; int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return false;
            x = x * (uint64_t)base + (uint64_t)d; if (x > 0xFFFFFFFFu) return false;
        }
        v = (uint32_t)x; return true;
    }
    bool regName(const std::string &s, uint32_t &r) const {
        auto it = regs.find(s); if (it != regs.end()) { r = it->second; return true; }
        if (s.size() < 2 || s.size() > 3 || s[0] != 'r') return false;
        for (size_t i = 1; i < s.size(); ++i) if (!std::isdigit((unsigned char)s[i])) return false;
        return number(s.substr(1), r) && r < (uint32_t)kRegs;
    }
    bool reg(uint32_t &r) {
        if (!more()) return fail("a register is missing");
        if (!regName(tok[at], r)) return fail("not a register: " + tok[at]);
        ++at; return true;
    }
    bool nameOf(const std::map<std::string, uint32_t> &M, const char *what, uint32_t &v) {
        if (!more()) return fail(std::string("a ") + what + " is missing");
        auto it = M.find(tok[at]); if (it != M.end()) { v = it->second; ++at; return true; }
        // by name only: a description's objects may be read back in another key order (a JSON object has none)
        return fail(std::string("no such ") + what + ": " + tok[at]);
    }

    // a value: a number, a register, or (op values…); nesting bounded (descriptions are untrusted)
    bool value(uint16_t &out, int depth = 0) {
        if (depth > 200) return fail("a value nested too deep");
        if (!more()) return fail("a value is missing");
        const std::string t = tok[at++];
        uint32_t v;
        if (t == ")") return fail("an unexpected )");
        if (t != "(") {
            if (number(t, v)) { out = ex(EX_CONST, 0, 0, v); return err.empty(); }
            if (regName(t, v)) { out = ex(EX_REG, 0, 0, v); return err.empty(); }
            return fail("not a value: " + t);
        }
        if (!more()) return fail("an empty (");
        const std::string op = tok[at++];
        const ExName *n = nullptr; for (const ExName &e : ExNames()) if (op == e.name) n = &e;
        if (!n) return fail("no such operation: " + op);
        uint16_t a = 0, b = 0; uint32_t imm = 0;
        if (n->arity == -1) { if (!nameOf(n->op == EX_TABLE ? tables : arrays, n->op == EX_TABLE ? "table" : "array", imm) || !value(a, depth + 1)) return false; }
        if (n->arity >= 1 && !value(a, depth + 1)) return false;
        if (n->arity == 2 && !value(b, depth + 1)) return false;
        if (!more() || tok[at] != ")") return fail("(" + op + " …) takes " + std::to_string(n->arity < 0 ? 2 : n->arity) + " values");
        ++at;
        out = ex(n->op, a, b, imm); return err.empty();
    }

    bool line(const std::string &s) {
        lex(s);
        if (!more()) return fail("an empty instruction");
        Op p; p.x = p.v = p.m = 0;
        std::string m = tok[at];
        if (!m.empty() && m.back() == ':') {                 // a mode prefix
            m.pop_back(); ++at;
            size_t i = 0;
            while (i <= m.size()) {
                size_t j = m.find('+', i); if (j == std::string::npos) j = m.size();
                const std::string w = m.substr(i, j - i);
                if (w == "code") p.modes |= kCode; else if (w == "decode") p.modes |= kDecode; else if (w == "price") p.modes |= kPrice;
                else return fail("no such mode: " + w);
                i = j + 1;
            }
            if (!more()) return fail("a mode without an instruction");
        }
        const std::string mn = tok[at++];
        int code = -1; for (size_t i = 0; i < Sigs().size(); ++i) if (mn == Sigs()[i].name) code = (int)i;
        if (code < 0) return fail("no such instruction: " + mn);
        p.op = (uint8_t)code;
        const Sig &sg = Sigs()[(size_t)code];
        bool fr = false;
        if (sg.freeable && peek() == "free") { fr = true; ++at; p.flags = kFree; }
        for (const Arg &a : sg.args) {
            if (fr && a.field == 'v') continue;
            if (a.opt && !more()) continue;                              // left out: no bound
            if (a.opt) p.flags |= kBounded;                              // given: a bounded run (0 too)
            uint32_t v = 0; uint16_t e = 0;
            switch (a.kind) {
                case kE: if (!value(e)) return false; (a.field == 'x' ? p.x : a.field == 'v' ? p.v : p.m) = e; break;
                case kR: if (!reg(v)) return false; p.tgt = (uint8_t)v; break;
                case kB: if (!reg(v)) return false; p.nb = (uint8_t)v; break;
                case kN: if (!more() || !number(tok[at], v) || v > 255) return fail("not a count: " + peek()); ++at; p.nb = (uint8_t)v; break;
                case kH: if (!nameOf(huffs, "code", v)) return false; p.imm = v; break;
                case kA: if (!nameOf(arrays, "array", v) || v > 255) return fail("no such array"); p.nb = (uint8_t)v; break;
                case kF: if (!more()) return fail("a family is missing");
                         if (tok[at] == "lz4hc") p.nb = kFamilyLz4hc; else if (tok[at] == "zlib") p.nb = kFamilyZlib; else return fail("no such family: " + tok[at]);
                         ++at; break;
                case kK: if (!more() || !number(tok[at], v)) return fail("not a number: " + peek()); ++at; p.imm = v; break;
                case kT: if (!nameOf(tables, "table", v)) return false; p.imm = v; break;
                case kL: if (!more() || tok[at].size() < 2 || tok[at][0] != '@') return fail("not a label: " + peek());
                         fix.push_back({D.ops.size(), tok[at].substr(1)}); ++at; break;
            }
        }
        if (more()) return fail("more than " + mn + " takes: " + tok[at]);
        if (D.ops.size() >= 65535) return fail("too many instructions");
        D.ops.push_back(p);
        return true;
    }
};

bool Ident(const std::string &s) {
    if (s.empty() || s.size() > 64 || !(std::isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    for (char c : s) if (!(std::isalnum((unsigned char)c) || c == '_' || c == '.')) return false;
    return true;
}

bool U32(const ojson &j, uint32_t &v) {
    if (!j.is_number_unsigned() && !(j.is_number_integer() && j.get<int64_t>() >= 0)) return false;
    const uint64_t x = j.get<uint64_t>(); if (x > 0xFFFFFFFFu) return false; v = (uint32_t)x; return true;
}

}  // namespace

bool Read(const std::string &Text, Description &Out, std::string &Err, TextNames *Names) {
    Out = Description();
    if (Names) *Names = TextNames();
    if (Text.size() > (64u << 20)) { Err = "a description too large"; return false; }
    ojson J;
    try { J = ojson::parse(Text); } catch (const std::exception &e) { Err = std::string("not a description (") + e.what() + ")"; return false; }
    //a node: the description its CODED layers carry (one: a node coding several formats names the layer, by giving its
    //description alone)
    if (J.is_object() && J.contains("LAYERS") && J["LAYERS"].is_array()) {
        ojson One;
        for (const auto &L : J["LAYERS"])
            if (L.is_object() && L.contains("CODED") && L.contains("DESCRIPTION") && L["DESCRIPTION"].is_object()) {
                if (!One.is_null() && One != L["DESCRIPTION"]) { Err = "a node whose CODED layers carry different descriptions: give the one meant alone"; return false; }
                One = L["DESCRIPTION"];
            }
        if (One.is_null()) { Err = "a node with no CODED layer carrying a description"; return false; }
        J = One;
    }
    if (!J.is_object()) { Err = "not a description"; return false; }
    Description D;
    Reader R{D};
    auto bad = [&](const std::string &m) { Err = m; return false; };
    static const std::vector<std::string> known = {"NAME", "ISA", "MODE", "NAMES", "CODER", "SHIFT", "SLOTS", "WINDOW", "MAXLEN", "LEN1SLOT", "HISTORY",
                                                   "TOKEN", "REGISTERS", "TABLES", "ARRAYS", "HUFFS", "ENTRY", "TOKEN_ENTRY", "CODE"};
    for (auto it = J.begin(); it != J.end(); ++it)
        if (std::find(known.begin(), known.end(), it.key()) == known.end()) return bad("an unknown description field: " + it.key());
    uint32_t v = 0;
    if (!J.contains("NAME") || !J["NAME"].is_string()) return bad("a description needs a NAME");
    D.name = J["NAME"].get<std::string>();
    if (!J.contains("ISA") || !U32(J["ISA"], D.isa)) return bad("a description needs its ISA");
    if (J.contains("MODE")) {                          // ISA 10: "VIEW" lists the files in a content (viewmode.h)
        if (!J["MODE"].is_string() || J["MODE"].get<std::string>() != "VIEW") return bad("MODE is \"VIEW\" (a codec names none)");
        D.view = true;
        if (J.contains("CODER")) return bad("a view has no CODER");
        if (!J.contains("NAMES") || !J["NAMES"].is_string()) return bad("a view says how its names are written: NAMES utf-8, ascii, latin-1, utf-16be, cp932 or cp437");
        const std::string n = J["NAMES"].get<std::string>();
        if (n == "utf-8") D.names = kNamesUtf8; else if (n == "ascii") D.names = kNamesAscii; else if (n == "latin-1") D.names = kNamesLatin1;
        else if (n == "utf-16be") D.names = kNamesUtf16be; else if (n == "cp932") D.names = kNamesCp932; else if (n == "cp437") D.names = kNamesCp437;
        else return bad("no such NAMES encoding: " + n);
    } else {
        if (J.contains("NAMES")) return bad("NAMES belongs to a view (MODE \"VIEW\")");
        if (!J.contains("CODER") || !J["CODER"].is_string()) return bad("a description needs its CODER (BITS or RANGE)");
        const std::string c = J["CODER"].get<std::string>(); if (c == "BITS") D.coder = kBits; else if (c == "BITS16M") D.coder = kBits16M; else if (c == "RANGE") D.coder = kRange; else return bad("no such coder: " + c);
    }
    auto num = [&](const char *k, uint32_t &dst, uint32_t max) {
        if (!J.contains(k)) return true;
        if (!U32(J[k], dst) || dst > max) { Err = std::string("a bad ") + k; return false; }
        return true;
    };
    uint32_t shift = 5, len1 = 0;
    if (!num("SHIFT", shift, 15) || !num("SLOTS", D.nslots, 0xFFFFFFFFu) || !num("WINDOW", D.window, 0xFFFFFFFFu) ||
        !num("MAXLEN", D.maxlen, 0xFFFFFFFFu) || !num("LEN1SLOT", len1, 127)) return false;
    D.shift = (uint8_t)shift;
    D.len1slot = J.contains("LEN1SLOT") ? (int8_t)len1 : (int8_t)-1;
    if (J.contains("REGISTERS")) {
        if (!J["REGISTERS"].is_object()) return bad("REGISTERS is { name: number }");
        for (auto it = J["REGISTERS"].begin(); it != J["REGISTERS"].end(); ++it) {
            const std::string &n = it.key();
            bool clash = n.size() >= 2 && n[0] == 'r' && std::isdigit((unsigned char)n[1]);
            for (const auto &e : ExNames()) clash |= n == e.name;
            if (!Ident(n) || clash || n == "free") return bad("not a register name: " + n);
            if (!U32(it.value(), v) || v >= (uint32_t)kRegs) return bad("register " + n + " names no register");
            R.regs[n] = v;
        }
    }
    auto namedList = [&](const char *k, std::map<std::string, uint32_t> &M, size_t max, auto &&each) -> bool {
        if (!J.contains(k)) return true;
        const ojson &X = J[k];
        if (!X.is_object()) { Err = std::string(k) + " is { name: … }"; return false; }
        if (X.size() > max) { Err = std::string("too many ") + k; return false; }
        //numbered in NAME order, never in the order the text lists them: a JSON object has no key order a reader keeps
        //(a mount reads the description back from its spec with its keys sorted), and records store arrays by number
        std::vector<std::string> names;
        for (auto it = X.begin(); it != X.end(); ++it) {
            if (!Ident(it.key())) { Err = std::string("a bad name in ") + k + ": " + it.key(); return false; }
            names.push_back(it.key());
        }
        std::sort(names.begin(), names.end());
        for (uint32_t i = 0; i < names.size(); ++i) {
            if (i && names[i] == names[i - 1]) { Err = std::string("a name twice in ") + k + ": " + names[i]; return false; }
            M[names[i]] = i;
            if (!each(X[names[i]], names[i])) return false;
        }
        return true;
    };
    if (!namedList("TABLES", R.tables, 16, [&](const ojson &t, const std::string &n) {
            if (!t.is_array() || t.size() > (1u << 20)) { Err = "table " + n + " is a list of numbers"; return false; }
            std::vector<uint32_t> T; T.reserve(t.size());
            for (const auto &x : t) { uint32_t y; if (!U32(x, y)) { Err = "table " + n + " is a list of numbers"; return false; } T.push_back(y); }
            D.tables.push_back(std::move(T)); return true; }))
        return false;
    if (!namedList("ARRAYS", R.arrays, 16, [&](const ojson &a, const std::string &n) {
            uint32_t size = 0;
            if (!a.is_object() || !a.contains("SIZE") || !U32(a["SIZE"], size) || size > (1u << 20)) { Err = "array " + n + " is { SIZE, INIT }"; return false; }
            for (auto it = a.begin(); it != a.end(); ++it) if (it.key() != "SIZE" && it.key() != "INIT") { Err = "array " + n + " is { SIZE, INIT }"; return false; }
            std::vector<uint32_t> A(size, 0);
            if (a.contains("INIT")) {
                const ojson &in = a["INIT"];
                if (!in.is_array() || in.size() > size) { Err = "array " + n + ": INIT longer than SIZE"; return false; }
                for (size_t i = 0; i < in.size(); ++i) if (!U32(in[i], A[i])) { Err = "array " + n + ": INIT is numbers"; return false; }
            }
            D.arrays.push_back(std::move(A)); return true; }))
        return false;
    if (J.contains("HUFFS")) {
        const ojson &H = J["HUFFS"];
        if (!H.is_array() || H.size() > 255) return bad("HUFFS is a list of names");
        for (size_t i = 0; i < H.size(); ++i) {
            if (!H[i].is_string() || !Ident(H[i].get<std::string>()) || R.huffs.count(H[i].get<std::string>())) return bad("HUFFS is a list of names");
            R.huffs[H[i].get<std::string>()] = (uint32_t)i;
        }
        D.nhuff = (uint8_t)H.size();
    }
    if (J.contains("HISTORY")) {
        const ojson &H = J["HISTORY"]; uint32_t from = 0, count = 0;
        if (!H.is_object() || !H.contains("FROM") || !H["FROM"].is_string() || !R.regName(H["FROM"].get<std::string>(), from) ||
            !H.contains("COUNT") || !U32(H["COUNT"], count) || count > (uint32_t)kRegs || H.size() != 2)
            return bad("HISTORY is { FROM: register, COUNT: number }");
        D.histbase = (uint8_t)from; D.histlen = (uint8_t)count;
    }
    if (J.contains("TOKEN")) {
        const ojson &T = J["TOKEN"];
        if (!T.is_object() || T.size() != 4) return bad("TOKEN is { KIND, LENGTH, SLOT, DISTANCE } registers");
        uint8_t *dst[4] = {&D.tokK, &D.tokL, &D.tokSL, &D.tokD}; const char *keys[4] = {"KIND", "LENGTH", "SLOT", "DISTANCE"};
        for (int i = 0; i < 4; ++i) {
            uint32_t r = 0;
            if (!T.contains(keys[i]) || !T[keys[i]].is_string() || !R.regName(T[keys[i]].get<std::string>(), r)) return bad("TOKEN is { KIND, LENGTH, SLOT, DISTANCE } registers");
            *dst[i] = (uint8_t)r;
        }
    }
    if (!J.contains("CODE") || !J["CODE"].is_array()) return bad("a description needs its CODE");
    R.ex(EX_CONST, 0, 0, 0);                                 // expression 0: the constant 0 (every field an op leaves unnamed)
    size_t n = 0;
    for (const auto &L : J["CODE"]) {
        ++n;
        if (!L.is_string()) return bad("CODE line " + std::to_string(n) + " is not a string");
        std::string s = L.get<std::string>();
        size_t a = s.find_first_not_of(" \t"); if (a == std::string::npos) continue;
        s = s.substr(a);
        if (s[0] == '#') continue;
        if (s[0] == '@') {
            const std::string name = s.substr(1, s.find_last_not_of(" \t"));
            if (!Ident(name)) return bad("CODE line " + std::to_string(n) + ": a bad label");
            if (R.labels.count(name)) return bad("label @" + name + " twice");
            R.labels[name] = (uint32_t)D.ops.size();
            continue;
        }
        if (!R.line(s)) return bad("CODE line " + std::to_string(n) + " (" + (s.size() > 120 ? s.substr(0, 117) + "..." : s) + "): " + R.err);
    }
    for (const auto &f : R.fix) {
        auto it = R.labels.find(f.second);
        if (it == R.labels.end() || it->second >= D.ops.size()) return bad("no instruction at label @" + f.second);
        D.ops[f.first].target = (uint16_t)it->second;
    }
    auto entry = [&](const char *k, int32_t &dst) {
        if (!J[k].is_string()) { Err = std::string(k) + " is a label"; return false; }
        const std::string l = J[k].get<std::string>();
        auto it = l.size() > 1 && l[0] == '@' ? R.labels.find(l.substr(1)) : R.labels.end();
        if (it == R.labels.end() || it->second >= D.ops.size()) { Err = std::string(k) + ": no instruction at " + l; return false; }
        dst = (int32_t)it->second; return true;
    };
    if (!J.contains("ENTRY")) return bad("a description needs its ENTRY");
    int32_t es = 0;
    if (!entry("ENTRY", es)) return false;
    D.entryStream = (uint16_t)es;
    if (J.contains("TOKEN_ENTRY") && !entry("TOKEN_ENTRY", D.entryToken)) return false;
    if (!R.err.empty()) return bad(R.err);
    if (!Validate(D, Err)) return false;
    if (Names) {                                              // what the text named, for printing it back as it was
        for (const auto &kv : R.regs) Names->regs.emplace((int)kv.second, kv.first);
        for (const auto &kv : R.labels) Names->labels.emplace((int)kv.second, kv.first);
        auto list = [](const std::map<std::string, uint32_t> &M, size_t Count) {
            std::vector<std::string> L(Count); for (const auto &kv : M) if (kv.second < Count) L[kv.second] = kv.first; return L; };
        Names->tables = list(R.tables, D.tables.size()); Names->arrays = list(R.arrays, D.arrays.size()); Names->huffs = list(R.huffs, D.nhuff);
    }
    Out = std::move(D);
    return true;
}

std::vector<uint8_t> Serialize(const Description &D) {
    std::string t, err;
    if (!Print(D, t, err)) return {};
    return std::vector<uint8_t>(t.begin(), t.end());
}

bool Parse(const uint8_t *Data, size_t N, Description &D, std::string &Err) {
    return Read(std::string((const char *)Data, N), D, Err);
}

}  // namespace coding
