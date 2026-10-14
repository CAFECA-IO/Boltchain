// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title Parsing and signature helpers for TEE attestation (ADR 0013): P-256 (EIP-7951
/// precompile), DER / X.509 / CRL, a small JSON reader, base64 and dates.
/// @notice Written for Intel's attestation formats (DCAP quotes, PCK certificates, TCB info, QE
/// identity, CRLs); they reject anything they do not understand rather than guess.

/// P-256 ECDSA verification through the EIP-7951 precompile (0x100, Osaka).
library P256 {
    address internal constant PRECOMPILE = address(0x100);

    function verify(bytes32 hash, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
        (bool ok, bytes memory out) = PRECOMPILE.staticcall(abi.encodePacked(hash, r, s, x, y));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    /// Verifies a raw 64-byte (r ‖ s) signature over sha256(message).
    function verifyRaw(bytes memory message, bytes memory sig64, bytes32 x, bytes32 y) internal view returns (bool) {
        if (sig64.length != 64) return false;
        return verify(sha256(message), Bytes.word(sig64, 0), Bytes.word(sig64, 32), x, y);
    }
}

/// Byte helpers.
library Bytes {
    error OutOfBounds();

    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > b.length) revert OutOfBounds();
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[start + i];
        }
    }

    /// 32 bytes at `p` (zero-padded on the right past the end is not allowed).
    function word(bytes memory b, uint256 p) internal pure returns (bytes32 w) {
        if (p + 32 > b.length) revert OutOfBounds();
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), p))
        }
    }

    /// Little-endian unsigned integer of `n` bytes at `p`.
    function le(bytes memory b, uint256 p, uint256 n) internal pure returns (uint256 v) {
        if (p + n > b.length) revert OutOfBounds();
        for (uint256 i = 0; i < n; i++) {
            v |= uint256(uint8(b[p + i])) << (8 * i);
        }
    }

    /// Big-endian unsigned integer of `n` (≤ 32) bytes at `p`.
    function be(bytes memory b, uint256 p, uint256 n) internal pure returns (uint256 v) {
        if (p + n > b.length) revert OutOfBounds();
        for (uint256 i = 0; i < n; i++) {
            v = (v << 8) | uint256(uint8(b[p + i]));
        }
    }

    function hash(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes32 h) {
        if (start + len > b.length) revert OutOfBounds();
        assembly ("memory-safe") {
            h := keccak256(add(add(b, 32), start), len)
        }
    }

    function sha(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes32) {
        return sha256(slice(b, start, len));
    }

    function eq(bytes memory b, uint256 start, uint256 len, bytes memory other) internal pure returns (bool) {
        return other.length == len && hash(b, start, len) == keccak256(other);
    }

    function isZero(bytes memory b, uint256 start, uint256 len) internal pure returns (bool) {
        if (start + len > b.length) revert OutOfBounds();
        for (uint256 i = 0; i < len; i++) {
            if (b[start + i] != 0) return false;
        }
        return true;
    }
}

/// Days and seconds since the Unix epoch.
library Dates {
    error BadDate();

    /// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
    function daysFrom(uint256 y, uint256 m, uint256 d) internal pure returns (uint256) {
        if (m < 1 || m > 12 || d < 1 || d > 31 || y < 1970) revert BadDate();
        int256 yy = int256(y) - (m <= 2 ? int256(1) : int256(0));
        int256 era = yy / 400;
        int256 yoe = yy - era * 400;
        int256 mp = (int256(m) + 9) % 12;
        int256 doy = (153 * mp + 2) / 5 + int256(d) - 1;
        int256 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return uint256(era * 146097 + doe - 719468);
    }

    function timestamp(uint256 y, uint256 mo, uint256 d, uint256 h, uint256 mi, uint256 s)
        internal
        pure
        returns (uint256)
    {
        if (h > 23 || mi > 59 || s > 60) revert BadDate();
        return daysFrom(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
    }

    function digits(bytes memory b, uint256 p, uint256 n) internal pure returns (uint256 v) {
        if (p + n > b.length) revert BadDate();
        for (uint256 i = 0; i < n; i++) {
            uint8 c = uint8(b[p + i]);
            if (c < 48 || c > 57) revert BadDate();
            v = v * 10 + (c - 48);
        }
    }

    /// "YYYY-MM-DDTHH:MM:SSZ" at `p`.
    function iso(bytes memory b, uint256 p) internal pure returns (uint256) {
        return timestamp(
            digits(b, p, 4),
            digits(b, p + 5, 2),
            digits(b, p + 8, 2),
            digits(b, p + 11, 2),
            digits(b, p + 14, 2),
            digits(b, p + 17, 2)
        );
    }
}

/// Distinguished Encoding Rules: just enough to walk X.509 certificates and CRLs.
library Der {
    error BadDer();

    /// The element at `p`: its tag, where its content starts and its content length.
    function read(bytes memory d, uint256 p) internal pure returns (uint8 tag, uint256 start, uint256 len) {
        if (p + 2 > d.length) revert BadDer();
        tag = uint8(d[p]);
        uint8 l = uint8(d[p + 1]);
        if (l < 0x80) {
            start = p + 2;
            len = l;
        } else {
            uint256 n = l & 0x7f;
            if (n == 0 || n > 4 || p + 2 + n > d.length) revert BadDer();
            len = Bytes.be(d, p + 2, n);
            start = p + 2 + n;
        }
        if (start + len > d.length) revert BadDer();
    }

    /// The element after the one at `p`.
    function next(bytes memory d, uint256 p) internal pure returns (uint256) {
        (, uint256 start, uint256 len) = read(d, p);
        return start + len;
    }

    /// Content of the element at `p`, requiring tag `want`.
    function expect(bytes memory d, uint256 p, uint8 want) internal pure returns (uint256 start, uint256 len) {
        uint8 tag;
        (tag, start, len) = read(d, p);
        if (tag != want) revert BadDer();
    }

    /// An INTEGER's value as up to 32 big-endian bytes (leading zero byte dropped).
    function integer32(bytes memory d, uint256 p) internal pure returns (bytes32 v) {
        (uint256 s, uint256 n) = expect(d, p, 0x02);
        while (n > 0 && d[s] == 0) {
            s++;
            n--;
        }
        if (n > 32) revert BadDer();
        v = bytes32(Bytes.be(d, s, n));
    }

    /// UTCTime or GeneralizedTime at `p`, in Unix seconds.
    function time(bytes memory d, uint256 p) internal pure returns (uint256) {
        (uint8 tag, uint256 s, uint256 n) = read(d, p);
        if (tag == 0x17 && n == 13) {
            uint256 yy = Dates.digits(d, s, 2);
            uint256 y = yy >= 50 ? 1900 + yy : 2000 + yy;
            return Dates.timestamp(
                y, Dates.digits(d, s + 2, 2), Dates.digits(d, s + 4, 2), Dates.digits(d, s + 6, 2),
                Dates.digits(d, s + 8, 2), Dates.digits(d, s + 10, 2)
            );
        }
        if (tag == 0x18 && n == 15) {
            return Dates.timestamp(
                Dates.digits(d, s, 4), Dates.digits(d, s + 4, 2), Dates.digits(d, s + 6, 2),
                Dates.digits(d, s + 8, 2), Dates.digits(d, s + 10, 2), Dates.digits(d, s + 12, 2)
            );
        }
        revert BadDer();
    }

    /// An ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) inside a BIT STRING at `p`.
    function ecdsaSig(bytes memory d, uint256 p) internal pure returns (bytes32 r, bytes32 s) {
        (uint256 bs,) = expect(d, p, 0x03);
        if (d[bs] != 0) revert BadDer(); // no unused bits
        (uint256 seq,) = expect(d, bs + 1, 0x30);
        r = integer32(d, seq);
        s = integer32(d, next(d, seq));
    }
}

/// An X.509 certificate with a P-256 key, signed with ECDSA-SHA256 (as all of Intel's
/// attestation certificates are).
library X509 {
    error BadCert();

    struct Cert {
        uint256 tbsStart; // offset of the to-be-signed element (header included)
        uint256 tbsLen;
        bytes32 serial;
        bytes32 issuer; // keccak256 of the issuer Name element
        bytes32 subject; // keccak256 of the subject Name element
        uint256 notBefore;
        uint256 notAfter;
        bytes32 keyX;
        bytes32 keyY;
        bytes32 sigR;
        bytes32 sigS;
        uint256 extStart; // content of the extensions SEQUENCE (0 if none)
        uint256 extLen;
    }

    function parse(bytes memory d) internal pure returns (Cert memory c) {
        (uint256 cert,) = Der.expect(d, 0, 0x30);
        c.tbsStart = cert;
        (uint256 tbs, uint256 tbsLen) = Der.expect(d, cert, 0x30);
        c.tbsLen = tbs + tbsLen - cert;
        uint256 p = tbs;
        (uint8 tag,,) = Der.read(d, p);
        if (tag == 0xa0) p = Der.next(d, p); // version
        c.serial = Der.integer32(d, p);
        p = Der.next(d, p); // serial
        p = Der.next(d, p); // signature algorithm
        c.issuer = _element(d, p);
        p = Der.next(d, p);
        (uint256 v,) = Der.expect(d, p, 0x30); // validity
        c.notBefore = Der.time(d, v);
        c.notAfter = Der.time(d, Der.next(d, v));
        p = Der.next(d, p);
        c.subject = _element(d, p);
        p = Der.next(d, p);
        (uint256 spki,) = Der.expect(d, p, 0x30);
        (uint256 key, uint256 keyLen) = Der.expect(d, Der.next(d, spki), 0x03);
        if (keyLen != 66 || d[key] != 0 || d[key + 1] != 0x04) revert BadCert();
        c.keyX = Bytes.word(d, key + 2);
        c.keyY = Bytes.word(d, key + 34);
        p = Der.next(d, p);
        uint256 end = tbs + tbsLen;
        while (p < end) {
            (uint8 t, uint256 s, uint256 n) = Der.read(d, p);
            if (t == 0xa3) {
                (c.extStart, c.extLen) = Der.expect(d, s, 0x30);
                if (c.extStart + c.extLen > s + n) revert BadCert();
            }
            p = s + n;
        }
        uint256 sigAlg = Der.next(d, cert);
        (c.sigR, c.sigS) = Der.ecdsaSig(d, Der.next(d, sigAlg));
    }

    function _element(bytes memory d, uint256 p) private pure returns (bytes32) {
        (, uint256 s, uint256 n) = Der.read(d, p);
        return Bytes.hash(d, p, s + n - p);
    }

    /// Whether `c` (from `d`) is signed by the P-256 key (x, y).
    function signedBy(bytes memory d, Cert memory c, bytes32 x, bytes32 y) internal view returns (bool) {
        return P256.verify(Bytes.sha(d, c.tbsStart, c.tbsLen), c.sigR, c.sigS, x, y);
    }

    /// The value (OCTET STRING content) of the extension whose OID content is `oid`, or (0, 0).
    function extension(bytes memory d, Cert memory c, bytes memory oid) internal pure returns (uint256, uint256) {
        uint256 p = c.extStart;
        uint256 end = c.extStart + c.extLen;
        while (p < end) {
            (uint256 e, uint256 elen) = Der.expect(d, p, 0x30);
            (uint256 o, uint256 olen) = Der.expect(d, e, 0x06);
            if (Bytes.eq(d, o, olen, oid)) {
                uint256 q = o + olen;
                (uint8 t,,) = Der.read(d, q);
                if (t == 0x01) q = Der.next(d, q); // critical
                return Der.expect(d, q, 0x04);
            }
            p = e + elen;
        }
        return (0, 0);
    }
}

/// The SGX extension of a PCK certificate (OID 1.2.840.113741.1.13.1).
library SgxExtension {
    error BadExtension();

    /// DER content of OID 1.2.840.113741.1.13.1.
    bytes internal constant OID = hex"2a864886f84d010d01";

    struct Pck {
        bytes16 ppid;
        bytes16 cpusvn;
        uint16 pcesvn;
        bytes2 pceid;
        bytes6 fmspc;
        uint8[16] compSvn;
    }

    function parse(bytes memory d, X509.Cert memory c) internal pure returns (Pck memory x) {
        (uint256 v, uint256 vlen) = X509.extension(d, c, OID);
        if (vlen == 0) revert BadExtension();
        (uint256 seq, uint256 seqLen) = Der.expect(d, v, 0x30);
        uint256 p = seq;
        uint256 found;
        while (p < seq + seqLen) {
            (uint256 e, uint256 elen) = Der.expect(d, p, 0x30);
            (uint256 o, uint256 olen) = Der.expect(d, e, 0x06);
            // The component is the last arc under the SGX OID (its first 9 bytes).
            if (olen != 10 || !Bytes.eq(d, o, 9, OID)) {
                p = e + elen;
                continue;
            }
            uint8 arc = uint8(d[o + 9]);
            uint256 val = o + olen;
            if (arc == 1) {
                (uint256 s, uint256 n) = Der.expect(d, val, 0x04);
                if (n != 16) revert BadExtension();
                x.ppid = bytes16(Bytes.word(d, s));
                found |= 1;
            } else if (arc == 2) {
                _tcb(d, val, x);
                found |= 2;
            } else if (arc == 3) {
                (uint256 s, uint256 n) = Der.expect(d, val, 0x04);
                if (n != 2) revert BadExtension();
                x.pceid = bytes2(Bytes.word(d, s));
                found |= 4;
            } else if (arc == 4) {
                (uint256 s, uint256 n) = Der.expect(d, val, 0x04);
                if (n != 6) revert BadExtension();
                x.fmspc = bytes6(Bytes.word(d, s));
                found |= 8;
            }
            p = e + elen;
        }
        if (found != 15) revert BadExtension();
    }

    function _tcb(bytes memory d, uint256 p, Pck memory x) private pure {
        (uint256 seq, uint256 seqLen) = Der.expect(d, p, 0x30);
        uint256 q = seq;
        while (q < seq + seqLen) {
            (uint256 e, uint256 elen) = Der.expect(d, q, 0x30);
            (uint256 o, uint256 olen) = Der.expect(d, e, 0x06);
            if (olen == 11) {
                uint8 arc = uint8(d[o + 10]);
                uint256 val = o + olen;
                if (arc >= 1 && arc <= 16) {
                    x.compSvn[arc - 1] = uint8(uint256(Der.integer32(d, val)));
                } else if (arc == 17) {
                    x.pcesvn = uint16(uint256(Der.integer32(d, val)));
                } else if (arc == 18) {
                    (uint256 s, uint256 n) = Der.expect(d, val, 0x04);
                    if (n != 16) revert BadExtension();
                    x.cpusvn = bytes16(Bytes.word(d, s));
                }
            }
            q = e + elen;
        }
    }
}

/// A certificate revocation list signed with ECDSA-SHA256.
library Crl {
    struct List {
        uint256 tbsStart;
        uint256 tbsLen;
        bytes32 issuer;
        uint256 thisUpdate;
        uint256 nextUpdate;
        bytes32 sigR;
        bytes32 sigS;
        bytes32[] serials;
    }

    function parse(bytes memory d) internal pure returns (List memory l) {
        (uint256 crl,) = Der.expect(d, 0, 0x30);
        l.tbsStart = crl;
        (uint256 tbs, uint256 tbsLen) = Der.expect(d, crl, 0x30);
        l.tbsLen = tbs + tbsLen - crl;
        uint256 end = tbs + tbsLen;
        uint256 p = tbs;
        (uint8 tag,,) = Der.read(d, p);
        if (tag == 0x02) p = Der.next(d, p); // version
        p = Der.next(d, p); // signature algorithm
        (, uint256 iss, uint256 il) = Der.read(d, p);
        l.issuer = Bytes.hash(d, p, iss + il - p);
        p = iss + il;
        l.thisUpdate = Der.time(d, p);
        p = Der.next(d, p);
        (tag,,) = Der.read(d, p);
        if (tag == 0x17 || tag == 0x18) {
            l.nextUpdate = Der.time(d, p);
            p = Der.next(d, p);
        }
        if (p < end) {
            (tag,,) = Der.read(d, p);
            if (tag == 0x30) {
                (uint256 r, uint256 rl) = Der.expect(d, p, 0x30);
                uint256 count;
                for (uint256 q = r; q < r + rl; q = Der.next(d, q)) count++;
                l.serials = new bytes32[](count);
                uint256 i;
                for (uint256 q = r; q < r + rl; q = Der.next(d, q)) {
                    (uint256 e,) = Der.expect(d, q, 0x30);
                    l.serials[i++] = Der.integer32(d, e);
                }
            }
        }
        uint256 sigAlg = Der.next(d, crl);
        (l.sigR, l.sigS) = Der.ecdsaSig(d, Der.next(d, sigAlg));
    }

    function signedBy(bytes memory d, List memory l, bytes32 x, bytes32 y) internal view returns (bool) {
        return P256.verify(Bytes.sha(d, l.tbsStart, l.tbsLen), l.sigR, l.sigS, x, y);
    }
}

/// Standard base64 (with padding, newlines skipped) as used by PEM.
library Base64 {
    error BadBase64();

    function decode(bytes memory s, uint256 start, uint256 end) internal pure returns (bytes memory out) {
        out = new bytes(((end - start) * 3) / 4 + 3);
        uint256 o;
        uint256 acc;
        uint256 bits;
        for (uint256 i = start; i < end; i++) {
            uint8 c = uint8(s[i]);
            uint256 v;
            if (c >= 65 && c <= 90) v = c - 65;
            else if (c >= 97 && c <= 122) v = c - 71;
            else if (c >= 48 && c <= 57) v = c + 4;
            else if (c == 43) v = 62;
            else if (c == 47) v = 63;
            else if (c == 61) break;
            else if (c == 10 || c == 13) continue;
            else revert BadBase64();
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = bytes1(uint8(acc >> bits));
                acc &= (1 << bits) - 1;
            }
        }
        assembly ("memory-safe") {
            mstore(out, o)
        }
    }
}

/// PEM certificate chains (as carried in DCAP quotes).
library Pem {
    error BadPem();

    bytes internal constant BEGIN = "-----BEGIN CERTIFICATE-----";
    bytes internal constant END = "-----END CERTIFICATE-----";

    /// The DER certificates of a PEM chain, in order.
    function certs(bytes memory pem) internal pure returns (bytes[] memory out) {
        uint256 n;
        for (uint256 p = 0; (p = _find(pem, BEGIN, p)) != type(uint256).max; p++) n++;
        out = new bytes[](n);
        uint256 q;
        for (uint256 i = 0; i < n; i++) {
            uint256 b = _find(pem, BEGIN, q);
            uint256 e = _find(pem, END, b);
            if (e == type(uint256).max) revert BadPem();
            out[i] = Base64.decode(pem, b + BEGIN.length, e);
            q = e + END.length;
        }
    }

    function _find(bytes memory h, bytes memory needle, uint256 from) private pure returns (uint256) {
        if (h.length < needle.length) return type(uint256).max;
        bytes32 k = keccak256(needle);
        for (uint256 i = from; i + needle.length <= h.length; i++) {
            if (h[i] == needle[0] && Bytes.hash(h, i, needle.length) == k) return i;
        }
        return type(uint256).max;
    }
}

/// A small JSON reader for Intel's collateral documents: tokens in document order, each with its
/// byte range; objects and arrays are followed by their members.
library Json {
    error BadJson();

    uint8 internal constant OBJECT = 1;
    uint8 internal constant ARRAY = 2;
    uint8 internal constant STRING = 3; // range excludes the quotes
    uint8 internal constant PRIMITIVE = 4;

    struct Token {
        uint8 kind;
        uint32 start;
        uint32 end;
    }

    function parse(bytes memory j) internal pure returns (Token[] memory toks) {
        toks = new Token[](_count(j));
        (uint256 p, uint256 n) = _value(j, _ws(j, 0), toks, 0);
        if (_ws(j, p) != j.length) revert BadJson();
        assembly ("memory-safe") {
            mstore(toks, n)
        }
    }

    // Upper bound on the number of tokens: one per value start character.
    function _count(bytes memory j) private pure returns (uint256 n) {
        bool inStr;
        for (uint256 i = 0; i < j.length; i++) {
            bytes1 c = j[i];
            if (inStr) {
                if (c == "\\") i++;
                else if (c == '"') inStr = false;
            } else if (c == '"') {
                inStr = true;
                n++;
            } else if (c == "{" || c == "[") {
                n += 2; // itself and a first primitive member
            } else if (c == ":" || c == ",") {
                n++;
            }
        }
        n += 2;
    }

    function _ws(bytes memory j, uint256 p) private pure returns (uint256) {
        while (p < j.length && (j[p] == " " || j[p] == "\n" || j[p] == "\r" || j[p] == "\t")) p++;
        return p;
    }

    function _value(bytes memory j, uint256 p, Token[] memory toks, uint256 n) private pure returns (uint256, uint256) {
        if (p >= j.length) revert BadJson();
        bytes1 c = j[p];
        uint256 me = n++;
        if (c == "{" || c == "[") {
            bool obj = c == "{";
            toks[me] = Token(obj ? OBJECT : ARRAY, uint32(p), 0);
            p = _ws(j, p + 1);
            if (p < j.length && j[p] == (obj ? bytes1("}") : bytes1("]"))) {
                toks[me].end = uint32(p + 1);
                return (p + 1, n);
            }
            while (true) {
                if (obj) {
                    if (j[p] != '"') revert BadJson();
                    (p, n) = _value(j, p, toks, n);
                    p = _ws(j, p);
                    if (p >= j.length || j[p] != ":") revert BadJson();
                    p = _ws(j, p + 1);
                }
                (p, n) = _value(j, p, toks, n);
                p = _ws(j, p);
                if (p >= j.length) revert BadJson();
                if (j[p] == ",") {
                    p = _ws(j, p + 1);
                    continue;
                }
                if (j[p] != (obj ? bytes1("}") : bytes1("]"))) revert BadJson();
                toks[me].end = uint32(p + 1);
                return (p + 1, n);
            }
        }
        if (c == '"') {
            uint256 s = p + 1;
            p = s;
            while (p < j.length && j[p] != '"') {
                if (j[p] == "\\") p++;
                p++;
            }
            if (p >= j.length) revert BadJson();
            toks[me] = Token(STRING, uint32(s), uint32(p));
            return (p + 1, n);
        }
        uint256 st = p;
        while (p < j.length && j[p] != "," && j[p] != "}" && j[p] != "]" && j[p] != " " && j[p] != "\n") p++;
        if (p == st) revert BadJson();
        toks[me] = Token(PRIMITIVE, uint32(st), uint32(p));
        return (p, n);
    }

    /// The token after the subtree of token `i`.
    function skip(Token[] memory t, uint256 i) internal pure returns (uint256 k) {
        uint256 end = t[i].kind == STRING ? t[i].end + 1 : t[i].end;
        k = i + 1;
        while (k < t.length && t[k].start < end) k++;
    }

    /// The value of member `key` of object token `obj`, or type(uint256).max.
    function get(bytes memory j, Token[] memory t, uint256 obj, bytes memory key) internal pure returns (uint256) {
        if (t[obj].kind != OBJECT) revert BadJson();
        uint256 k = obj + 1;
        while (k < t.length && t[k].start < t[obj].end) {
            if (t[k].kind == STRING && Bytes.eq(j, t[k].start, t[k].end - t[k].start, key)) return k + 1;
            k = skip(t, k + 1); // past the value
        }
        return type(uint256).max;
    }

    function must(bytes memory j, Token[] memory t, uint256 obj, bytes memory key) internal pure returns (uint256 v) {
        v = get(j, t, obj, key);
        if (v == type(uint256).max) revert BadJson();
    }

    /// Elements of array token `arr`.
    function items(Token[] memory t, uint256 arr) internal pure returns (uint256[] memory out) {
        if (t[arr].kind != ARRAY) revert BadJson();
        uint256 n;
        for (uint256 k = arr + 1; k < t.length && t[k].start < t[arr].end; k = skip(t, k)) n++;
        out = new uint256[](n);
        uint256 i;
        for (uint256 k = arr + 1; k < t.length && t[k].start < t[arr].end; k = skip(t, k)) out[i++] = k;
    }

    function uintOf(bytes memory j, Token memory tok) internal pure returns (uint256 v) {
        if (tok.kind != PRIMITIVE) revert BadJson();
        for (uint256 i = tok.start; i < tok.end; i++) {
            uint8 c = uint8(j[i]);
            if (c < 48 || c > 57) revert BadJson();
            v = v * 10 + (c - 48);
        }
    }

    /// A hex string token's bytes.
    function hexOf(bytes memory j, Token memory tok) internal pure returns (bytes memory out) {
        if (tok.kind != STRING || (tok.end - tok.start) % 2 != 0) revert BadJson();
        out = new bytes((tok.end - tok.start) / 2);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = bytes1(uint8(_nib(j[tok.start + 2 * i]) * 16 + _nib(j[tok.start + 2 * i + 1])));
        }
    }

    function _nib(bytes1 c) private pure returns (uint8) {
        uint8 x = uint8(c);
        if (x >= 48 && x <= 57) return x - 48;
        if (x >= 97 && x <= 102) return x - 87;
        if (x >= 65 && x <= 70) return x - 55;
        revert BadJson();
    }

    function strIs(bytes memory j, Token memory tok, bytes memory s) internal pure returns (bool) {
        return tok.kind == STRING && Bytes.eq(j, tok.start, tok.end - tok.start, s);
    }

    function date(bytes memory j, Token memory tok) internal pure returns (uint256) {
        if (tok.kind != STRING || tok.end - tok.start != 20) revert BadJson();
        return Dates.iso(j, tok.start);
    }
}
