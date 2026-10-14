// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Sys} from "./System.sol";
import {Bytes, P256, Pem, SgxExtension, X509} from "./TeeLib.sol";

interface ITeeCollateral {
    function cas(bytes32 subject) external view returns (bytes32 x, bytes32 y, uint64 notAfter);
    function revoked(bytes32 issuer, bytes32 serial) external view returns (bool);
    function tdxStatus(
        bytes6 fmspc,
        uint8[16] calldata compSvn,
        uint16 pcesvn,
        bytes16 teeTcbSvn,
        bytes calldata mrSignerSeam,
        bytes8 seamAttributes
    ) external view returns (uint8 status, uint64 nextUpdate);
    function qeStatus(bytes4 miscselect, bytes16 attributes, bytes32 mrsigner, uint16 isvprodid, uint16 isvsvn)
        external
        view
        returns (uint8, uint64);
}

/// @title Intel TDX quote verification (ADR 0013 §6.1): DCAP quote v4 with an ECDSA-256 (P-256)
/// attestation key, checked against the collateral in `TeeCollateral`.
/// @notice Steps: the TD report is signed by the attestation key; the quoting enclave's report
/// binds that key and is signed by the platform's PCK key; the PCK certificate is issued by a
/// known Intel CA (under the root) and not revoked; the platform's TCB level and the quoting
/// enclave are looked up in Intel's signed collateral, which must not be older than its own
/// `nextUpdate` plus a grace period. Debug TDs are refused.
contract TdxVerifier {
    /// How long collateral past its `nextUpdate` is still accepted.
    uint256 public constant COLLATERAL_GRACE = 14 days;

    uint256 internal constant HEADER = 48;
    uint256 internal constant BODY = 584;
    uint256 internal constant QE_REPORT = 384;

    struct Result {
        uint8 tcbStatus; // TeeCollateral status (1 = UpToDate …)
        uint8 qeStatus;
        bytes32 machineId; // keccak256(PPID)
        bytes6 fmspc;
        bytes16 teeTcbSvn;
        bytes mrSeam;
        bytes8 tdAttributes;
        bytes8 xfam;
        bytes mrTd; // 48 bytes
        bytes rtmr0;
        bytes rtmr1;
        bytes rtmr2;
        bytes rtmr3;
        bytes reportData; // 64 bytes
        uint8[16] compSvn;
        uint16 pcesvn;
        bytes32 pckSerial;
        bytes32 pckIssuer; // keccak256 of the PCK certificate's issuer Name
        bytes mrSignerSeam;
        bytes8 seamAttributes;
    }

    error BadQuote(string why);
    error StaleCollateral();
    error Revoked();
    error DebugTd();

    /// Verifies `quote` and returns what it attests. Reverts when any check fails; a platform
    /// whose TCB is not up to date still verifies (the status is returned for the caller to
    /// judge), an unknown TCB level does not.
    function verify(bytes calldata quote) external view returns (Result memory r) {
        bytes memory q = quote;
        if (q.length < HEADER + BODY + 4 + 128 + 6) revert BadQuote("short");
        if (Bytes.le(q, 0, 2) != 4) revert BadQuote("version");
        if (Bytes.le(q, 2, 2) != 2) revert BadQuote("attestation key type");
        if (Bytes.le(q, 4, 4) != 0x81) revert BadQuote("not a TD quote");

        // TD report body.
        uint256 b = HEADER;
        r.teeTcbSvn = bytes16(Bytes.word(q, b));
        r.mrSeam = Bytes.slice(q, b + 16, 48);
        r.mrSignerSeam = Bytes.slice(q, b + 64, 48);
        r.seamAttributes = bytes8(Bytes.word(q, b + 112));
        r.tdAttributes = bytes8(Bytes.word(q, b + 120));
        r.xfam = bytes8(Bytes.word(q, b + 128));
        r.mrTd = Bytes.slice(q, b + 136, 48);
        r.rtmr0 = Bytes.slice(q, b + 328, 48);
        r.rtmr1 = Bytes.slice(q, b + 376, 48);
        r.rtmr2 = Bytes.slice(q, b + 424, 48);
        r.rtmr3 = Bytes.slice(q, b + 472, 48);
        r.reportData = Bytes.slice(q, b + 520, 64);
        if (uint8(r.tdAttributes[0]) & 1 != 0) revert DebugTd();

        // Signature data: signature over header + body, attestation key, certification data.
        uint256 s = HEADER + BODY;
        uint256 sigLen = Bytes.le(q, s, 4);
        s += 4;
        if (s + sigLen > q.length) revert BadQuote("signature data");
        bytes32 akX = Bytes.word(q, s + 64);
        bytes32 akY = Bytes.word(q, s + 96);
        if (!P256.verify(Bytes.sha(q, 0, HEADER + BODY), Bytes.word(q, s), Bytes.word(q, s + 32), akX, akY)) {
            revert BadQuote("TD report signature");
        }
        uint256 c = s + 128;
        if (Bytes.le(q, c, 2) != 6) revert BadQuote("certification data type");
        c += 6; // type and size
        uint256 qeReport = c;
        bytes memory qeSig = Bytes.slice(q, c + QE_REPORT, 64);
        uint256 authLen = Bytes.le(q, c + QE_REPORT + 64, 2);
        uint256 auth = c + QE_REPORT + 66;
        // The QE report binds the attestation key: report data = sha256(key ‖ auth data) ‖ 0^32.
        bytes32 bind = sha256(abi.encodePacked(akX, akY, Bytes.slice(q, auth, authLen)));
        if (Bytes.word(q, qeReport + 320) != bind || !Bytes.isZero(q, qeReport + 352, 32)) {
            revert BadQuote("QE report data");
        }
        uint256 cert = auth + authLen;
        if (Bytes.le(q, cert, 2) != 5) revert BadQuote("PCK chain type");
        uint256 chainLen = Bytes.le(q, cert + 2, 4);
        bytes[] memory chain = Pem.certs(Bytes.slice(q, cert + 6, chainLen));
        if (chain.length == 0) revert BadQuote("PCK chain");

        // PCK certificate: issued by a known Intel CA, valid, not revoked; signs the QE report.
        X509.Cert memory pck = X509.parse(chain[0]);
        ITeeCollateral col = ITeeCollateral(Sys.COLLATERAL);
        {
            (bytes32 cx, bytes32 cy, uint64 caNotAfter) = col.cas(pck.issuer);
            if (cx == 0) revert BadQuote("unknown PCK issuer");
            if (block.timestamp > caNotAfter || block.timestamp > pck.notAfter || block.timestamp < pck.notBefore) {
                revert BadQuote("PCK certificate expired");
            }
            if (!X509.signedBy(chain[0], pck, cx, cy)) revert BadQuote("PCK certificate signature");
            if (col.revoked(pck.issuer, pck.serial)) revert Revoked();
        }
        if (!P256.verifyRaw(Bytes.slice(q, qeReport, QE_REPORT), qeSig, pck.keyX, pck.keyY)) {
            revert BadQuote("QE report signature");
        }
        SgxExtension.Pck memory ext = SgxExtension.parse(chain[0], pck);
        r.machineId = keccak256(abi.encodePacked(ext.ppid));
        r.fmspc = ext.fmspc;
        r.compSvn = ext.compSvn;
        r.pcesvn = ext.pcesvn;
        r.pckSerial = pck.serial;
        r.pckIssuer = pck.issuer;

        // Collateral.
        uint64 next;
        (r.tcbStatus, next) = col.tdxStatus(ext.fmspc, ext.compSvn, ext.pcesvn, r.teeTcbSvn, r.mrSignerSeam, r.seamAttributes);
        if (r.tcbStatus == 0) revert BadQuote("TCB level unknown");
        if (block.timestamp > next + COLLATERAL_GRACE) revert StaleCollateral();
        (r.qeStatus, next) = col.qeStatus(
            bytes4(Bytes.word(q, qeReport + 16)),
            bytes16(Bytes.word(q, qeReport + 48)),
            Bytes.word(q, qeReport + 128),
            uint16(Bytes.le(q, qeReport + 256, 2)),
            uint16(Bytes.le(q, qeReport + 258, 2))
        );
        if (r.qeStatus == 0) revert BadQuote("quoting enclave unknown");
        if (block.timestamp > next + COLLATERAL_GRACE) revert StaleCollateral();
    }

    /// keccak256 of the measurements an image registers for TDX: MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2.
    function measurementOf(Result memory r) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(r.mrTd, r.rtmr0, r.rtmr1, r.rtmr2));
    }
}
