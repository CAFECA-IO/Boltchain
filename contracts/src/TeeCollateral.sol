// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemContract} from "./System.sol";
import {Bytes, Crl, Json, P256, X509} from "./TeeLib.sol";

/// @title Intel attestation collateral (ADR 0013 §6.2): the certificate authorities under the
/// Intel SGX Root CA, revocation lists, TDX TCB information and the TD quoting enclave identity.
/// @notice Every document is signed by Intel and checked here against the root key compiled
/// into this contract, so anyone may submit them: nodes do so automatically from Intel's
/// Provisioning Certification Service. Only newer documents replace older ones.
contract TeeCollateral is SystemContract {
    // ------------------------------------------------------------------ root

    /// Intel SGX Root CA (P-256), the trust anchor of every Intel attestation.
    bytes32 public constant INTEL_ROOT_X = 0x0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5;
    bytes32 public constant INTEL_ROOT_Y = 0x67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394;

    /// Development chains only: a test root replacing Intel's, set at genesis.
    bytes32 public devRootX;
    bytes32 public devRootY;

    // ------------------------------------------------------------------ statuses

    uint8 public constant UNKNOWN = 0;
    uint8 public constant UP_TO_DATE = 1;
    uint8 public constant SW_HARDENING_NEEDED = 2;
    uint8 public constant CONFIGURATION_NEEDED = 3;
    uint8 public constant CONFIGURATION_AND_SW_HARDENING_NEEDED = 4;
    uint8 public constant OUT_OF_DATE = 5;
    uint8 public constant OUT_OF_DATE_CONFIGURATION_NEEDED = 6;
    uint8 public constant REVOKED = 7;

    // ------------------------------------------------------------------ state

    struct Ca {
        bytes32 x;
        bytes32 y;
        uint64 notAfter;
    }

    /// Certificate authorities signed by the root, by keccak256 of their subject Name.
    mapping(bytes32 => Ca) public cas;
    /// Revoked serial numbers per issuer (keccak256 of the issuer Name).
    mapping(bytes32 => mapping(bytes32 => bool)) public revoked;
    mapping(bytes32 => uint64) public crlThisUpdate;
    mapping(bytes32 => uint64) public crlNextUpdate;

    struct TcbLevel {
        bytes16 sgx; // SGX TCB component SVNs
        uint16 pcesvn;
        bytes16 tdx; // TDX TCB component SVNs
        uint8 status;
    }

    struct TcbInfo {
        uint32 evaluation;
        uint64 issueDate;
        uint64 nextUpdate;
        bytes2 pceid;
        bytes8 seamAttributes;
        bytes8 seamAttributesMask;
        bytes seamMrSigner; // 48 bytes
    }

    struct ModuleIdentity {
        bool exists;
        bytes8 attributes;
        bytes8 attributesMask;
        bytes mrsigner;
        uint8[] isvsvn; // descending, with their statuses
        uint8[] status;
    }

    mapping(bytes6 => TcbInfo) internal tcbInfos;
    mapping(bytes6 => TcbLevel[]) internal tcbLevels;
    /// TDX module identities per FMSPC, by major version.
    mapping(bytes6 => mapping(uint8 => ModuleIdentity)) internal modules;

    struct QeIdentity {
        uint32 evaluation;
        uint64 issueDate;
        uint64 nextUpdate;
        bytes4 miscselect;
        bytes4 miscselectMask;
        bytes16 attributes;
        bytes16 attributesMask;
        bytes32 mrsigner;
        uint16 isvprodid;
        uint16[] isvsvn; // descending, with their statuses
        uint8[] status;
    }

    QeIdentity internal qe;

    event CaAdded(bytes32 indexed subject, uint64 notAfter);
    event CrlUpdated(bytes32 indexed issuer, uint64 thisUpdate, uint256 serials);
    event TcbInfoUpdated(bytes6 indexed fmspc, uint32 evaluation, uint64 nextUpdate);
    event QeIdentityUpdated(uint32 evaluation, uint64 nextUpdate);

    error BadSignature();
    error NotNewer();
    error Expired();
    error UnknownSigner();
    error Unsupported();

    // ------------------------------------------------------------------ root

    /// Genesis of development chains: replaces Intel's root with a test root.
    function initDevRoot(bytes32 x, bytes32 y) external onlyGenesis {
        devRootX = x;
        devRootY = y;
    }

    function root() public view returns (bytes32 x, bytes32 y) {
        if (devRootX != 0) return (devRootX, devRootY);
        return (INTEL_ROOT_X, INTEL_ROOT_Y);
    }

    // ------------------------------------------------------------------ certificates and CRLs

    /// Adds a CA certificate signed by the root (PCK Processor CA, PCK Platform CA, TCB Signing).
    function addCa(bytes calldata der) external {
        bytes memory d = der;
        X509.Cert memory c = X509.parse(d);
        (bytes32 rx, bytes32 ry) = root();
        if (!X509.signedBy(d, c, rx, ry)) revert BadSignature();
        if (block.timestamp > c.notAfter || block.timestamp < c.notBefore) revert Expired();
        if (revoked[c.issuer][c.serial]) revert BadSignature();
        cas[c.subject] = Ca(c.keyX, c.keyY, uint64(c.notAfter));
        emit CaAdded(c.subject, uint64(c.notAfter));
    }

    /// A CRL signed by the root or by a known CA; only one issued later than the current one.
    /// Revocations accumulate (a revoked certificate is never reinstated).
    function setCrl(bytes calldata der) external {
        bytes memory d = der;
        Crl.List memory l = Crl.parse(d);
        Ca memory ca = cas[l.issuer];
        bool ok;
        if (ca.x != 0) {
            ok = Crl.signedBy(d, l, ca.x, ca.y);
        } else {
            (bytes32 rx, bytes32 ry) = root();
            ok = Crl.signedBy(d, l, rx, ry);
        }
        if (!ok) revert BadSignature();
        if (l.thisUpdate <= crlThisUpdate[l.issuer]) revert NotNewer();
        crlThisUpdate[l.issuer] = uint64(l.thisUpdate);
        crlNextUpdate[l.issuer] = uint64(l.nextUpdate);
        for (uint256 i = 0; i < l.serials.length; i++) {
            revoked[l.issuer][l.serials[i]] = true;
        }
        emit CrlUpdated(l.issuer, uint64(l.thisUpdate), l.serials.length);
    }

    // ------------------------------------------------------------------ TCB info

    /// TDX TCB info (version 3) as served by Intel PCS: `{"tcbInfo":{…},"signature":"…"}`, signed
    /// by a CA added with `addCa` (the TCB Signing certificate).
    function setTcbInfo(bytes calldata document, bytes32 signer) external {
        bytes memory j = document;
        Json.Token[] memory t = Json.parse(j);
        uint256 info = Json.must(j, t, 0, "tcbInfo");
        _checkSigned(j, t, info, Json.must(j, t, 0, "signature"), signer);
        if (!Json.strIs(j, t[Json.must(j, t, info, "id")], "TDX")) revert Unsupported();
        if (Json.uintOf(j, t[Json.must(j, t, info, "version")]) != 3) revert Unsupported();
        bytes6 fmspc = bytes6(bytes(Json.hexOf(j, t[Json.must(j, t, info, "fmspc")])));
        TcbInfo storage cur = tcbInfos[fmspc];
        uint32 evaluation = uint32(Json.uintOf(j, t[Json.must(j, t, info, "tcbEvaluationDataNumber")]));
        uint64 issueDate = uint64(Json.date(j, t[Json.must(j, t, info, "issueDate")]));
        if (evaluation < cur.evaluation || (evaluation == cur.evaluation && issueDate <= cur.issueDate)) {
            revert NotNewer();
        }
        cur.evaluation = evaluation;
        cur.issueDate = issueDate;
        cur.nextUpdate = uint64(Json.date(j, t[Json.must(j, t, info, "nextUpdate")]));
        cur.pceid = bytes2(bytes(Json.hexOf(j, t[Json.must(j, t, info, "pceId")])));
        uint256 m = Json.must(j, t, info, "tdxModule");
        cur.seamMrSigner = Json.hexOf(j, t[Json.must(j, t, m, "mrsigner")]);
        cur.seamAttributes = bytes8(bytes(Json.hexOf(j, t[Json.must(j, t, m, "attributes")])));
        cur.seamAttributesMask = bytes8(bytes(Json.hexOf(j, t[Json.must(j, t, m, "attributesMask")])));

        delete tcbLevels[fmspc];
        uint256[] memory levels = Json.items(t, Json.must(j, t, info, "tcbLevels"));
        for (uint256 i = 0; i < levels.length; i++) {
            uint256 tcb = Json.must(j, t, levels[i], "tcb");
            tcbLevels[fmspc].push(
                TcbLevel({
                    sgx: _svns(j, t, Json.must(j, t, tcb, "sgxtcbcomponents")),
                    pcesvn: uint16(Json.uintOf(j, t[Json.must(j, t, tcb, "pcesvn")])),
                    tdx: _svns(j, t, Json.must(j, t, tcb, "tdxtcbcomponents")),
                    status: _status(j, t[Json.must(j, t, levels[i], "tcbStatus")])
                })
            );
        }
        uint256 ids = Json.get(j, t, info, "tdxModuleIdentities");
        if (ids != type(uint256).max) {
            uint256[] memory list = Json.items(t, ids);
            for (uint256 i = 0; i < list.length; i++) {
                _moduleIdentity(j, t, list[i], fmspc);
            }
        }
        emit TcbInfoUpdated(fmspc, evaluation, cur.nextUpdate);
    }

    function _moduleIdentity(bytes memory j, Json.Token[] memory t, uint256 obj, bytes6 fmspc) private {
        // "TDX_03": the module's major version in hex.
        Json.Token memory id = t[Json.must(j, t, obj, "id")];
        if (id.kind != Json.STRING || id.end - id.start != 6 || !Bytes.eq(j, id.start, 4, "TDX_")) {
            revert Unsupported();
        }
        uint8 major = uint8(bytes(Json.hexOf(j, Json.Token(Json.STRING, id.start + 4, id.end)))[0]);
        ModuleIdentity storage mi = modules[fmspc][major];
        mi.exists = true;
        mi.mrsigner = Json.hexOf(j, t[Json.must(j, t, obj, "mrsigner")]);
        mi.attributes = bytes8(bytes(Json.hexOf(j, t[Json.must(j, t, obj, "attributes")])));
        mi.attributesMask = bytes8(bytes(Json.hexOf(j, t[Json.must(j, t, obj, "attributesMask")])));
        delete mi.isvsvn;
        delete mi.status;
        uint256[] memory levels = Json.items(t, Json.must(j, t, obj, "tcbLevels"));
        for (uint256 i = 0; i < levels.length; i++) {
            uint256 tcb = Json.must(j, t, levels[i], "tcb");
            mi.isvsvn.push(uint8(Json.uintOf(j, t[Json.must(j, t, tcb, "isvsvn")])));
            mi.status.push(_status(j, t[Json.must(j, t, levels[i], "tcbStatus")]));
        }
    }

    /// The TD quoting enclave identity (`{"enclaveIdentity":{… "id":"TD_QE" …},"signature":"…"}`).
    function setQeIdentity(bytes calldata document, bytes32 signer) external {
        bytes memory j = document;
        Json.Token[] memory t = Json.parse(j);
        uint256 e = Json.must(j, t, 0, "enclaveIdentity");
        _checkSigned(j, t, e, Json.must(j, t, 0, "signature"), signer);
        if (!Json.strIs(j, t[Json.must(j, t, e, "id")], "TD_QE")) revert Unsupported();
        uint32 evaluation = uint32(Json.uintOf(j, t[Json.must(j, t, e, "tcbEvaluationDataNumber")]));
        uint64 issueDate = uint64(Json.date(j, t[Json.must(j, t, e, "issueDate")]));
        if (evaluation < qe.evaluation || (evaluation == qe.evaluation && issueDate <= qe.issueDate)) {
            revert NotNewer();
        }
        qe.evaluation = evaluation;
        qe.issueDate = issueDate;
        qe.nextUpdate = uint64(Json.date(j, t[Json.must(j, t, e, "nextUpdate")]));
        qe.miscselect = bytes4(bytes(Json.hexOf(j, t[Json.must(j, t, e, "miscselect")])));
        qe.miscselectMask = bytes4(bytes(Json.hexOf(j, t[Json.must(j, t, e, "miscselectMask")])));
        qe.attributes = bytes16(bytes(Json.hexOf(j, t[Json.must(j, t, e, "attributes")])));
        qe.attributesMask = bytes16(bytes(Json.hexOf(j, t[Json.must(j, t, e, "attributesMask")])));
        qe.mrsigner = bytes32(bytes(Json.hexOf(j, t[Json.must(j, t, e, "mrsigner")])));
        qe.isvprodid = uint16(Json.uintOf(j, t[Json.must(j, t, e, "isvprodid")]));
        delete qe.isvsvn;
        delete qe.status;
        uint256[] memory levels = Json.items(t, Json.must(j, t, e, "tcbLevels"));
        for (uint256 i = 0; i < levels.length; i++) {
            uint256 tcb = Json.must(j, t, levels[i], "tcb");
            qe.isvsvn.push(uint16(Json.uintOf(j, t[Json.must(j, t, tcb, "isvsvn")])));
            qe.status.push(_status(j, t[Json.must(j, t, levels[i], "tcbStatus")]));
        }
        emit QeIdentityUpdated(evaluation, qe.nextUpdate);
    }

    function _checkSigned(bytes memory j, Json.Token[] memory t, uint256 body, uint256 sig, bytes32 signer) private view {
        Ca memory ca = cas[signer];
        if (ca.x == 0) revert UnknownSigner();
        if (block.timestamp > ca.notAfter) revert Expired();
        bytes memory s = Json.hexOf(j, t[sig]);
        bytes32 h = Bytes.sha(j, t[body].start, t[body].end - t[body].start);
        if (s.length != 64 || !P256.verify(h, Bytes.word(s, 0), Bytes.word(s, 32), ca.x, ca.y)) {
            revert BadSignature();
        }
    }

    function _svns(bytes memory j, Json.Token[] memory t, uint256 arr) private pure returns (bytes16 out) {
        uint256[] memory comps = Json.items(t, arr);
        if (comps.length != 16) revert Unsupported();
        bytes memory b = new bytes(16);
        for (uint256 i = 0; i < 16; i++) {
            b[i] = bytes1(uint8(Json.uintOf(j, t[Json.must(j, t, comps[i], "svn")])));
        }
        out = bytes16(b);
    }

    function _status(bytes memory j, Json.Token memory s) private pure returns (uint8) {
        if (Json.strIs(j, s, "UpToDate")) return UP_TO_DATE;
        if (Json.strIs(j, s, "SWHardeningNeeded")) return SW_HARDENING_NEEDED;
        if (Json.strIs(j, s, "ConfigurationNeeded")) return CONFIGURATION_NEEDED;
        if (Json.strIs(j, s, "ConfigurationAndSWHardeningNeeded")) return CONFIGURATION_AND_SW_HARDENING_NEEDED;
        if (Json.strIs(j, s, "OutOfDate")) return OUT_OF_DATE;
        if (Json.strIs(j, s, "OutOfDateConfigurationNeeded")) return OUT_OF_DATE_CONFIGURATION_NEEDED;
        if (Json.strIs(j, s, "Revoked")) return REVOKED;
        revert Unsupported();
    }

    // ------------------------------------------------------------------ evaluation

    /// TCB status of a TDX platform: the first level its PCK certificate's SVNs and the TD's
    /// TEE_TCB_SVN reach, combined with the TDX module identity (Intel's algorithm). Also the
    /// TCB info's `nextUpdate`.
    function tdxStatus(
        bytes6 fmspc,
        uint8[16] calldata compSvn,
        uint16 pcesvn,
        bytes16 teeTcbSvn,
        bytes calldata mrSignerSeam,
        bytes8 seamAttributes
    ) external view returns (uint8 status, uint64 nextUpdate) {
        TcbInfo storage info = tcbInfos[fmspc];
        nextUpdate = info.nextUpdate;
        if (info.evaluation == 0) return (UNKNOWN, 0);
        uint8 major = uint8(teeTcbSvn[1]);
        uint8 moduleStatus = UP_TO_DATE;
        if (major == 0) {
            if (keccak256(mrSignerSeam) != keccak256(info.seamMrSigner)) return (UNKNOWN, nextUpdate);
            if (seamAttributes & info.seamAttributesMask != info.seamAttributes) return (UNKNOWN, nextUpdate);
        } else {
            ModuleIdentity storage mi = modules[fmspc][major];
            if (!mi.exists) return (UNKNOWN, nextUpdate);
            if (keccak256(mrSignerSeam) != keccak256(mi.mrsigner)) return (UNKNOWN, nextUpdate);
            if (seamAttributes & mi.attributesMask != mi.attributes) return (UNKNOWN, nextUpdate);
            moduleStatus = UNKNOWN;
            for (uint256 i = 0; i < mi.isvsvn.length; i++) {
                if (uint8(teeTcbSvn[0]) >= mi.isvsvn[i]) {
                    moduleStatus = mi.status[i];
                    break;
                }
            }
            if (moduleStatus == UNKNOWN) return (UNKNOWN, nextUpdate);
        }
        TcbLevel[] storage levels = tcbLevels[fmspc];
        uint256 from = major == 0 ? 0 : 2;
        for (uint256 i = 0; i < levels.length; i++) {
            TcbLevel storage l = levels[i];
            if (pcesvn < l.pcesvn) continue;
            bool ok = true;
            for (uint256 k = 0; k < 16 && ok; k++) {
                if (compSvn[k] < uint8(l.sgx[k])) ok = false;
            }
            for (uint256 k = from; k < 16 && ok; k++) {
                if (uint8(teeTcbSvn[k]) < uint8(l.tdx[k])) ok = false;
            }
            if (ok) {
                status = l.status > moduleStatus ? l.status : moduleStatus;
                return (status, nextUpdate);
            }
        }
        return (UNKNOWN, nextUpdate);
    }

    /// Status of a TD quoting enclave given its report fields; also the identity's `nextUpdate`.
    function qeStatus(bytes4 miscselect, bytes16 attributes, bytes32 mrsigner, uint16 isvprodid, uint16 isvsvn)
        external
        view
        returns (uint8, uint64)
    {
        if (qe.evaluation == 0) return (UNKNOWN, 0);
        if (miscselect & qe.miscselectMask != qe.miscselect) return (UNKNOWN, qe.nextUpdate);
        if (attributes & qe.attributesMask != qe.attributes) return (UNKNOWN, qe.nextUpdate);
        if (mrsigner != qe.mrsigner || isvprodid != qe.isvprodid) return (UNKNOWN, qe.nextUpdate);
        for (uint256 i = 0; i < qe.isvsvn.length; i++) {
            if (isvsvn >= qe.isvsvn[i]) return (qe.status[i], qe.nextUpdate);
        }
        return (UNKNOWN, qe.nextUpdate);
    }

    function tcbInfo(bytes6 fmspc) external view returns (TcbInfo memory info, TcbLevel[] memory levels) {
        return (tcbInfos[fmspc], tcbLevels[fmspc]);
    }

    function qeIdentity() external view returns (QeIdentity memory) {
        return qe;
    }
}
