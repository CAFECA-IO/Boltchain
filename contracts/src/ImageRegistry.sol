// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title Agent runtime images and their expected measurements (ADR 0013 §6.3).
/// @notice Open registration, no review (decision 7): anyone registers an image (its source by
/// CID and how to build it) and the measurements a reproducible build yields on given hardware;
/// others who rebuilt it and got the same measurement say so, and wallets show how many did.
/// A lease names an image; an enclave is accepted only if its measurement is registered for it.
contract ImageRegistry {
    /// Measurement kinds: TDX (keccak256 of MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2), SEV-SNP
    /// (keccak256 of MEASUREMENT), TPM (keccak256 of abi.encode(uint32 PCR mask, bytes32[] PCR
    /// values) over the SHA-256 bank).
    uint8 public constant TDX = 1;
    uint8 public constant SNP = 2;
    uint8 public constant TPM = 3;

    struct Image {
        address registrant;
        uint64 registeredAt;
        string name;
        bytes source; // CID of the source tree
        string build; // how to build it reproducibly
    }

    struct Measurement {
        uint8 kind;
        uint32 reproductions; // registrants other than the image's who reproduced it
        string platform; // hardware and firmware it applies to
    }

    Image[] internal images;
    mapping(uint64 => mapping(bytes32 => Measurement)) internal measurements;
    mapping(uint64 => bytes32[]) internal measurementList;
    mapping(uint64 => mapping(bytes32 => mapping(address => bool))) public reproducedBy;

    event ImageRegistered(uint64 indexed id, address indexed registrant, string name, bytes source);
    event MeasurementAdded(uint64 indexed id, bytes32 indexed measurement, uint8 kind, string platform);
    event Reproduced(uint64 indexed id, bytes32 indexed measurement, address indexed by);

    error BadParams();
    error NotAllowed();
    error UnknownImage();

    function register(string calldata name, bytes calldata source, string calldata build)
        external
        returns (uint64 id)
    {
        if (bytes(name).length == 0 || bytes(name).length > 128 || source.length == 0 || source.length > 128) {
            revert BadParams();
        }
        if (bytes(build).length > 2048) revert BadParams();
        images.push(Image(msg.sender, uint64(block.timestamp), name, source, build));
        id = uint64(images.length);
        emit ImageRegistered(id, msg.sender, name, source);
    }

    /// The image's registrant adds a measurement (raw bytes, hashed here) for some hardware.
    function addMeasurement(uint64 id, uint8 kind, bytes calldata raw, string calldata platform)
        external
        returns (bytes32 m)
    {
        Image storage img = _image(id);
        if (msg.sender != img.registrant) revert NotAllowed();
        if (kind < TDX || kind > TPM || raw.length == 0 || bytes(platform).length > 256) revert BadParams();
        m = keccak256(raw);
        if (measurements[id][m].kind != 0) revert BadParams();
        measurements[id][m] = Measurement(kind, 0, platform);
        measurementList[id].push(m);
        emit MeasurementAdded(id, m, kind, platform);
    }

    /// The caller rebuilt image `id` and got measurement `m`.
    function reproduce(uint64 id, bytes32 m) external {
        Image storage img = _image(id);
        Measurement storage me = measurements[id][m];
        if (me.kind == 0 || msg.sender == img.registrant || reproducedBy[id][m][msg.sender]) revert NotAllowed();
        reproducedBy[id][m][msg.sender] = true;
        me.reproductions++;
        emit Reproduced(id, m, msg.sender);
    }

    /// Whether image `id` lists measurement hash `m` of `kind`.
    function allows(uint64 id, uint8 kind, bytes32 m) external view returns (bool) {
        return id != 0 && id <= images.length && measurements[id][m].kind == kind;
    }

    function image(uint64 id) external view returns (Image memory) {
        return _image(id);
    }

    function measurement(uint64 id, bytes32 m) external view returns (Measurement memory) {
        return measurements[id][m];
    }

    function measurementsOf(uint64 id) external view returns (bytes32[] memory) {
        return measurementList[id];
    }

    function imageCount() external view returns (uint256) {
        return images.length;
    }

    function _image(uint64 id) internal view returns (Image storage) {
        if (id == 0 || id > images.length) revert UnknownImage();
        return images[id - 1];
    }
}
