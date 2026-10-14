// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title Model registry (ADR 0011 §7).
/// @notice Anyone may register a model: its weights, tokenizer and runtime by content id, with
/// its size. Entries are immutable and have no owner beyond the registrant's name in the event;
/// nothing is reviewed. Jobs in `ComputeMarket` name a model by its id here, and providers
/// declare which models they serve so requesters can see who can run one.
contract ModelRegistry {
    struct Model {
        address registrant;
        uint64 registeredAt;
        uint64 parameters; // parameter count
        uint32 vramMiB; // suggested GPU memory
        string name; // e.g. "Llama-3.1-8B-Instruct Q4_K_M"
        bytes weights; // CID of the weights (e.g. a GGUF file)
        bytes tokenizer; // CID of the tokenizer (empty when inside the weights file)
        string runtime; // e.g. "llama.cpp b4500" or "vllm 0.8.4"
    }

    Model[] internal models;
    /// Providers declaring that they serve a model.
    mapping(uint64 => mapping(address => bool)) public serves;
    mapping(uint64 => uint32) public providerCount;
    /// Ids of models with the same weights CID (exact duplicates are refused).
    mapping(bytes32 => uint64) public idOfWeights;

    event ModelRegistered(uint64 indexed id, address indexed registrant, string name, bytes weights);
    event SupportChanged(uint64 indexed id, address indexed provider, bool serving);

    error BadParams();
    error Duplicate(uint64 id);
    error UnknownModel();

    /// Registers a model; ids start at 1.
    function register(
        string calldata name,
        bytes calldata weights,
        bytes calldata tokenizer,
        string calldata runtime,
        uint64 parameters,
        uint32 vramMiB
    ) external returns (uint64 id) {
        if (bytes(name).length == 0 || bytes(name).length > 128) revert BadParams();
        if (weights.length == 0 || weights.length > 128 || tokenizer.length > 128) revert BadParams();
        if (bytes(runtime).length > 128) revert BadParams();
        bytes32 w = keccak256(abi.encode(weights, tokenizer, runtime));
        if (idOfWeights[w] != 0) revert Duplicate(idOfWeights[w]);
        models.push(
            Model({
                registrant: msg.sender,
                registeredAt: uint64(block.timestamp),
                parameters: parameters,
                vramMiB: vramMiB,
                name: name,
                weights: weights,
                tokenizer: tokenizer,
                runtime: runtime
            })
        );
        id = uint64(models.length);
        idOfWeights[w] = id;
        emit ModelRegistered(id, msg.sender, name, weights);
    }

    /// The caller (a provider) starts or stops serving a model.
    function setSupport(uint64 id, bool serving) external {
        if (!exists(id)) revert UnknownModel();
        if (serves[id][msg.sender] == serving) return;
        serves[id][msg.sender] = serving;
        if (serving) providerCount[id]++;
        else providerCount[id]--;
        emit SupportChanged(id, msg.sender, serving);
    }

    function exists(uint64 id) public view returns (bool) {
        return id != 0 && id <= models.length;
    }

    function model(uint64 id) external view returns (Model memory) {
        if (!exists(id)) revert UnknownModel();
        return models[id - 1];
    }

    function modelCount() external view returns (uint256) {
        return models.length;
    }
}
