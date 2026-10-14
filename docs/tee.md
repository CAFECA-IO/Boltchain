# TEE Agent 租用：操作指南

設計見 [ADR 0013](adr/0013-tee-agent-leasing.md)。本文說明第一期已實作的部分要怎麼用：執行者出租機器、租用者租用並驗證 enclave、Agent 的限權錢包。

## 誰負責什麼

| 角色 | 做什麼 | 指令 |
| --- | --- | --- |
| 執行者 | 登記機器（附證明）、報價、押金、啟用租約、退出 | `boltchain enclave` |
| Agent 執行環境 | 在 TEE 內產生金鑰、取得證明、接收秘密、每小時送檢查點 | `boltchain enclave runtime`（目前只有 `--simulate`） |
| 租用者 | 選報價、託管、本機驗證、交付秘密、搬家、結束 | `boltchain lease` |
| 映像登記者 | 登記映像的原始碼、建置方式與量測值；別人重建後可以宣告「我重現了」 | `boltchain image` |
| 任何人 | 提交 Intel 的附帶資料（Intel 簽章，不必信任提交者） | `boltchain collateral update` |
| 驗證者 | 驗證小組：審核 T2（TPM）機器與它們的啟用 | `boltchain validator --tpm-roots <目錄>` |

## 在開發鏈上走一遍

開發鏈（`genesis/dev.json`、`boltchain genesis make-dev` 產生的 genesis）信任模擬的 Intel PKI 與模擬的 TPM 廠商，所以 `--simulate` 的機器能通過驗證。公開測試網與主網只信任真實硬體。

```sh
R=http://127.0.0.1:8545
# 0. 附帶資料與映像
boltchain collateral update --simulated --wallet me.json --rpc $R
boltchain image register --wallet me.json --name bolt-art --source <原始碼 CID> --build "nix build .#bolt-art"
boltchain image measure --wallet me.json --image 1 --kind tdx --simulate

# 1. 執行者：啟動（模擬的）執行環境，登記機器並報價
boltchain enclave runtime --simulate --kind tdx --state rt-data --listen 127.0.0.1:9100 --relay $R &
boltchain enclave register --wallet op.json --runtime http://127.0.0.1:9100 --cpus 16 --mem 64 --price 0.8
boltchain enclave bond --wallet op.json deposit 64

# 2. 租用者：託管 24 小時，指定映像與 Agent 包
boltchain lease offers
boltchain lease create --wallet me.json --machine 1 --image 1 --agent agent.tar --hours 24 --min-bond 32

# 3. 執行者啟用（經中繼代送，執行者不需要 BOLT）
boltchain enclave activate --lease 1 --runtime http://127.0.0.1:9100 --relay $R

# 4. 租用者在本機驗證後交付秘密
boltchain lease verify 1 --simulated
boltchain lease deliver 1 --file api-key.txt

# 5. 給 Agent 一個限權錢包：每日 1 BOLT、單筆 0.1 BOLT、只能付給指定合約
boltchain lease wallet --wallet me.json --lease 1 --daily 1 --per-tx 0.1 --target 0x…
```

T2（TPM）機器把 `--kind tdx` 換成 `--kind tpm`：登記與啟用都會進入驗證小組的待審清單，小組成員向機器的端點取證明、重播事件記錄、做 TPM 挑戰，三分之二同意後才生效。

## 證明綁定的內容

| 用途 | TDX（REPORT_DATA，64 bytes） | TPM（quote 的 qualifyingData） |
| --- | --- | --- |
| 登記機器 | `machineBinding(執行者)` ‖ 0 | `machineBinding(執行者)` |
| 啟用租約 | `enclaveBinding(租約, S, E)` ‖ Agent 包雜湊 | `keccak256(enclaveBinding ‖ Agent 包雜湊)` |

- `machineBinding = keccak256(abi.encode("boltchain/machine/v1" 的雜湊, chainId, EnclaveLease, 執行者))`
- `enclaveBinding = keccak256(abi.encode("boltchain/enclave/v1" 的雜湊, chainId, EnclaveLease, 租約, S, E, nonce))`，nonce 每次建立或搬家時重新產生，舊證明不能重播。
- 機器 ID：TDX 是 `keccak256(PPID)`，TPM 是 `keccak256(EK 的 SubjectPublicKeyInfo)`，在鏈上公開，一台機器只能屬於一個執行者。
- 映像量測值：TDX 是 `keccak256(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2)`；TPM 是 `keccak256(abi.encode(uint32 PCR 遮罩, bytes32[] PCR 值))`，預設 PCR 0–7 與 11。

## 檢查點、計費與罰沒

- 檢查點由 enclave 的金鑰 S 簽名（EIP-191），內容是 `(租約, 版本, 狀態根, 狀態 CID 雜湊, 最近看到的 blockhash)`；版本必須遞增，所以舊狀態重啟送不上鏈。
- 距上次付款滿 1 小時後的第一個檢查點付一小時；收入先扣 20% 累積押金（到 64 BOLT 為止）。每個檢查點與啟用付租約的中繼費給代送者。
- 同一把 S 對同一版本簽出兩份不同的狀態（上鏈或中間檢查點都算）：任何人都能把兩份簽名送進 `reportEquivocation`，執行者押金全部罰沒（一半給檢舉人、一半燒掉），機器列入黑名單。
- 平台降級（Intel 發布新的 TCB 等級、PCK 憑證被撤銷）：任何人都能 `lease recheck`，租約標成降級後不再付款，租用者可以立刻搬家。
- 搬家：租約還在等待、已降級、執行者宣告退出（24 小時通知期）或被罰沒，或 2 小時沒有檢查點時，租用者可以 `lease migrate` 到另一台機器；版本號延續，舊的 S 立刻失效。

## 驗證小組（T2 與之後的 SNP）

- `EnclaveLease` 有待審的請求時，每一塊都把它們交給當期的驗證小組（從委員會抽出，挖礦階段從質押者抽出；每個 epoch 一組）。
- 小組成員從機器登記的端點取得證明包（`GET /attest/evidence/<sha256>`，與鏈上的雜湊比對），用 `bolt-attest` 驗證 EK 憑證鏈、AK 屬性、quote 簽章、事件記錄重播出的 PCR，再送 TPM2 MakeCredential 挑戰（`POST /attest/challenge`），只有持有該 EK 的 TPM 能解開。
- 結果以 BLS 簽章投票（`AttestVote`），超過三分之二同意的憑證（`AttestCert`）由出塊者放進區塊，鏈驗證後呼叫 `recordAttestation`。
- 驗證者需要 TPM 廠商的根憑證（`--tpm-roots`）；沒有設定就棄權。開發鏈另外信任模擬的廠商。

## 已知限制（第一期）

- `bolt-art` 映像（真正的 TDX 機密 VM 與 T2 開機映像）尚未建置，要等三款裝置的實機確認（ADR 0013 第 10 節第零期）。目前只有模擬執行環境。
- 只支援 RSA EK；ECC EK 的 MakeCredential 尚未實作。
- TPM 廠商根憑證沒有內建清單，需要驗證者自行提供。
- 提交一份 Intel TCB Info 約 1,500 萬 gas，接近單筆交易上限 16,777,216（EIP-7825）；Intel 的 TCB 等級再多幾級就會超過，需要再優化 JSON 解析。
- SEV-SNP、保管小組（租用者離線時自動搬家）、GPU 證明是第二、三期。
