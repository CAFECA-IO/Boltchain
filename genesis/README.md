# Genesis 檔

| 檔案 | 用途 |
| --- | --- |
| `mainnet.template.json` | 主網範本：chain id 8017，沒有任何驗證者、多簽或分配，只差啟動時間 |
| `devnet.json` | 主網格式的測試 genesis（chain id 8017，extra data 不同），CI 用來檢查 `genesis inspect` |
| `dev.json` | 本地開發鏈（chain id 1337）：3 個注資帳戶、7 個在 genesis 質押的驗證者，從第 1 塊就跑 PoS |
| `pow-dev.json` | 本地挖礦鏈（chain id 1338）：3 個注資帳戶，RandomBOLT 低難度、4 秒一塊、每 epoch 32 塊；2 位驗證者共 128 BOLT 維持 2 個 epoch 進入階段 B（檢查點深度 4），3 位共 192 BOLT 再維持 2 個 epoch 切換到 PoS |

```sh
cargo run -p boltchain -- genesis inspect genesis/devnet.json
```

驗證規則見 `crates/primitives/src/genesis.rs` 的 `Genesis::validate`，重點如下：

- chain id 必須是 8017，slot 長度 6 s，每個 epoch 14,400 個 slot，委員會至少 512 席，gas limit 在 15M–60M 之間
- 挖礦參數固定：RandomBOLT、12 秒一塊、ASERT 半衰期 1 小時；起始難度必須大於 0
- **沒有特殊待遇**（ADR 0007）：不能列 genesis 驗證者、不能調整 PoS 門檻、`alloc` 中所有帳戶餘額必須為 0
- **沒有治理**（ADR 0008）：genesis 不部署多簽或 timelock，系統合約不可升級
- EIP-4788 與 EIP-2935 的系統合約會自動加入，不可覆寫；`0xB017…` 系統合約範圍也不可覆寫

dev 鏈（`"dev": true`，chain id 不可為 8017）可以：注資帳戶、在 genesis 質押驗證者（`devValidators`）、
調低門檻（階段 B：`checkpointMinStakers`、`checkpointMinStakeBolt`、`checkpointDepth`；PoS：`posMinStakers`、`posMinStakeBolt`、`posStreakEpochs`，階段 B 的門檻不可高於 PoS）、縮短 epoch、改挖礦參數，
或把 `pow.algorithm` 設成 `keccak` 以加快測試，
並可用 `devTeeRoot`（P-256 公鑰 `[x, y]`）把 `TeeCollateral` 的信任根換成模擬的 PKI，讓 `enclave runtime --simulate` 的機器通過證明（ADR 0013；`dev.json`、`pow-dev.json` 與 `boltchain genesis make-dev` 產生的檔案都用 `SimIntel::dev()` 的根）。

## 主網範本 `mainnet.template.json`

主網從挖礦開始，任何人都能用一般電腦參與。質押達到 32 位驗證者、共 100 萬 BOLT 並連續 14 個 epoch 後，委員會開始確認挖出來的區塊（階段 B）；
達到 128 位、共 1,000 萬 BOLT 並連續 14 個 epoch 後自動切換到 PoS。
發布前只需要填入 `timestamp`（主網啟動時間），執行 `boltchain genesis inspect genesis/mainnet.json` 確認通過，再公布 genesis hash。

想成為驗證者的人不必出現在 genesis：用 `boltchain keys new` 產生金鑰，`boltchain keys register-tx` 印出
`StakingManager.register` 交易，從持有質押的錢包送出（至少 64 BOLT）。

## Bootstrap 節點

主網 bootstrap 節點使用 `node001.cafeca.io` 到 `node009.cafeca.io`，預設埠 8017（QUIC/UDP 與 TCP）。
客戶端內建的清單是 `/dnsaddr/node00N.cafeca.io`，所以每台主機要在 DNS 發布一筆 TXT 記錄，
把位址和節點的 peer ID 一起公布，例如：

```
_dnsaddr.node001.cafeca.io.  TXT  "dnsaddr=/dns4/node001.cafeca.io/udp/8017/quic-v1/p2p/12D3KooW..."
_dnsaddr.node001.cafeca.io.  TXT  "dnsaddr=/dns4/node001.cafeca.io/tcp/8017/p2p/12D3KooW..."
```

peer ID 由各主機的 `--node-key` 檔決定（`boltchain node-id --node-key <檔案>` 會印出來）。
換主機時只要改 DNS，不必發新版客戶端。
