# Boltchain 公開測試網

測試網從 2026-09-25 開始運作。它和主網走同一條路：先用 RandomBOLT 挖礦，質押夠多後由委員會確認檢查點（階段 B），再切換到 PoS。
測試幣只能靠挖礦取得，沒有水龍頭，也沒有創世分配。

測試網的目的是讓問題在真實網路上浮現。遇到任何異常，請到 GitHub 開 issue，並附上節點日誌與 `/health` 的輸出。

## 網路參數

| 項目 | 值 |
| --- | --- |
| Chain ID | 8018 |
| genesis | [`genesis/testnet.json`](../genesis/testnet.json)，區塊雜湊 `0x4036621660f1990718ec2c59c821657ac17b91a4fa620a654e0c9bc8db137a99` |
| 代幣 | BOLT（測試用，沒有價值） |
| 挖礦 | RandomBOLT，目標 12 秒一塊，ASERT 半衰期 1 小時 |
| epoch | 600 塊（挖礦階段約 2 小時；PoS 階段 6 秒一塊，約 1 小時） |
| 階段 B 門檻 | 8 位驗證者、共 20,000 BOLT，維持 3 個 epoch |
| PoS 門檻 | 16 位驗證者、共 100,000 BOLT，維持 3 個 epoch |
| 最低質押 | 64 BOLT |
| 歷史保留窗口 | 3 個 epoch（更舊的由被指派的驗證者保存並接受抽查） |

## 公開端點

| 用途 | 位址 |
| --- | --- |
| Bootnode（QUIC） | `/ip4/211.22.118.149/udp/8017/quic-v1/p2p/12D3KooWCFZiVi5pkzNA83AZqaUevCbi5fYULiEGtmz8FSvMuhDo` |
| Bootnode（TCP） | `/ip4/211.22.118.149/tcp/8017/p2p/12D3KooWCFZiVi5pkzNA83AZqaUevCbi5fYULiEGtmz8FSvMuhDo` |
| JSON-RPC | `http://211.22.118.149:8545` |
| 區塊鏈瀏覽器 | `http://211.22.118.149:8080/`（繁體中文與英文） |
| 存證 | `https://boltchain.cafeca.io/verify`：建立證書（CAFECA 付款）、以代碼查詢證書、上傳檔案比對；證明檔驗證在頁尾的「進階」 |
| IPFS 閘道 | `http://211.22.118.149:8080/ipfs/<cid>?format=car`、`http://211.22.118.149:8080/history/epoch/<n>.car` |

MetaMask：新增網路。網路名稱填 `Boltchain Testnet`，RPC 填 `http://211.22.118.149:8545`，Chain ID 填 `8018`，貨幣符號填 `BOLT`。

## 取得執行檔

從原始碼編譯需要 Rust 1.95、cmake、clang（libclang）與 C++ 編譯器：

```sh
git clone https://github.com/CAFECA-IO/Boltchain && cd Boltchain
cargo build --release -p boltchain
./target/release/boltchain genesis inspect genesis/testnet.json   # 區塊雜湊應與上表一致
```

發布 tag 之後，GitHub Releases 會有 Linux x86_64、Linux ARM64（樹莓派）與 macOS ARM64 的執行檔。

## 挖礦

```sh
B=./target/release/boltchain
BOOT=/ip4/211.22.118.149/udp/8017/quic-v1/p2p/12D3KooWCFZiVi5pkzNA83AZqaUevCbi5fYULiEGtmz8FSvMuhDo
$B wallet new --out ~/.boltchain-testnet/wallet.json            # 記下地址；檔案權限 0600，請備份
$B mine --genesis genesis/testnet.json --datadir ~/.boltchain-testnet/data \
  --bootnode $BOOT --beneficiary <你的地址> \
  --randomx-fast --mining-threads 4 --metrics 127.0.0.1:9017
```

- `--randomx-fast`：使用 2 GiB 資料集，雜湊速度約快 8 倍；啟動時需要約 1 分鐘初始化。記憶體少於 4 GiB 的機器請拿掉這個選項。
- 家用網路最好在路由器上把 UDP 與 TCP 8017 轉發到這台機器。沒有轉發也能運作：節點會先試 UPnP，再由 AutoNAT 判斷是否在 NAT 後面；是的話會經由 bootnode 的中繼（Circuit Relay v2）讓別人連進來，並嘗試打洞（DCUtR）改成直連。
- 節點每分鐘會在日誌印一行 `status`，內容包括高度、peer 數、雜湊率與已挖到的區塊數。

查詢餘額：`$B wallet balance --wallet ~/.boltchain-testnet/wallet.json`（預設連本機 RPC `http://127.0.0.1:8545`）。

## 成為驗證者

帳戶挖到至少 64 BOLT 之後：

```sh
$B keys new --out ~/.boltchain-testnet/validator.json
$B wallet stake --wallet ~/.boltchain-testnet/wallet.json --key ~/.boltchain-testnet/validator.json --amount 100
$B wallet set-peer --wallet ~/.boltchain-testnet/wallet.json --key ~/.boltchain-testnet/validator.json \
  --node-key ~/.boltchain-testnet/data/node.key
```

- `set-peer` 公布你的節點是這位驗證者保存歷史資料的地方。沒有公布的驗證者被抽查時一律算失敗，每次罰 1% 質押。
- 之後用 `validator` 取代 `mine` 重新啟動節點。參數相同，另外加上 `--key ~/.boltchain-testnet/validator.json`；如果還要繼續挖礦，加上 `--mine`。
- `wallet new` 與 `keys new` 會要求設定密碼並加密保存。節點在背景執行時，把密碼放進只有自己能讀的檔案（`chmod 600`），啟動時設定 `BOLT_PASSWORD_FILE=<檔案>`。

## 從快照加入（不必從 genesis 同步）

先向可信的來源取得最近一個 epoch 結尾區塊的高度與雜湊，例如自己的另一個節點，或 `eth_getBlockByNumber`，然後：

```sh
$B validator --genesis genesis/testnet.json --datadir ~/.boltchain-testnet/data2 --bootnode $BOOT \
  --checkpoint <高度>:<雜湊>
```

## 重新開始（2026-09-26，ADR 0012）

測試網以新的 genesis 重新開始（時間戳 2026-09-26 10:00 UTC，hash `0x0dd221dfcc1a212819e50717e4700e464cd0bf61065df9ed1c624c426ce162bb`）。舊鏈與它的 `compute` 分叉作廢，餘額、質押與合約部署都不保留；舊的資料目錄要刪掉。

- 每塊 32 BOLT（共識 31 + 存儲 1），每 4 年減半，第 5 期起固定為共識 1 + 存儲 1；沒有總量上限。
- 沒有算力份額；`ComputeMarket` 從 genesis 起就在（`0xB017000000000000000000000000000000000006`）。
- 存儲抽查開放給未質押節點：`boltchain wallet storage-register --wallet <帳戶> --node-key <datadir>/node.key`（沒有 BOLT 時加 `--signed`，把印出的交易交給任何人代送），然後節點加上 `--storage-account <地址>`。

## 第二台主機（211.22.118.148）

2026-09-26 加入第二台主機，跑 2 個節點（`cafeca-e-n1`、`cafeca-e-n2`）、8 把驗證者金鑰，一起挖礦，並負責讓測試網達到 PoS 門檻（16 位驗證者、100,000 BOLT）：

- 部署：`deploy/testnet/usermode/setup-second-host.sh 2 4 2 211.22.118.148 cafeca-e`（這台的 8545 已被占用，RPC 用 18545、18546）
- 這台是 Ubuntu 22.04（glibc 2.35），執行檔要另外建置：`cargo zigbuild --release -p boltchain --target x86_64-unknown-linux-gnu.2.35`，C 編譯參數加 `-DMDBX_HAVE_BUILTIN_CPU_SUPPORTS=0 -mevex512 -Wno-date-time`，並提供一個空的 `asm/cachectl.h`
- 自動質押：第 3300 塊起，第一台主機的 `fund-host2.sh` 把各節點錢包的 BOLT（保留 30）轉到第二台的質押錢包；第二台的 `stake-t2.sh` 等餘額足夠補齊 100,000 BOLT 後，平均質押 8 把金鑰並公布歷史節點。必須在第 3601 塊（第 6 週期開始）之前完成，PoS 才會在第 6001 塊（第 10 週期）開始

## 硬分叉 `swarm`（第 2401 塊，ADR 0014）

測試網的 genesis 是 `HistoryRegistry`；第 2401 塊（epoch 4 的第一塊）把 `0xB017…0005` 的程式碼換成 `SwarmStorage`（固定的 bytecode，`contracts/forks/8018-swarm`），原有狀態全部保留。從那個 epoch 起：

- 提供者可以開放報價：`boltchain storage offer --wallet <帳戶> --id <提供者 id> --capacity <MiB> --price <BOLT/GiB/epoch>`
- 使用者可以付費保存檔案：節點加 `--rpc-storage`（RPC 綁 localhost），然後 `boltchain storage put`
- 每個 epoch 多 16 個委託抽查任務

節點必須在第 2401 塊之前換上新版，否則會停在分叉前（fork id 不同）。

## 硬分叉 `tee`（第 233401 塊，ADR 0011、ADR 0013）

第 233401 塊（epoch 389 的第一塊，約 2026-10-16 12:20 UTC+8）安裝下列程式碼（固定的 bytecode，`contracts/forks/8018-tee`），原有狀態全部保留：

| 位址 | 合約 | 內容 |
| --- | --- | --- |
| `0xB017…0006` | `ComputeMarket`（新版） | 中繼代送的接單與收據付中繼費、`acceptFor` / `deliverFor` 的新簽名格式、工作必須指定已登記的模型；儲存佈局與舊版相同（新的 `relays` 放在最後） |
| `0xB017…0007` | `ModelRegistry` | 模型登記表 |
| `0xB017…0008` | `ImageRegistry` | Agent 執行環境映像與量測值 |
| `0xB017…0009` | `TeeCollateral` | Intel 附帶資料（信任根是 Intel SGX Root CA） |
| `0xB017…000A` | `TdxVerifier` | TDX quote 鏈上驗證 |
| `0xB017…000B` | `EnclaveLease` | TEE 租約 |
| `0xB017…000C` | `LimitedWallet` | Agent 的限權錢包（EIP-7702 委派目標） |

從那一塊起：

- 新的工作要先有模型：`boltchain model register`，再 `boltchain job post --model <id>`；不指定執行者（`--provider` 省略）就是開放承接。
- 節點可以加 `--relay-wallet <帳戶檔> --relay-min-fee 0.001`，替沒有 BOLT 的執行者與 enclave 代送交易並收中繼費。
- 驗證小組開始審核 T2 機器（TPM）的證明。測試網上的驗證者要用 `--tpm-roots <目錄>` 提供 TPM 廠商根憑證，沒有提供就棄權。
- `TeeCollateral` 是空的，需要任何人提交 Intel 的附帶資料：`boltchain collateral update --wallet <帳戶檔>`（從 Intel PCS 抓取）。TCB Info 一筆約 1,500 萬 gas。
- 模擬機器（`enclave runtime --simulate`）只在開發鏈上有效，測試網上的 TDX 證明必須來自真實硬體。

節點必須在第 233401 塊之前換上 r39 以後的版本，否則會停在分叉前（fork id 不同）。

## Uniswap v4

測試網部署了 Uniswap v4（core 1.0.2、periphery 1.0.3、UniversalRouter 2.1.0；2026-09-26 在 v2 重新部署，第 720–761 塊），部署腳本與地址紀錄在 [`scripts/uniswap-v4`](../scripts/uniswap-v4)：

| 合約 | 地址 |
| --- | --- |
| PoolManager | `0x5dFd9A046A4bCcfa831909f809E9bA519f1fF47C` |
| PositionManager | `0x4Efa6167f81e046E7A8427a9E197eB875DfcDc59` |
| UniversalRouter | `0x7cF5C62E8805D0968230ca232F3bAE22F1F3A9F2` |
| V4Quoter | `0xa823a804F0a81317c099eEFd66Bf5FcCf97A79FB` |
| StateView | `0xAaa79cBAba5aEBAdE64c2ae8367bB72b3380c4D1` |
| PositionDescriptor | `0xb0f5B41Ba48E8DE03625BCd196C4b691254112C9` |
| Permit2 | `0x02B5cC3B42C2646a39634374d8cC35B55b8e158C` |
| WBOLT | `0x7Eb67a435eA575231FDdaA5056f15580Edc581d4` |
| tUSD（測試代幣，任何人都能 mint） | `0xd348f3bfb9Ba449De548945E54f2eD25A3263305` |

- 已建立原生 BOLT / tUSD 池（手續費 0.30%，tick spacing 60，沒有 hook），pool id `0xe49b160f7a87b3db34381eccae1824a8a9828f87c4b004de412a0e1b1b258398`，初始價格 1 BOLT = 10 tUSD，並有 100 單位的全區間流動性。
- Permit2 不在其他鏈上的標準位址：標準位址要靠不帶 chain id 的交易部署，Boltchain 不接受這種交易。程式碼與標準版本逐位元組相同。
- Uniswap 官方網頁不支援 chain 8018，請用腳本、ethers 或 Foundry（`cast`）直接呼叫合約。範例見 `scripts/uniswap-v4/deploy.mjs` 的冒煙測試。
- 瀏覽器會顯示這些合約的名稱，以及 `execute`、`modifyLiquidities` 等方法名稱。
- Uniswap v4 core 採用 BUSL-1.1，測試網屬於非正式環境的使用；主網部署前要先取得授權（見腳本目錄的 README）。

## 監看與回報

- 瀏覽器的「網路」頁列出線上節點的版本與國家（r40 起；每個節點每 10 分鐘廣播一次心跳，舊版節點只在與瀏覽器節點直接連線時才會出現）。

- 執行中的版本：`https://boltchain.cafeca.io/api/status` 的 `version`（如 `boltchain/v0.1.0-1a2b3c4`），或 `boltchain --version`。
- `curl 127.0.0.1:9017/health`：高度、階段、peer 數、最終區塊、快照高度。
- `curl 127.0.0.1:9017/metrics`：Prometheus 格式，包括匯入、重組、被拒提案、Bitswap、抽查、修剪等計數。
- 回報問題時請附上：`/health` 輸出、日誌中的 `WARN` 與 `ERROR`、作業系統與 CPU、網路環境（是否在 NAT 後面）。

## 已知限制（測試網第一階段）

- 中繼連線有時間與流量上限（每條 30 分鐘、256 MiB），會自動重建；打洞在對稱型 NAT 後面通常不會成功，這時資料一直走中繼。
- 同一把驗證者金鑰不要同時在兩個節點上執行。節點發現金鑰在別處被使用時會停止用它簽署（日誌出現 `another node is signing with this validator key`，`/metrics` 的 `doppelganger` 大於 0）；停掉另一個節點後重新啟動即可恢復。
- 公開的閘道與瀏覽器每個 IP 每秒限 20 次請求。
- 舊版（r34 以前）在全部驗證者同時重啟後會停鏈，日誌一直出現 `could not build proposal: parent block not available`。r35 起重啟時會從本機資料重建尚未最終的區塊（日誌 `restored pending blocks`），請升級。
- 測試網可能因為修正而重置，重置時會更新本頁的 genesis 雜湊。
