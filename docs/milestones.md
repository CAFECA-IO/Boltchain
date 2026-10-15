# 里程碑

| 里程碑 | 內容 | 驗收標準 | 狀態 |
| --- | --- | --- | --- |
| M0 骨架 | workspace、CI、genesis 格式、資料庫選型 | Osaka statetest 全數通過；CI 在 ARM64 上跑測試 | 完成（CI run 36045139504：statetest、x86 與 ARM64 全數通過） |
| M1 單節點鏈 | revm 執行、MPT、MDBX、RPC，暫用單一簽名者出塊 | Foundry 部署合約、MetaMask 轉帳；30M gas / 6 s；樹莓派執行最壞情況區塊 < 2 s | 程式完成，CI（x86 與 ARM64）通過；樹莓派實測與實機 MetaMask/Foundry 待驗證 |
| M2 IPFS 同步 | IPLD 格式、內嵌 bitswap、gossipsub 公告 | 5 個跟隨節點只靠 IPFS 同步；公告到資料取完 p95 < 1 s | 程式完成，驗收測試通過（本機） |
| M3 BFT 共識 | HotStuff-2、模擬器、DA 投票規則，固定 7 人驗證者集 | 10,000 個故障情境無安全違規；關掉 2 個節點仍持續出塊 | 完成 |
| M4 PoS | 系統合約、BLS-VRF、512 席抽籤、獎勵、罰沒、啟動期 | 100 個驗證者完成 epoch 輪替；鏈上驗證雙重簽名證據 | 完成（啟動期設計由 M4.5 取代） |
| M4.5 PoW 啟動 | RandomBOLT 挖礦、ASERT、分叉選擇與重組上限、移除治理、自動切換到 PoS | 5 礦工 + 10 跟隨節點；重組上限生效；從 genesis 同步驗證 PoW；自動切換到 PoS | 完成（本機驗收） |
| M4.6 質押最終性 | 階段 B：委員會以 BFT 確認 PoW 檢查點；60/40 獎勵；完整 A → B → C | 多數算力攻擊被最終性擋下；小額質押無法啟動委員會；A → B → C 走完 | 完成（本機驗收） |
| M5 儲存層 | 檢查點同步、CAR 快照、修剪、歷史分片與抽查 | 新節點從快照起步追上最新區塊 | 完成（本機驗收） |
| M6 強化與測試網 | peer scoring、NAT 穿透、防罰沒、樹莓派基準 | 樹莓派驗證者 7 天參與率 > 99%，RSS < 1.5 GB | 進行中：公開測試網已上線（見 `docs/testnet.md`） |
| 主網上線閘門 | 見下方「主網上線閘門」 | 六項必要條件全部完成，且測試網在 PoS 下連續 2–4 週未停鏈、有外部驗證者 | 未達成（2026-09-27 決定：以條件而非日期決定上線） |

## 主網上線閘門（2026-09-27 決定）

主網不訂日期，以下條件全部達成才上線。

必要條件：

- [ ] 外部安全稽核：共識（HotStuff-2、BLS 聚合與延後驗證、檢查點）、系統合約（質押、罰沒、SwarmStorage、ComputeMarket、ModelRegistry、TEE 的五個合約與 `TeeLib` 的 DER / JSON 解析）、分叉機制
- [ ] 測試網在 PoS 下連續 2–4 週未停鏈，期間有外部驗證者加入、快照同步、修剪與抽查正常（全體重啟停鏈已修正並有測試、gossip 重複警告已查明，2026-10-04）
- [ ] 主網 genesis 定稿（依 ADR 0007，genesis 沒有驗證者與多簽、從 PoW 開始）：填入上線時間 `timestamp` 與最終 `extraData`、確認起始難度 2¹⁸ 與 T1/T2 門檻、bootstrap `node001`–`node009.cafeca.io` 架設並設好 DNS
- [x] 金鑰保護：驗證者金鑰預設為 EIP-2335 keystore（通過 EIP-2335 測試向量）、錢包為 v3 keystore（與 eth-account 互通）；`keys encrypt` / `wallet encrypt` 轉換舊檔；主網拒絕未加密的驗證者金鑰；密碼取自 `BOLT_PASSWORD_FILE`、`BOLT_PASSWORD` 或終端機
- [ ] 安全升級：簽章發布清單、可重現建置與 CI 建置證明、`--auto-update notify`
- [ ] 規模與硬體：128 位驗證者 / 1,000 萬 BOLT 規模的模擬或測試網演練、樹莓派實測、修剪巡檢改成游標與事件驅動

建議完成：

- [ ] leader 依質押權重做不可預測的 VRF 抽樣；投票直送下一任 leader
- [ ] 營運演練：監控與告警、備份、崩潰後重啟（全體同時重啟已有自動恢復與測試）、停鏈處理手冊
- [ ] BOLT 發行的法律與法規確認（臺灣及其他地區）

上線後再做：公開 IPFS 橋接、TEE 的 `bolt-art` 映像與實機驗收。零 BOLT 執行者中繼、開放承接、`ModelRegistry` 與 TEE 租用的合約已在 2026-10-14 完成，放進主網 genesis（決定：與其上線後再硬分叉，不如從 genesis 就有）。

## M1 結果（2026-09-25）

完成項目：

- [x] `store`：libmdbx 資料表、路徑式增量 MPT（對照 alloy-trie 全量重算的 property test，另跑 5,000 組隨機案例）、最近 128 塊的狀態歷史與修剪
- [x] `exec`：區塊執行器（EIP-4788 / EIP-2935 system call、收據與 bloom、EIP-1559 base fee、EIP-7934 區塊大小、拒收 blob）
- [x] `chain`：出塊與匯入。匯入端會重新執行並逐欄比對 header；不符就中止寫入交易，什麼都不落地
- [x] `txpool`：admission 規則（EIP-155、chain id、拒收 type 3、gas 範圍、手續費下限、nonce、餘額、每帳戶 16 筆、10% 替換加價）
- [x] `rpc`：25 個 `eth_*` / `net_*` / `web3_*` 方法，含 CORS
- [x] `node`：`boltchain devnet`、`boltchain bench`
- [x] 端到端測試：alloy 客戶端經 HTTP JSON-RPC 轉帳、部署合約、呼叫合約、查 log、查歷史餘額（`crates/node/tests/e2e.rs`）

### 基準測試（雲端 x86_64，2 vCPU；ARM 數據由 CI 產生）

| 情境 | 每塊 gas | 出塊（執行 + 提交） | 驗證者匯入（驗簽 + 重新執行 + 提交） |
| --- | --- | --- | --- |
| 1,428 筆轉帳 | 30.0M | 15 ms | 50 ms |
| BN254 pairing 塞滿 | 28.6M | 340 ms | 330 ms（最壞 332 ms） |
| BLS12-381 pairing 塞滿 | 29.4M | 259 ms | 254 ms（最壞 260 ms） |

過程中做的兩項調整：

- BN254 後端從 substrate-bn 改回 revm 預設的 arkworks：最壞情況區塊從 754 ms 降到 332 ms。
- 匯入時的簽章還原改為多核平行，並改用 libsecp256k1：轉帳區塊的匯入時間從 309 ms 降到 50 ms。

樹莓派的數字還沒有實測。若照「樹莓派比這台慢 3–5 倍」粗估，最壞情況約 1.0–1.7 秒，在 2 秒目標內，但餘裕不大。
GitHub 的 ARM64 runner 比樹莓派快，只能當下限參考；最終要在實機上跑 `boltchain bench`。

### 尚未完成

- [x] Osaka state tests 在 CI 上全數通過（GitHub Actions run 36045139504）
- [x] ARM64 上的測試與基準跑完（數據在該次 CI 的 `block execution benchmark` 步驟日誌）
- [ ] 樹莓派實機測試
- [ ] 以真正的 MetaMask 與 Foundry 手動驗證一次（自動化測試已涵蓋同樣的 RPC 流程）

## M2 結果（2026-09-25）

完成項目：

- [x] `ipld`：header 用 `eth-block`（0x90）+ keccak-256，CID 的 digest 就是 block hash；body 切成 ≤ 1 MiB 的 raw chunk；dag-cbor envelope 以 `parent` 串起整條鏈；CAR v1 讀寫
- [x] `store`：`ipld` 與 `envelopes` 資料表；區塊的 IPLD 資料與狀態在同一個寫入交易提交
- [x] `net`：QUIC/TCP + DNS（支援 `/dnsaddr`）、Kademlia（`/bolt/<chain id>/kad/1.0.0`）、gossipsub 公告（只接受指定出塊者簽署的訊息）、交易轉發
- [x] Bitswap 1.2.0：自行實作，與 Kubo/Helia 線上格式相容（見 ADR 0004）；以 Helia 7.1.15 實測可取回並驗證區塊
- [x] `sync`：收到公告 → 驗證 envelope 與 header → 用 Bitswap 抓 chunk（先向轉發者要，對方回 DONT_HAVE 或 150 ms 內沒回應就改問其他節點）→ 重新執行並核對 header 與 envelope；落後時沿 `parent` 回填
- [x] `boltchain follow`、`boltchain node-id`；出塊者每塊發公告並接收轉發的交易
- [x] 主網 genesis 範本：7 個驗證者收款地址、9 位多簽簽署者（EIP-55 校驗碼全數正確）、bootstrap `node001`–`node009.cafeca.io`（驗證者與多簽已由 ADR 0007 取消，現行範本只保留參數與 bootstrap）

### 驗收測試（`crates/node/tests/m2_sync.rs`）

1 個出塊者 + 5 個跟隨者，其中 3 個跟隨者只連到另一個跟隨者、不直接連出塊者。24 個區塊輪流包含：空塊、小 body（內嵌在公告裡）、約 190 KB body（走 Bitswap）、約 1.4 MB body（兩個 chunk）。
全部跟隨者的 head 與 envelope root 都與出塊者一致；第 6 個晚加入的節點只連到其中一個跟隨者，沿 parent 回填 25 個區塊。

| 建置 | 公告 → 資料到手 p50 | p95 | 最大值 |
| --- | --- | --- | --- |
| release | 3 ms | 58 ms | 164 ms |
| debug（CI 跑的版本，7 個節點共用 2 vCPU） | 92 ms | 661 ms | 1,145 ms |

這是同一台機器上的 localhost 數字。跨網路的實際延遲要到 M6 測試網才量得到；每多一跳大約增加一個 RTT 加上一次 1.4 MB 的傳輸時間。

### 尚未完成

- [ ] 驗證者 BLS 公鑰（M3 的 `boltchain keys`）
- [ ] 公開 IPFS 網路的橋接與 epoch 索引（M5）
- [x] NAT 穿透（AutoNAT、Circuit Relay v2、DCUtR）（M6）

## M3 結果（2026-09-25）

完成項目：

- [x] `boltchain keys`：用 BLS12-381（blst，min_pk，以太坊 DST）產生金鑰和持有證明（PoP）。`feeRecipient` 地址以 EIP-191 personal_sign 簽署綁定聲明。`genesis-entry` 會先驗證 PoP 和綁定，再印出 genesis 條目
- [x] `consensus`：兩鏈 HotStuff 加上 Jolteon 的投票與逾時規則（見 ADR 0005）。狀態機是純函式，含 QC/TC、BLS 聚合簽章、最終性證明 `CommitProof`、安全狀態的持久化與恢復
- [x] `sim`：決定性模擬器，涵蓋延遲、丟包、GST、崩潰重啟和 5 種拜占庭行為（包括串通的連續惡意 leader）。CI 每次跑 10,000 個情境
- [x] `chain`：尚未最終的區塊透過 overlay 疊在已提交狀態上推測執行。同一個 parent 可以有多個候選，提交後其餘的自動丟棄
- [x] DA 投票規則：投票前必須以 Bitswap 取得區塊的全部 chunk、寫入 blockstore、在 parent 上重新執行，且 header 相符
- [x] `boltchain validator`：共識、出塊、提交，並在提交後發出帶最終性證明的公告。跟隨節點只匯入帶有效證明的區塊
- [x] `net`：新增共識 gossipsub topic `/bolt/<chain id>/consensus`

### 驗收

| 項目 | 結果 |
| --- | --- |
| 模擬 10,000 個故障情境，無安全違規 | 情境 0–9,999 與 10,000–19,999：0 安全違規、0 活性失敗（release 各約 65 秒） |
| 故意改壞程式，確認模擬器抓得到錯 | 移除鎖定規則：3,000 個情境中抓到 65 次違規。同輪兩票：沒抓到（見 ADR 0005） |
| 關掉 2 個節點仍持續出塊（`crates/node/tests/m3_consensus.rs`） | 7 個驗證者到高度 5 後關掉 2 個，其餘 5 個再推進 5 塊以上且 head 一致；只信任最終性證明的跟隨節點同步到同一條鏈。連跑 4 次都通過，每次約 30 秒 |

### 尚未完成（移到後續里程碑）

- [ ] leader 依質押權重做 VRF 抽樣，委員會由系統合約決定（M4）
- [ ] 投票直送下一任 leader，不走 gossip 廣播（M4/M6）
- [ ] 模擬器加入能精準分割誠實節點的對手，用來抓「同輪兩票」這類變異（M4）
- [x] 加密 keystore（EIP-2335）（M6，2026-09-27）
- [x] ~~主網 genesis 填入 7 位驗證者的 BLS 公鑰、PoP 和綁定簽章~~：已取消，主網改由 PoW 啟動，驗證者在鏈上質押加入（ADR 0007，2026-09-25）

## M4 結果（2026-09-25）

設計見 ADR 0006。完成項目：

- [x] 系統合約（Solidity 0.8.30，npm 的 solcjs 編譯；產物提交在 `contracts/out`，CI 會重新編譯比對）：
  - StakingManager：註冊時在鏈上驗證 PoP，最低 64 BOLT，退出後 14 epoch 可提領，可暫停存入
  - ConsensusRegistry：各 epoch 的委員會；雙重投票與雙重提案證據在鏈上驗證，罰沒 5%–100%（相關性加重），1% 給舉報者
  - RewardDistributor：流通量記帳（燃燒、罰沒）、每區塊記票、epoch 結算
  - ParamRegistry：參數有硬性上下限
  - HistoryRegistry：先保留位址，M5 實作
  - 治理：Safe 1.4.1 5-of-9，加上兩個 OpenZeppelin TimelockController（16 天、2 天）
  - 系統合約都是 UUPS proxy，只有 16 天 timelock 能升級
- [x] Solidity BLS 函式庫：RFC 9380 hash-to-curve（SHA-256 預編譯、MODEXP、EIP-2537），與 blst 交叉驗證
- [x] genesis：在固定位址直接執行 initcode 部署系統合約，再以 system 地址初始化。devnet genesis hash 改為 `0x207c7090…8ea0c`
- [x] 每區塊的 system call：記錄燃燒與投票；epoch 起點結算上一個 epoch 的獎勵，並依質押權重抽下一個 epoch 的委員會（512 席，可重複抽中）
- [x] RANDAO：`extra_data` 帶 proposer 的 BLS reveal，投票前驗證
- [x] 共識：
  - 訊息與簽章加入 epoch；
  - epoch 交接用 nil 收尾區塊與 anchor QC；
  - 席次加權的 leader 輪值；
  - 一個引擎可以替多把本地金鑰簽署。
- [x] 模擬器：一半的情境每 3–12 個區塊換一次委員會（隨機子集、隨機席次）；節點在 epoch 結束時切換引擎，落後的節點用 epoch 證明追上
- [x] 驗證者節點：
  - 從鏈上狀態讀取委員會，一個節點可以持有多把金鑰；
  - 保存 epoch 證明；
  - 偵測到雙重投票時寫出可以直接送出的證據 calldata。
- [x] 跟隨節點：落後超過一個 epoch 時，逐個 epoch 驗證證明再匯入
- [x] 網路層：送往節點的事件不再阻塞 swarm（節點處理不及時丟棄 gossip，而不是讓 Bitswap 停擺）；追趕匯入移到獨立的 task
- [x] dev profile 對所有相依套件開最佳化（revm、blst 不最佳化時慢 10–50 倍，多節點測試會餓死）

### 驗收

| 項目 | 結果 |
| --- | --- |
| 100 個驗證者跑完 epoch 輪替（`crates/node/tests/m4_pos.rs`） | 100 個驗證者（各約 100 BOLT）在 epoch 0 以交易註冊，由 5 個節點運行 107 把金鑰；epoch 2–6 的委員會各不相同，數十位驗證者輪流上任，啟動期驗證者只佔 80 席中的 2 席；新的跟隨節點從 genesis 逐個 epoch 驗證證明，同步到 epoch 6。release 約 43 秒、debug 約 46 秒 |
| 鏈上驗證雙重簽名證據並罰沒 | 注入的雙重投票被節點偵測、寫出證據，以交易送出後，該驗證者被罰沒 5% 並失去抽籤資格。`submitEvidence` 需 572,075 gas，`register` 需 428,634 gas |
| 流通量不變量（`crates/chain/src/epoch_tests.rs`） | 逐塊檢查「餘額加總 = 流通量 + 罰沒鎖死額」，包括燃燒、增發、鎖倉、提領 |
| 共識模擬 | 見下方 |

模擬器第一次跑 seeds 10,000–19,999 時，seed 19148 出現 2 次安全違規。原因是隨機產生的委員會讓拜占庭節點拿到 43% 的席次，超出 BFT 的前提（< 1/3），不是協定錯誤。產生器已改為保證每個委員會的拜占庭席次低於 1/3，之後重跑的結果記在 ADR 0006 §12。

### 決定

- [x] 啟動期驗證者的鎖倉獎勵在抽籤與退出條件中設權重上限，預設 78,125 BOLT（ADR 0006 §11）。驗收情境中，啟動期驗證者只佔 80 席中的 2 席

### 尚未完成（移到後續里程碑）

- [x] 存儲獎勵與歷史抽查（M5；金額見 ADR 0012）
- [ ] 證據自動送交易（需要付 gas 的帳戶）、投票直送 leader、sentry 節點（M6）
- [x] 交易 gossip（M6，`m6_tx_gossip`）

## 方向調整：PoW 啟動（2026-09-25，ADR 0007）

專案負責人決定：鏈在初期不依賴 CAFECA 的驗證者，也沒有任何特殊待遇的錢包。
啟動期改為「CPU 友善的 PoW 起步，質押最終性逐步接手」，分三個階段：

- 階段 A：純 PoW
- 階段 B：PoW 出塊，質押委員會確認檢查點
- 階段 C：PoS

M4 的 PoS 機制完整保留，用在階段 B 與階段 C；啟動期驗證者相關的程式碼會在 M4.5 移除。

### M4.5 PoW 啟動期：結果（2026-09-25）

- [x] RandomBOLT：RandomX 1.2.1 原始碼放在 `third_party/randomx`，只改 Argon2 salt（`RandomBOLT\x01`），Monero 的算力不能直接挪用。light mode 驗證（雲端 x86 每次 28 ms），fast mode 挖礦；種子每 2,048 塊更換、延遲 64 塊。每把金鑰共用一份 cache，VM 以池管理，驗證與挖礦可以並行
- [x] header 封印：`difficulty` 放難度，`nonce` 放 PoW nonce，輸入是「nonce 清零的 header hash ‖ nonce」；ASERT（aserti3-2d 三次多項式），目標 12 秒、半衰期 1 小時，主網起始難度 2¹⁸
- [x] 分叉選擇：累積難度最大者勝，同分取 hash 較小者（每個節點選得一樣）。儲存層新增累積難度表與「倒回 head」，用狀態歷史反向套用並核對 state root。自動重組上限 128 塊，也不會越過 PoS 區塊
- [x] PoW 同步：公告不帶證明；跟隨節點沿 envelope 的 parent 往回找到已知區塊（可以在別的分支上），檢查每個封印後交給分叉選擇。PoS 區塊的祖先如果是挖出來的，也走封印驗證
- [x] `boltchain mine`、`validator --mine`；每塊獎勵 = 未發行量 × 6.59×10⁻⁸ × 80%，直接記給礦工並計入流通量
- [x] 移除啟動期驗證者、鎖倉獎勵、鎖倉權重上限。genesis 不列任何驗證者；dev 鏈可以用 `devValidators` 在 genesis 質押，從第 1 塊就跑 PoS（M3/M4 的測試改用這個）
- [x] 移除治理（ADR 0008）：Safe、兩個 timelock、UUPS proxy、ParamRegistry、暫停權限都刪除；系統合約直接部署在固定地址，管理函式只接受 system 地址。`0xB017…0004` 留空
- [x] gasLimit 由出塊者投票（每塊變動小於 parent 的 1/1024，範圍 15M–60M，`--gas-target`）；委員會大小、最低 base fee 是 genesis 常數
- [x] 硬分叉表（目前是空的）與不規則狀態變更（替換合約程式碼、寫 storage）；分叉 ID（EIP-2124）放在 identify 的 agent 字串，不相容的 peer 會被斷線，看到更新的分叉會提醒升級
- [x] 階段 A → C：每個 epoch 起點檢查 T2（主網 128 人、1,000 萬 BOLT），連續 14 個 epoch 成立就排定 PoS 從兩個 epoch 後開始；終端區塊是 PoS 前一個 epoch 的最後一塊；首個委員會只算滿 14 個 epoch 的質押；之後的 PoW 區塊一律無效
- [x] 首個 PoS epoch 以終端區塊為 anchor，第一塊不帶證明（和 genesis 的下一塊一樣）。若在委員會認證任何區塊之前，較重的分支換掉了終端區塊，引擎換到新 anchor 重新開始，而且不會在用過的 round 再簽名
- [x] 模擬器（`crates/sim/src/pow.rs`，可重現）：
  - 20 個誠實礦工、1 秒傳播：孤塊率約 7%，平均出塊 12–14 秒，最深重組 1 塊
  - 起始難度估高 10 倍：一天內平均出塊仍在 24 秒以內
  - 60% 算力私下挖約 10 分鐘再公開：誠實節點跟著重組（最深 43 塊），這是階段 A 已知的風險
  - 同樣的攻擊私下挖超過 128 塊：被拒絕，誠實節點留在自己的鏈上
  - 33% 自私挖礦：拿到約 41% 的區塊。同分取小 hash 等同隨機選邊，門檻約 25%（first-seen 規則在攻擊者連線好時更差），這是階段 A 的已知代價，要靠階段 B 補
  - 網路分區 10 分鐘：重新連上後較輕的一邊重組（23 塊）；分區 1 小時：超過上限，兩邊各自維持，需要營運者介入
- [x] 轉換點奪取：在首個委員會抽籤前一刻質押 50 倍資金的大戶拿不到席位，下一個 epoch 才有（`crates/chain/src/pow_tests.rs`）

| 驗收項目 | 結果 |
| --- | --- |
| 5 個礦工節點 + 10 個跟隨節點，自動切換到 PoS（`crates/node/tests/m45_pow.rs`） | RandomBOLT（light mode）挖礦；4 位驗證者在挖礦階段以交易註冊，第 9、17 塊滿足門檻，PoS 排在 epoch 4，第 32 塊是終端區塊；之後的區塊全部由委員會產生，15 個節點停在同一條鏈上，至少兩位礦工挖到區塊。debug 約 160 秒 |
| 終端區塊之後的 PoW 區塊無法接受 | 同一測試：接在終端區塊後面的 PoW 區塊被拒絕 |
| 從 genesis 同步會驗證 PoW | 同一測試：新節點逐塊檢查封印，接著逐個 epoch 驗證 PoS 證明 |
| 51% 攻擊下重組上限生效 | `chain` 測試：比 128 塊更深的較重分支被拒絕，head 不變；模擬器同上 |

已知限制（M4.6 處理）：

- 委員會已經在某個終端區塊上認證區塊之後，如果有跟隨節點改跟了另一條更重、終端區塊不同的 PoW 分支，它驗不了 PoS 證明，會卡住。階段 B 先確認深度 ≥ 32 的檢查點，可以消除轉換點的分歧
- 重組時先倒回再匯入，期間 RPC 會短暫看到較低的 head
- 交易仍沒有 gossip（M6）；挖礦節點只打包自己交易池裡的交易

### M4.6 質押最終性：結果（2026-09-25）

- [x] 階段 B 排程：每個 epoch 起點也檢查 T1（主網 32 人、100 萬 BOLT），連續 14 個 epoch 成立就排定階段 B 從兩個 epoch 後開始。PoS 必定晚於或同時於階段 B；同時達成時跳過階段 B。首個階段 B 委員會同樣只抽成熟質押
- [x] 檢查點確認：沿用 M4 的 BFT 引擎與最終性證明格式，只是「區塊」換成 PoW 鏈上的區塊。leader 提議上一個已確認區塊的下一塊（被埋至少 32 塊之後）；成員只在它是自己規範鏈上的那一塊、而且被埋得夠深時才投票；兩鏈規則提交後，這塊與所有祖先就是最終的。每個 epoch 的委員會確認該 epoch 的區塊，epoch 最後一塊的證明交接給下一個委員會
- [x] 分叉選擇：不會越過已確認的檢查點；檢查點若在別的分支上，節點會直接切過去（質押最終性優先於累積難度）。最終性以公告附證明傳到所有節點，跟隨節點也適用
- [x] 獎勵：階段 B 的每塊獎勵 60% 給礦工；40% 在 epoch 結束時依參與度付給委員會。參與度來自礦工放進區塊的最新檢查點 QC（鏈上逐一驗證 BLS 聚合簽章，每個 round 只算一次）
- [x] A → B → C：階段 B 會確認到終端區塊為止（終端區塊附近的深度要求遞減到 0），首個 PoS 區塊帶著這個證明，所以 M4.5 的轉換點分歧不再發生；階段 B 沒跑過時才沿用 M4.5 的做法
- [x] 模擬器：同樣是 60% 算力私下挖 50 塊，在階段 A 會改寫歷史（最深重組 43 塊、攻擊者拿走 92% 區塊）；有深度 32 的檢查點時被所有誠實節點拒絕，攻擊者只拿到攻擊前的 13%
- [x] 小額質押奪取：只有一位（質押 50 倍）的驗證者永遠湊不到 T1，沒有委員會可奪（`crates/chain/src/pow_tests.rs`）

| 驗收項目 | 結果 |
| --- | --- |
| A → B → C（`crates/node/tests/m46_finality.rs`） | 3 個礦工、1 個不挖礦的驗證者節點、2 個跟隨節點。第 9、17 塊滿足 T1，階段 B 從 epoch 4 開始，6 個節點的最終檢查點一起前進（包括跟隨節點）；後來加入的兩位驗證者讓第 41、49 塊滿足 T2，PoS 從 epoch 8 開始；第 64 塊（終端）由階段 B 確認，第 65 塊帶著它的證明；新節點從 genesis 同步完整條鏈。debug 約 150 秒 |
| 多數算力攻擊被質押最終性擋下 | 同一測試：從最終檢查點之下分岔、累積難度更高的私有分支被拒絕；沒有這個最終性的對照節點則會重組過去 |
| 階段 B 的獎勵 | 同一測試：epoch 4 的投票者在第 41 塊領到獎勵；`chain` 測試核對 60% / 40% 與 QC 驗證、同一 round 不重複計算 |

已知限制：

- 投票者的參與度要靠礦工把 QC 放進區塊；礦工沒有直接的誘因這麼做（預設的節點軟體會做）。每個 epoch 最後約 32 塊的 QC 會落到下一個 epoch 才產生，這部分參與度不計入
- 最終性以「同時到達」的方式傳播：節點在收到證明之前仍依累積難度選鏈

### 決定

- [x] 治理：規則只能靠硬分叉修改，鏈上沒有任何治理權限；節點預留自動更新機制，預設只提醒（ADR 0008）

## M5 儲存層：結果（2026-09-25，ADR 0009）

- [x] epoch 索引：每個 epoch 的第一塊把上一個 epoch 的 envelope CID 建成 dag-cbor 索引，以系統呼叫記錄在 `HistoryRegistry`；從鏈上狀態就能找到全部歷史
- [x] 狀態快照：每個 epoch 結尾依地址順序切成確定性分塊（約 512 KiB），誠實節點得到相同的 CID；保留最近 2 份，舊快照只刪除沒有共用的分塊；區塊最終後在 `/bolt/<chain>/storage` 公告
- [x] 檢查點同步：`--checkpoint <number>:<hash>`（可選 `--snapshot <cid>`）。取回快照、區塊與前 256 塊（或本 epoch 起點）的 header 和 envelope，在同一個寫入交易中重建狀態與 MPT，狀態根必須吻合信任的 header；該塊成為 head、最終檢查點與本地歷史起點
- [x] 修剪與分片：舊於保留窗口（主網 7 個 epoch）的 body 會刪除，除非本機驗證者是該 epoch 的 16 位被指派者之一（rendezvous hashing）；被指派的 epoch 缺什麼就從網路補齊；header 與 envelope 永遠保留；`--archive` 關閉修剪
- [x] 抽查：每個 epoch 抽出 16 人小組與 16 個任務；審計者只向提供者登記的 peer（`setPeer`）要抽中的分塊，簽 `AuditVote`；超過 2/3 聚合成 `AuditCert` 放進 envelope，鏈上驗證後記錄。通過平分該 epoch 排放的 20%，失敗罰 1% 質押（不強制退出）
- [x] 公開閘道：`--gateway`，提供 trustless gateway 子集（`/ipfs/<cid>?format=raw|car`、`/history/epoch/<n>.car`）；`boltchain history export --epoch <n>` 離線匯出 CAR
- [x] 工具：`boltchain keys set-peer-tx`；Bitswap 新增只問指定 peer、不看本機的 `probe`

| 驗收項目 | 結果 |
| --- | --- |
| 索引、抽查、存儲獎勵（`crates/node/tests/m5_storage.rs`） | 3 個節點、7 位 genesis 驗證者、6 塊的 epoch、保留窗口 1 個 epoch，持續有轉帳。每個 epoch 都有索引；7 位 owner 送出 `setPeer` 後，epoch 2 的 16 個任務全部通過並在同一個 epoch 內上鏈，通過者在 epoch 結算時領到存儲獎勵 |
| 修剪 | 同一測試：沒有驗證者的節點逐一刪除舊 epoch 的 body；驗證者（7 人少於 16 份副本，全部被指派）保留完整資料 |
| 新節點從快照起步追上最新區塊 | 同一測試：新節點只信任第 30 塊的雜湊，0.2 秒內從公告的快照起步，接著用最終性證明追上最新區塊；區塊雜湊與驗證者一致 |
| 從閘道讀得到歷史 CAR | 同一測試：從驗證者的閘道取得 epoch 0 的 CAR（18 個 IPFS 區塊），逐塊驗證 CID，還原出 6 個完整區塊；已修剪節點的閘道回 404 |
| 單元測試 | 快照往返（跨分塊的大 storage、狀態根相同、確定性）；鏈上：錯誤的信任雜湊被拒、從快照繼續匯入、修剪後補回、只保留 2 份快照；無效或偽造的抽查證書整塊拒絕；失敗罰 1% |

整個測試在 debug 約 40 秒。

已知限制（移到 M6）：

- 修剪巡檢每 2 秒掃過所有舊 epoch，主網規模要改成游標與事件驅動
- 快照建立期間持有讀取交易，狀態很大時資料庫檔案會暫時成長
- 檢查點必須是節點仍保留的快照（約最近 2 個 epoch）；之後改成接受較新的快照，再回溯 header 驗證到檢查點
- 儲存 topic（審計投票、快照公告）沒有 peer scoring 與速率限制；閘道沒有速率限制
- 抽查只證明「被問時交得出來」；空區塊的抽查目標是人人都有的 envelope

## M6 強化與測試網：進行中

先開小型公開測試網，讓問題在真實環境中浮現，再依觀察做網路強化。

- [x] 確認區塊資料完整存在 IPFS：以標準 IPFS 實作（Helia）只靠 Bitswap，從最新區塊沿 `parent` 一路下載到 genesis。157 塊、60 筆交易、12 個 body 分塊，與 RPC 逐塊比對零差異（`scripts/interop/helia-full-chain.mjs`）
- [x] 修正：M4.5 的分叉 ID 檢查把沒有分叉 ID 的一般 IPFS 用戶端斷線，導致它們取不到區塊。現在保留連線，但不把它們當成鏈上的 peer
- [x] 修正：交易池沒有檢查 intrinsic gas 與 EIP-7623 calldata 下限，這類交易 RPC 回應成功，之後卻在出塊時被默默丟掉
- [x] 修正：`eth_estimateGas`、`eth_getBalance` 等方法省略區塊參數時回傳 Invalid params（ethers 與 MetaMask 會省略這個參數）
- [x] 修正：同一個區塊的重播公告被 gossipsub 當成重複訊息丟掉，晚加入的節點收不到。公告加上發送時間 `at`
- [x] 維運：`--metrics`（Prometheus `/metrics`、JSON `/health`）、每分鐘一行 status 日誌（含雜湊率）、`net_peerCount`
- [x] 錢包：`boltchain wallet new|balance|send|stake|set-peer`，伺服器上不需要 MetaMask
- [x] 測試網 genesis（chain 8018，從挖礦開始，門檻縮小）、部署腳本（systemd 與免 root 兩種）、release workflow、加入說明（`docs/testnet.md`）
- [x] 公開測試網上線（2026-09-25）：211.22.118.149 上跑 4 個節點、16 把驗證者金鑰，公開 bootnode、RPC 與 IPFS 閘道
- [x] 測試網觀察 1：交易只會被收到它的那個節點放進區塊（其他節點看不到），公開 RPC 送出的交易平均要等好幾個區塊。加上交易 gossip（`/bolt/<chain>/tx`），本機收進交易池的交易會轉發給所有節點（`crates/node/tests/m6_tx_gossip.rs`）
- [x] 測試網觀察 2：Kubo 經由公開節點從 head 下載到 genesis 全部成功。Helia 連到公開節點時，大約 80 則訊息後就不再送出新的 want（節點端都有回覆）→ 待查
- [x] 內建區塊鏈瀏覽器第一階段（ADR 0010）：`--explorer`，繁中與英文；首頁與共識階段進度、區塊、交易（系統合約與 ERC-20 解碼）、地址（含地址索引）、驗證者、epoch 與抽查、搜尋、在瀏覽器中驗證 IPFS 區塊
- [x] 網路強化第一批：
  - 位址過濾：identify 回報的私有、loopback、Docker（172.17/16）位址不再寫進 Kademlia，除非跟這條連線同一個範圍；避免公開節點互相散播撥不通的位址
  - peer 評分：gossipsub peer scoring（無效訊息 −100、關閉 IP 同址懲罰），公告時間戳改成單調遞增
  - 交易 gossip 先做無狀態檢查（解碼、chain id、gas 上限、intrinsic gas）再轉發；storage topic 每個 peer 每分鐘上限 600 則
  - HTTP 限流：閘道與瀏覽器每個 IP 每秒 20 次（突發 80），同時最多 128 個請求，超過回 429 / 503
  - NAT 穿透：AutoNAT、UPnP、Circuit Relay v2（`--relay-server` 開啟中繼，每條電路最長 30 分鐘、256 MiB）、DCUtR 打洞；AutoNAT 判定在 NAT 後面時自動經由最多 2 個中繼監聽（`relayed_node_serves_blocks`）
  - 防罰沒（doppelganger）：收到自己座位簽的、但不是本機送出的投票或逾時訊息，就停止用那把金鑰簽署並記錄錯誤、`doppelganger` 指標加一；該節點的其他金鑰照常運作（`m4_pos` 驗收）
- [x] 測試網部署 Uniswap v4（`scripts/uniswap-v4`）：PoolManager、PositionManager、UniversalRouter、V4Quoter、StateView、Permit2、WBOLT；原生 BOLT / tUSD 池加流動性、雙向兌換成功。瀏覽器加上 `--explorer-labels` 顯示合約名稱與常見方法名稱
- [x] 測試網觀察 3（2026-09-26）：第 3601 塊（epoch 6）如期進入階段 B，委員會確認的最終區塊穩定落後 head 約 33 塊（檢查點深度 32）；共識與匯入零錯誤、抽查憑證 16 張、快照 3 份
  - 每個節點的日誌約 3,000 行 WARN，九成以上是 gossipsub 拒絕重送同一則共識訊息。重送本來就不會送出去（gossipsub 在 60 秒內會把它當重複訊息），現在在節點內先過濾，60 秒後才會真的重送
  - 「sealed block not imported: unknown parent」是算出 nonce 時父區塊已經被重組掉，改成 debug 等級
  - 修剪數為 0 是預期的：歷史副本數 16 大於測試網的 8 位驗證者，所以每個節點都被指派保存全部歷史
- [x] 投票驗證成本（`boltchain bench votes`，雲端 x86 2 vCPU）：512 席、法定 342 票，逐票驗證 366 ms（每票約 1.07 ms），彙整 34 ms，驗證彙整簽章 25 ms → 1.3 ms（公鑰只在 epoch 開始時解碼一次，委員會的簽章驗證全部改用解碼過的公鑰）。樹莓派約慢 3–5 倍，逐票驗證約 1.1–1.8 秒，占 6 秒出塊的 20–30%。改成延後驗證：下一輪的 leader 收到的票湊滿法定數量後先彙整、只驗一次彙整簽章（約 35 ms），失敗才逐票找出偽造的票並丟掉；同一位簽署者出現兩個不同簽章時立即個別驗證，偽造票無法擋掉真票（`votes_are_checked_as_one_aggregate_and_forgeries_are_dropped`）。新增指標 `consensus_messages_total`、`consensus_bytes_total`、`bls_verifications_total`、`bls_verify_microseconds_total`
- [x] 測試網觀察 4（2026-09-26）：部署 r14 時 4 個節點依序重啟，之後最終區塊停在 4285，不再前進（檢查點仍持續被認證，但一直沒有提交）。原因是階段 B 的檢查點 round 不在挖出來的區塊 header 裡，只記在記憶體：重啟後，從新憑證往回走到上一個已提交區塊時，重啟前認證過的區塊查不到 round，提交一直等在 FetchBlock。修正：
  - 共識狀態檔多存已知但尚未提交的區塊（`Persisted.blocks`），重啟後直接接上（`resumed_engine_commits_without_refetching_uncommitted_blocks`）
  - 舊版狀態檔或真的查不到時：round 改用手上的憑證，再不行用 0（只會被沿路走過，兩鏈規則不可能把它當成 P 與 B 配對）
  - r15 部署後最終區塊從 4285 追到 4375，但約 10 分鐘後又停在 4397：各節點的 round 只靠逾時前進（最長 8 倍退避，約 108 秒一輪），新一輪的 leader 沒有送出提案。當時的除錯紀錄不夠完整，無法確定原因
  - 加上共識除錯紀錄（`boltchain::validator=debug`：收到的提案、投票、逾時，round 變化與 leader，自己的提案）與每分鐘的 gossip mesh 和 peer 分數。r18 全部重啟後，最終區塊穩定落後 head 約 33–36 塊。持續觀察，若再停住就用這些紀錄找原因
- [x] 測試網觀察 5（2026-09-27）：加入第二台主機（211.22.118.148，2 節點）後，第 3330 塊達到 16 位驗證者、102,152 BOLT；第 3601、4201、4801 塊連續三次達標，第 6001 塊（2026-09-27 03:49 UTC，第 10 週期）如期進入 PoS
  - 進入 PoS 後出塊時間穩定 6.0 秒、難度 0，最終區塊等於 head（即時最終性）；兩台主機 6 個節點 head 一致，n1 日誌零 ERROR
  - 最近 300 塊的提案者分布大致依質押比例（主機 2 的 8 位驗證者約 78% 質押、出 85% 的塊）
  - n1 日誌約 6,000 行 WARN，幾乎全是 gossipsub「Not publishing a message that has already been published」：觀察 3 的節點內重送過濾沒有涵蓋全部路徑，待查
  - SwarmStorage：驗證者 1 報價；deal 0（300 KB，密封後 1.57 MB）由保存者取走，從沒有持有區塊的節點 `storage get` 讀回，雜湊一致
- [x] 測試網觀察 6（2026-09-28）：PoS 下 15,500 塊，出塊平均 6.05 秒，兩台主機 6 個節點一致、零 ERROR；抽查 560 張憑證全數通過、每小時一份快照
  - 唯一的缺塊：9/27 07:55 UTC 只重啟 n1（部署瀏覽器）後，n1 一直到下一個 epoch（約 1 小時）都無法驗證提案，輪到它的 27 次都逾時（每次 30–36 秒）。原因：重啟時錯過了一個提案，之後每個提案都建立在它沒有的區塊上，被拒絕的提案也不保留，於是一路拒絕；已最終的區塊經 catch-up 匯入又總是落後
  - 修正：提案因父區塊未知而失敗時，沿著信封的 parent CID 向 peer 取回缺的區塊並驗證（成為待定區塊，仍只經共識提交），並保留父區塊未知的提案供後續使用；新測試 `m3_restart`（第 7 位驗證者中途加入，之後不能有任何一輪逾時）修正前 4 次失敗 3 次，修正後 5 次全過
  - 記憶體：跑了 1–2 天的節點 RSS 約 800 MB，持平；繼續觀察
- [x] 測試網事件 7（2026-09-30 – 10-02）：主機 2（約 78% 質押）斷電，質押不足 2/3 停鏈是預期的；10/1 08:27 UTC 兩台主機開機後節點自動啟動，鏈卻停了約 26 小時，每位 leader 都報「could not build proposal: parent block not available」，10/2 10:26 UTC 手動把各節點的 high_qc 改回 committed_qc 才恢復
  - 原因：HotStuff-2 的 high_qc 永遠指向已認證、尚未最終的區塊（兩鏈規則下最終區塊是它的父區塊），而待定區塊只存在記憶體。全部節點同時重啟後沒有人有它，所有提案都必須建立在它之上，因此永遠停住。區塊資料其實已寫入 blockstore（投票前就寫入），只是沒有「區塊 hash → 信封」的對照，重啟後無法重建
  - 修正（r35）：執行過的待定區塊在同一筆交易中把信封 CID 記入新表 `pending`（最終後刪除）；重啟時在恢復共識狀態前，依共識狀態中的區塊、high_qc 與 committed 從 blockstore 重新執行（`Chain::restore_pending`），不需要網路
  - 共識狀態檔改成寫入暫存檔 → fsync → rename → fsync 目錄，斷電後不會變成空檔；狀態檔存在卻無法解析時拒絕啟動（不再當成沒有狀態，以免同一 round 重複投票）
  - 新測試 `whole_committee_restarts`：7 個驗證者各自在獨立 runtime 上執行，連續 3 次全部同時終止再啟動，每次都要再出 6 塊；修正前第一次重啟後就重現測試網的錯誤並停住，修正後連跑 3 次通過
- [x] gossip「Not publishing a message that has already been published」查明（觀察 5 的待查項目；n1 九天約 13,000 行，約占 17% 的區塊）：每個驗證者在區塊最終時都會發布同一則最終性公告，內容只差發送時間 `at`（毫秒）。不同節點在同一毫秒提交時，公告逐位元相同，別人的那份先到，gossipsub 就拒絕我們的並記一行 WARN。不是重送、沒有遺失訊息，去重本身是好事；10/2 之後的 WARN 只剩這一種。改成發布前先比對最近收到的公告，相同就不再交給 gossipsub
- [x] `/health`、`/metrics` 的 `finalized` 在 PoS 下一直停在最後一個階段 B 檢查點（測試網 6000）：PoS 下只存已最終的區塊，改成回報 head（`Chain::final_height`，瀏覽器狀態也改用同一個函式）
- [x] 版本帶 commit：`boltchain --version`、瀏覽器 `/api/status` 的 `version`、`web3_clientVersion` 都顯示 `0.1.0-<commit>`（有未提交修改時加 `-dirty`；沒有 git 時可用環境變數 `BOLT_COMMIT` 指定），從外部就能確認節點跑的是哪個版本
- [x] 測試網事件 8（2026-10-11 – 10-12）：第 180000 塊（epoch 299 結束）後停鏈約 16 小時
  - 根因：P2P 連線洩漏。AutoNAT 每次探測都由對方回撥開一條新連線，之後一直不關（多出的連線上還有串流，所以閒置逾時也不會關）。約 7 天後，6 個節點中有 5 個用光 1,024 個檔案描述符（約 880 條 TCP 連線）
  - 主機 2 的 n2 最先用光：存不下 epoch 299 的證明、讀不到共識狀態，`cannot enter epoch 300` 後再也沒有重試。它的席位不在，其餘湊不到 2/3。重啟後它是 round 2 的 leader，卻因沒有證明而放棄提案，又多卡了一輪
  - 連帶：瀏覽器、RPC、/health 無法接受新連線；閘道的 accept 在 EMFILE 下忙迴圈占滿核心；狀態寫不進硬碟時仍照送投票
  - 修正（r38）：
    - 同一個 peer 只保留一條連線（直連優先、回應 ping 的優先、再取最舊），其他的 30 秒後關閉（`one_connection_per_peer_is_kept`；`connections_do_not_accumulate`，4 個節點 5 分鐘：修正前每分鐘多 8 個 socket、累積到 46，修正後穩定在 10）
    - 啟動時把開檔上限提到 hard 上限（最多 1,048,576），低於 8,192 時警告
    - 進入下一個 epoch 失敗時每 5 秒重試
    - epoch 證明同時保留在記憶體，檔案寫入失敗也能提案
    - 共識狀態沒寫進硬碟時，不送出投票與逾時
    - 閘道 accept 失敗時暫停 0.5 秒
  - 恢復：10/12 03:17 UTC 全部重啟，03:24 單獨重啟主機 2 n2 後恢復出塊
- [ ] 觀察一週：A → B → C 轉換、外部節點加入、抽查與修剪、快照同步；依觀察到的問題排定網路強化的順序

## 發行改制（ADR 0012）：已實作

決定（2026-09-26）：取消總量上限；每塊 32 BOLT（共識 31 + 存儲 1），每 4 年（鏈上時間）減半，第 5 期起固定為共識 1 + 存儲 1；PoS 之後每塊一樣；取消算力份額與金絲雀任務；存儲開放給未質押節點；公開測試網重新開始。

- [x] `consensus_reward(era)`、`storage_reward()`、`emission_era`（`params.rs`）；礦工每塊直接拿共識獎勵（階段 B 為 60%），委員會與存儲在 epoch 結束時以「塊數 × 當期獎勵」結算
- [x] 移除 `SUPPLY_CAP`、按池比例發行、`reward_split`、`bolt_pow::block_reward`
- [x] `ComputeMarket` 移除算力份額（`recordWork`、`previewCompute`、`settleCompute`、`minted`）；每條鏈都在 genesis 部署；流通量只看 `RewardDistributor.supply`
- [x] 測試網 `compute` 分叉與固定 bytecode 移除；分叉機制保留（目前沒有任何鏈有分叉）
- [x] 未質押存儲提供者：`HistoryRegistry.registerStorage` / `registerStorageFor`（簽名、免 BOLT）、id 從 2^31 起、每個舊 epoch 另外 16 份副本（不擠掉驗證者）、領獎時扣 20% 累積押金（上限 64 BOLT）、抽查失敗燒 10% 押金並停止分配、14 天後取回押金；`wallet storage-register [--signed]`、節點 `--storage-account`
- [x] 開發鏈 genesis hash `0x89feb030…bd70103`；新測試網 genesis hash `0x0dd221df…e162bb`
- [x] 測試網重新開始（2026-09-26 10:00 UTC 新 genesis；8 位驗證者重新質押並 `set-peer`；Uniswap v4 重新部署）
- [ ] 中繼工具：代送未質押提供者的簽名註冊

## SwarmStorage（ADR 0014）：已實作

決定（2026-09-26）：新的 `SwarmStorage` 系統合約處理付費保存使用者資料，並取代 `HistoryRegistry`（同一地址），歷史與委託共用抽查。

- [x] `SwarmStorage`：保留 `HistoryRegistry` 的儲存佈局；提供者報價（容量、最低單價）、委託（託管、隨機指派、每個 epoch 領款、未質押者 20% 進押金、接單上限 5 + 10 × 押金）、延長、取消、結束結算、修復、`withdraw` / `payout`
- [x] 抽查：每個 epoch 在 16 個歷史任務後加 16 個委託任務；新副本寬限一個 epoch；失敗時罰則同歷史、副本解除且未付款項不付、自動抽替補；只有歷史任務分發行量
- [x] `DealIndex`（`bolt-ipld`）、節點保存者巡檢、委託資料公告（`DealAnnounce`）、審計者探測委託區塊
- [x] JSON-RPC `bolt_hostBlocks` / `bolt_getBlocks`（`--rpc-storage`）、`boltchain storage put/get/offer/deal/settle/extend/cancel/withdraw`、瀏覽器顯示任務種類
- [x] 測試：合約（指派、領款、押金上限、失敗與替補、修復、取消與延長、驗證者報價、測試網升級保留狀態）、整合測試 `m7_swarm`（3 份副本、抽查通過、領款、讀回檔案）
- [x] 開發鏈 genesis hash `0x4cb847e8…3e09418e`；測試網 genesis 不變，以分叉 `swarm` 在第 2401 塊換上固定的 bytecode
- [ ] 保存者刪除已結束委託的區塊
- [ ] 依委託金額加權抽查、提供者拒收、同一委託的副本分散到不同機器

## 存證與託管證據驗證（ADR 0015，issue #1）：已實作

決定（2026-09-28）：瀏覽器新增 `/verify`，用戶上傳檔案或證明檔，在瀏覽器中比對鏈上證據，並可下載報告。第一版不處理歷史狀態：事件證據任何時間都能驗證，`eth_call` 錨點與託管餘額以最新狀態為準。

- [x] `verify.js`：keccak-256 / sha-256（32 位元版本、Worker 分段，40 MiB 約 2.6 秒）、RLP、MPT 重建與 proof 驗證、ABI 編解碼（帶名稱的簽章與 tuple）、四種 Merkle 規則（對齊 CO2Exchange 的 `LedgerMerkle`、`MerkleSumTree`，以及 OpenZeppelin）
- [x] 不相信節點：區塊標頭 → 區塊雜湊，交易與 receipt trie → 標頭 root，託管餘額以 storage proof 對 `stateRoot` 證明
- [x] API：`/api/raw/block/<n>`、`/api/proof/<address>`、`/api/call`；RPC `eth_getProof`（只支援最新狀態）；`boltchain devnet --explorer`
- [x] 報告：JSON（附原始資料，可對任一節點重做）與可列印版（另存 PDF）；繁中／英文；手機寬度
- [x] 證明檔格式：`docs/evidence-proof-format.md`
- [x] 測試：參考向量 357 項（viem、@ethereumjs/trie、OpenZeppelin、CO2Exchange 的樹）、state proof 對 alloy-trie、端到端（本機鏈部署 CO2Exchange `Ledger`，Chromium 操作頁面）
- [ ] 巢狀證明（先證明小樹的 root 在葉子裡）
- [ ] 完整狀態歷史與歷史 `eth_getProof`（有需求再做）
- [ ] 公開瀏覽器走 HTTPS（反向代理）

## 存證證書（ADR 0016）：已實作

決定（2026-09-28）：在瀏覽器上傳檔案建立證書，以 CAFECA 支付 BOLT，手續費全部付給 SwarmStorage 儲存提供者；證書有 16 碼代碼，可選擇公開原始檔案供下載；證書頁有認證標章，可以上傳檔案比對。鏈上只記錄雜湊與大小，不記錄檔名。

- [x] `Certificates` 合約（一般合約，沒有管理員）：合約自行計算 root、代碼、建立委託（合約擁有、無法取消）、任何人可延長；`boltchain wallet deploy-certificates`
- [x] 瀏覽器節點：`POST /api/upload`、`POST /api/deal-index`（向提供者公告）、`/api/storage/quote`、`/api/cert/<代碼>`；未付款的上傳有上限、6 小時後清理；閘道支援 POST（本體最大 8 MiB）；`--certificates`、`--cafeca-wallet`
- [x] 介面：`/verify` 只剩查詢與建立；`/cert/<代碼>` 證書頁（認證標章、檔案比對、公開檔案下載、列印）；證明檔驗證移到「進階」
- [x] 測試：合約、瀏覽器節點（上傳、清理）、跨語言向量、Chromium 端到端（CAFECA 以測試替身代替）
- [ ] 以真實 CAFECA 帳戶在測試網付款（需要 Passkey，人工測試）
- [ ] 延長保存的介面

## TEE Agent 租用（ADR 0013）：第一期軟體完成

決定（2026-09-26）：必須支援 DGX Spark、Intel AI PC、AMD AI PC（沒有機密 VM，新增 T2「量測開機裝置」等級，靠 TPM 與驗證小組）；接受驗證小組背書；公開機器 ID；檢查點每小時上鏈；LLM 呼叫外部 API；映像開放登記；同版本雙簽罰沒全部押金。決定（2026-10-14）：先做第一期的軟體部分，合約放進主網 genesis，測試網以硬分叉 `tee` 加入。

- [ ] 第零期：三款裝置實機確認（TPM、量測開機、Boot Guard / PSB、記憶體加密、IOMMU）
- [x] 合約：`ImageRegistry`、`TeeCollateral`、`TdxVerifier`、`EnclaveLease`、`LimitedWallet`（`0xB017…0008`–`000C`），Intel 真實附帶資料可上鏈驗證；開發鏈 genesis 信任模擬 PKI
- [x] `bolt-attest`：TDX quote 與附帶資料（與合約結果一致）、TPM quote / 事件記錄 / EK 憑證鏈 / MakeCredential；模擬 Intel PKI 與軟體 TPM
- [x] 驗證小組 TPM 背書：`AttestVote` / `AttestCert`、鏈驗證後 `recordAttestation`、`--tpm-roots`
- [x] 命令列：`image`、`collateral`、`enclave`（含 `runtime --simulate`）、`lease`；中繼代送檢查點與啟用；瀏覽器「TEE 租用」頁
- [x] 測試：合約、`bolt-attest`、端到端 `m8_tee`（中繼啟用、本機驗證與交付秘密、檢查點、回滾被拒、搬家、雙簽罰沒、T2 驗證小組、EIP-7702 限權錢包）
- [x] 測試網硬分叉 `tee`：第 233401 塊（固定程式碼 `contracts/forks/8018-tee`）
- [ ] `bolt-art` 映像（x86-64 / arm64，可重現建置）、真實 TDX 機器驗收、ECC EK、TCB Info 提交的 gas 優化（目前約 1,484 萬）
- [ ] 第二期：保管小組、SEV-SNP
- [ ] 第三期：GPU 機密運算

## M7 AI 算力市場（ADR 0011）：完成（待測試網實跑）

決定（2026-09-26）：爭議由驗證小組處理；SwarmStorage 改用 bolt-vault WASM。發行分配與金絲雀任務已由 ADR 0012 取消。

- [x] `bolt-vault`（`crates/vault`）：分塊 XChaCha20-Poly1305、大小級距、密文上的 Reed-Solomon（預設 4 + 2）、加密清單、HPKE（X25519）包裝內容金鑰、不重傳即可加入收件人；Rust 與 WASM（約 350 KB），Node 煙霧測試；`js/file_operator.ts` 取代 SwarmStorage 的同名檔案
- [x] `ComputeMarket` 系統合約（`0xB017…0006`）：執行者以簽名註冊（中繼代送，費用從第一筆收入償還）、託管、以簽名接單與交付收據、委託者核可或爭議窗口過後任何人結算（結算者得中繼費）、押金從收入扣 20% 累積到 64 BOLT、接單上限 5 BOLT + 10 × 押金、逾期退款、爭議押金 1 BOLT、驗證小組裁決（錯則罰押金 10%）、7 天無裁決視為執行者勝、任何人可代為把餘額推給帳戶
- [x] 每個 epoch 起點把待處理的爭議交給驗證小組（從委員會抽；挖礦階段沒有委員會時從質押者抽）
- [x] 節點端：驗證小組的裁決憑證（`VerdictVote` / `VerdictCert`，BLS 聚合，放在 envelope 的 `audits` 清單）；鏈驗證（爭議仍待裁決、分派給該 epoch 的小組、超過 2/3）後呼叫 `recordVerdict`；公開測試網隨分叉 `swarm` 生效；判定介面 `Judge`、`--verifier-cmd`（外部程式從 `BOLT_*` 環境變數讀取工作、輸出 `fault` / `ok`）；整合測試 `m7_verdict`
- [x] 驗證者加密金鑰（由 BLS 金鑰衍生、gossip 公布、`bolt_verifierKeys`）、`job share`（加入小組為收件人、委託者簽署的 `DisputeShare`）、`boltchain judge`（重跑比對 token 數與相似度）
- [x] `boltchain provider register|run|status|collect`（OpenAI 相容後端：llama.cpp、Ollama、vLLM）、`boltchain job post|status|result|approve|dispute|share|refund|withdraw`；整合測試 `m7_compute`
- [x] 零 BOLT 執行者的中繼（`--relay-wallet`、`bolt_relay`；`acceptFor` / `deliverFor` 的中繼費從工作款項付）、開放任何執行者承接（`provider run --open`、`job post --wait` / `job watch` 分享輸入）、瀏覽器「AI 推論」頁（CAFECA 發出工作、瀏覽器內加解密）
- [x] 判定改用 log-probability 比對（top-k 重疊、平均差距、分歧處的平手判斷；`job post --logprobs`）
- [x] `ModelRegistry`（`0xB017…0007`）與 `boltchain model register|list|support`；`post` 要求模型已登記
- [x] 主網 genesis 包含新版 `ComputeMarket` 與 `ModelRegistry`；測試網以硬分叉 `tee`（第 233401 塊）換上，儲存佈局相容
- [ ] 在公開測試網以真實的 llama.cpp 跑一次完整流程；以真實 CAFECA 帳戶從瀏覽器發出工作

## M6 追加項目（ADR 0008）

- [ ] 發布清單（m-of-n ed25519 簽章、IPFS 發布、gossipsub 公告）與驗證
- [ ] `--auto-update off|notify|apply`（預設 notify）、`--update-signers`、`--pin-version`；7 天冷卻期、分叉預告期檢查、啟動失敗自動回滾
- [ ] 可重現建置與 CI 建置證明
- [x] 測試網演練一次硬分叉（含不規則狀態變更）：分叉 `swarm` 在第 2401 塊替換 `0xB017…0005` 的程式碼；4 個節點一致跨過，程式碼等於固定檔（sha256 `0314aa91…`），舊狀態（epoch 索引、history peer）保留；`pinned_testnet_swarm_code_is_current` 改為只檢查固定檔的雜湊
