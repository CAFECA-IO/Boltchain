# ADR 0013：租用遠端 TEE 執行 AI Agent

- 狀態：已採納（2026-09-26）；第一期的軟體部分已實作（2026-10-14，見文末實作紀錄），`bolt-art` 映像與實機確認未完成
- 相關：ADR 0002（不加客製交易與預編譯）、ADR 0008（治理只靠硬分叉）、ADR 0009（儲存層與抽查）、ADR 0011（算力市場、bolt-vault）、ADR 0012（發行）、ADR 0014（SwarmStorage）

## 決定（2026-09-26）

1. 付費保存使用者資料由新的 `SwarmStorage` 系統合約處理，它同時取代 `HistoryRegistry`，把歷史抽查抽象化（ADR 0014）。
2. **必須支援 DGX Spark、Intel AI PC、AMD AI PC。** 這三類裝置沒有機密 VM（見第 2 節），因此新增「量測開機裝置」這一級信任。
3. 接受驗證小組背書的證明（SEV-SNP、TPM、GPU）。
4. 公開機器 ID。
5. 檢查點每小時上鏈一次。
6. Agent 的 LLM 呼叫外部 API。
7. Agent 執行環境映像開放任何人登記。
8. 同一狀態版本被雙簽時，罰沒執行者全部押金。

## 目標

委託者（以下稱「租用者」）付 BOLT，租用別人機器上的 TEE（可信執行環境），長時間執行一個 AI Agent：

- 執行者（機器主人）看不到 Agent 的程式狀態、記憶、金鑰與對話內容，也改不了它的行為。
- Agent 可以跨重啟、跨機器延續狀態（記憶、檔案、錢包）。
- 付款依實際運行時間結算，不需要信任執行者或租用者。

這和 ADR 0011 的「單次推論工作」不同：租約是長時間、有狀態、會對外行動（呼叫 API、簽交易）的服務。

## 結論摘要

| 項目 | 可行性 | 說明 |
| --- | --- | --- |
| 在鏈上驗證 Intel TDX quote | 可行 | Osaka 已有 P-256 驗證預編譯（EIP-7951，0x100，每次 6,900 gas）與 SHA-256（0x02），用一般 Solidity 合約就能驗證，**不違反 ADR 0002** |
| AMD SEV-SNP、TPM、NVIDIA GPU 證明 | 由驗證小組背書 | 需要 P-384、RSA 或挑戰式流程，鏈上不划算；驗證小組在鏈下驗證，以 BLS 聚合簽章回報 |
| DGX Spark、Intel AI PC、AMD AI PC | 有條件可行，信任等級較低 | 沒有機密 VM，改用 TPM 量測開機 + 專用系統；對軟體攻擊有效，對實體攻擊比機密 VM 弱得多（第 2 節） |
| TEE 內持久儲存 | 可行，靠新設計 | 硬體封存綁定單一晶片，TDX 甚至沒有封存金鑰；改用「與硬體無關的狀態金鑰 + 鏈上版本號 + SwarmStorage」（第 5 節） |
| 防止執行者竊看或竄改 | 對遠端與軟體攻擊者成立；**對有實體存取能力的執行者不成立** | 2025 年公開的記憶體匯流排攻擊（TEE.fail、Battering RAM、WireTap 等）在實體存取下可以取出 TDX / SNP 的證明金鑰或解讀記憶體，Intel 與 AMD 都把實體攻擊列在威脅模型之外 |
| 保證可用性 | 不可行 | TEE 不保證機器會繼續開著；只能做到「不運行就不付錢」與「可以快速搬家」 |

整體判斷：**可行，但定位要清楚**。TEE 讓「執行者偷看或竄改」從「隨手可做」變成「需要實體攻擊硬體、且一旦被抓到會失去全部押金」。設計上必須同時做到：

1. 在 Agent 可動用的價值上設上限（鏈上帳戶限額），而且低於執行者押金。
2. 讓 TEE 被攻破時留下可證明的證據，並罰沒執行者全部押金。
3. 狀態可以隨時搬到另一台機器。

## 1. 信任模型

**要防的對象**

- 執行者：可以看、改、重播、延遲所有進出 TEE 的資料；可以隨時關機、複製磁碟、重啟 Agent 並餵給它舊狀態；可以同時開兩份。
- 租用者：可能在服務完成後拒付。
- 網路上的其他人：可能冒充執行者或 Agent。

**信任的對象**

- CPU 與 TPM 廠商的證明根金鑰、韌體與 TCB 公告。
- Agent Runtime 映像檔的原始碼：必須可重現建置，任何人都能算出相同的量測值。
- Boltchain 共識（驗證小組的 2/3 誠實假設，和 ADR 0009、0011 相同）。
- 外部 LLM API 業者：Agent 呼叫它時，提示與回應對它是明文（決定 6）。

**不保證的事**

- 可用性（執行者可以關機）。
- 流量後設資料的隱私：執行者看得到 Agent 連到哪些主機、傳輸量與時間點，TLS 只能保護內容。
- 對抗實體攻擊：只能靠押金與罰沒提高成本，並讓租用者依信任等級挑選機器。

## 2. 硬體與信任等級

### 2.1 兩個等級

| 等級 | 硬體 | 隔離方式 | 證明 | 驗證方式 |
| --- | --- | --- | --- | --- |
| **T1 機密 VM** | Intel TDX（Xeon 第 4 代以後）、AMD SEV-SNP（EPYC 7003 以後）；之後加入 Arm CCA | CPU 以硬體加密並隔離 VM 記憶體，主機作業系統與 hypervisor 都讀不到 | TD quote（P-256）/ SNP 報告（P-384） | TDX 鏈上；SNP 驗證小組 |
| **T2 量測開機裝置** | DGX Spark、Intel AI PC（Core Ultra）、AMD AI PC（Ryzen AI）等沒有機密 VM 的機器 | 整台機器開進專用的 `bolt-art` 系統，沒有登入、沒有 SSH，執行者無法在上面跑自己的程式 | TPM 2.0 quote（PCR + 事件記錄）+ EK 憑證 | 驗證小組 |

租約標明等級，租用者依需要選擇；T2 的押金門檻與接單上限可以設得比 T1 保守。

### 2.2 為什麼這三類裝置只能到 T2

據我們所知（2026 年中），這三類裝置都沒有可遠端證明的機密 VM：

- **Intel AI PC**：TDX 只在 Xeon 伺服器處理器上；用戶端處理器早已移除 SGX。可用的是 TPM（Intel PTT，韌體 TPM）、Boot Guard，以及 vPro 機種的 TME（記憶體整體加密）。
- **AMD AI PC**：SEV-SNP 只在 EPYC 上。Ryzen AI PRO 機種有 TSME（Memory Guard，記憶體整體加密）與 Pluton / 韌體 TPM。
- **DGX Spark**（GB10，Arm CPU + Blackwell GPU，統一記憶體）：NVIDIA 的 GPU 機密運算目前只在資料中心 GPU（H100 以後）上；GB10 的 Arm 核心是否支援 Arm CCA、是否有 TPM，都要拿實機確認。
- **這幾點都必須在實機上驗證**，這是第一期的第一件工作（第 10 節）。如果某款裝置連 TPM 或量測開機都沒有，它就無法提供任何證明，不能承接 TEE 租約。

記憶體整體加密（TME / TSME）和機密 VM 不同：它防止記憶體條被拔走後讀取，但不隔離作業系統。T2 的隔離完全靠「機器只跑我們量測過的系統」。

### 2.3 T2 的做法

1. 機器開進專用的 `bolt-art` 開機項目（USB 或獨立分割區）：UEFI Secure Boot 簽章的統一核心映像（UKI，內含核心、initrd、命令列），根目錄 dm-verity 唯讀，沒有任何登入方式。
2. 開機過程把每一段量測寫進 TPM 的 PCR（韌體與設定 0–7，UKI 各部分 11，系統設定另外的 PCR）。
3. Runtime 產生 enclave 金鑰（第 4.2 節），用 TPM 的證明金鑰（AK）對 PCR 簽出 quote，quote 的 `qualifyingData` 填入與 T1 相同的綁定資料。
4. Runtime 另外回報硬體狀態：記憶體加密是否開啟、IOMMU 與 DMA 保護、Boot Guard / Platform Secure Boot 狀態。這份回報出自已量測的程式，因此可信。
5. 驗證小組：
   - 核對 EK 憑證鏈到 TPM 廠商的根憑證（Intel、AMD、Microsoft Pluton，或獨立 TPM 廠商）。
   - 以挑戰（TPM2 MakeCredential / ActivateCredential）確認 AK 與 EK 在同一顆 TPM 裡。挑戰要加密給 EK，秘密不能公開，所以無法在合約裡做，只能由小組成員各自執行。
   - 重播事件記錄，確認 PCR 值與 `ImageRegistry` 登記的映像一致，韌體版本不在黑名單上。
6. 機器 ID = `keccak256(EK 公鑰)`，公開（決定 4）。

**T2 的弱點**（租約頁面要寫清楚）：

- 實體攻擊便宜得多：冷開機攻擊、在記憶體或匯流排上擷取資料；AMD 韌體 TPM 已有電壓故障注入攻擊的公開研究（faulTPM，2023）。記憶體焊在封裝上（這幾款多半如此）會提高難度，但不能排除。
- 開機韌體由機器主人控制：如果 OEM 沒有啟用 Boot Guard / Platform Secure Boot，主人可以刷入會謊報量測值的韌體。驗證小組只接受有啟用的機器。
- 系統漏洞：`bolt-art` 若有可遠端利用的漏洞，執行者可以透過網路攻擊它。系統要極小化，只開放 Agent 需要的對外連線，不開任何對內服務。

## 3. 元件

| 元件 | 內容 | 形式 |
| --- | --- | --- |
| `TdxVerifier` | 驗證 TD quote：簽章鏈、TCB 等級、QE 身分、撤銷清單；回傳量測值與 REPORT_DATA | 一般合約 |
| `TeeCollateral` | Intel 的 TCB Info、QE Identity、CRL、中繼憑證；**任何人都能提交**，合約驗證 Intel 簽章，只接受更新的版本 | 一般合約 |
| `ImageRegistry` | Runtime 映像：映像 ID → 預期量測值（TDX 的 MRTD、RTMR0–2；SNP 的 MEASUREMENT；T2 的 PCR 組合）、原始碼 CID、建置說明。任何人都能登記，不審核（決定 7） | 一般合約 |
| `EnclaveLease` | 機器登記、報價、託管、啟用、檢查點、按小時結算、終止、搬家、押金與罰沒；把 SNP / TPM / GPU 證明交給驗證小組 | 系統合約（需要 epoch 掛勾），與 `ComputeMarket` 共用執行者身分與押金規則 |
| 驗證小組擴充 | 除了 `ComputeMarket` 的爭議，也驗證 SNP、TPM、GPU 證明；以 BLS 聚合的裁決憑證上鏈 | 節點與系統合約 |
| `SwarmStorage` | 付費保存檢查點（ADR 0014） | 系統合約 |
| Agent Runtime（`bolt-art`） | T1 用的機密 VM 映像與 T2 用的開機映像（x86-64 與 arm64）：可重現建置、唯讀根目錄、產生 enclave 金鑰、取得證明、解密狀態、執行 Agent、送檢查點 | 新目錄 `images/agent-runtime` |
| `boltchain enclave` | 執行者端：偵測 TDX / SNP / TPM、登記機器、公布報價、啟動與停止、轉送證明與檢查點 | `crates/node` 子命令 |
| `boltchain lease` | 租用者端：選報價、託管、本機驗證證明、交付金鑰、查看狀態、終止、搬家 | `crates/node` 子命令，另有 WASM 版 |
| Rust 證明驗證函式庫 | TDX、SNP、TPM（含事件記錄重播）；租用者端、驗證小組與測試共用 | 新 crate `bolt-attest` |

## 4. 租約流程

### 4.1 登記機器與報價

1. 執行者登記機器：等級（T1 / T2）、TEE 類型、CPU / 記憶體、每小時價格、網路頻寬。第一次登記時附上一份證明，合約或驗證小組取出機器 ID（TDX：PCK 憑證裡的 PPID；SNP：CHIP_ID；T2：EK 公鑰雜湊），**同一台機器只能屬於一個執行者**，押金也因此無法重複使用。機器 ID 公開。
2. 租用者選定報價，存入託管款（至少 N 小時），指定映像 ID、Agent 包的雜湊、最低等級與最低 TCB 等級、要求的最低押金。

### 4.2 啟動與證明

1. 執行者用指定映像啟動（T1：機密 VM；T2：重新開機進入 `bolt-art`）。
2. Runtime 在 TEE 內產生兩把金鑰：簽章金鑰 `S`（secp256k1，用於鏈上簽名）與加密金鑰 `E`（X25519，用於 HPKE）。私鑰從不離開 TEE。
3. Runtime 取得證明，綁定資料（TDX 的 REPORT_DATA、SNP 的 REPORT_DATA、TPM 的 qualifyingData）填入：

   `keccak256(chainId, EnclaveLease 地址, leaseId, S 的地址, E 的公鑰, nonce)`，其中 nonce = 租用後合約指定區塊的 blockhash

   這樣一份證明只能用在這份租約、這兩把金鑰，而且不能拿舊證明重播。
4. 任何人把證明送到 `EnclaveLease.activate`：
   - TDX：合約呼叫 `TdxVerifier`，檢查簽章鏈、TCB 等級、量測值與映像登記相符、TD 屬性（debug 位元必須為 0）、綁定資料相符，當場啟用。
   - SNP、T2：合約把證明排進待驗證清單，由當期驗證小組在鏈下驗證，以 BLS 聚合簽章回報；三分之二同意才啟用（決定 3）。
5. 啟用後，`S` 成為這份租約唯一的「現役 enclave」。

### 4.3 交付秘密

- 狀態金鑰、LLM API 金鑰等秘密一律用 HPKE 包給 `E`。`bolt-vault` 的 `add_recipient` 可以直接把既有的加密狀態加上新收件人，不必重新加密整份資料。
- 租用者端在包金鑰前**自己再驗證一次證明**（本機驗證，不只相信鏈上結果），並確認 `E` 就是綁定資料裡那把。

### 4.4 運行、檢查點與計費

- **每小時上鏈一次**（決定 5）：Runtime 送出由 `S` 簽名的檢查點 `(leaseId, 版本號, 狀態根 CID, 狀態根雜湊, 最近看到的 blockhash)`，任何人都能代送。
- 檢查點兼作「存活證明」：它證明 enclave 在那個區塊之後還在運行，並且狀態已經備份。**計費單位是 1 小時**，每個有效檢查點付一小時。
- **兩次上鏈之間**：Runtime 每 10 分鐘產生一份簽名的中間檢查點，透過 P2P 交給租用者與保管小組（第 5.4 節），不上鏈。
- 執行者沒有 BOLT 也能運作：檢查點與領款交易的手續費從託管款扣（和 `ComputeMarket` 的中繼模式相同）。

### 4.5 終止與搬家

- 租用者可以隨時終止，只付到最後一個有效檢查點為止。
- 執行者可以宣告退出，必須給予通知期（例如 24 小時），期間照常計費。
- 搬家：在新機器上啟動、完成證明後，新 enclave 的 `S′` 取代 `S` 成為現役；舊 enclave 的簽章從此無效。新 enclave 從最新檢查點取回狀態（優先用比鏈上更新、且由 `S` 簽名的中間檢查點）。
- 執行者失聯：連續 2 個檢查點（2 小時）缺席後，租用者可以單方面把租約轉到另一位執行者。

## 5. TEE 儲存問題

### 5.1 為什麼不能直接用硬體封存

| 問題 | 說明 |
| --- | --- |
| 記憶體會消失 | 機密 VM 關機或重啟後，記憶體內容全部消失 |
| 封存金鑰綁定晶片 | SGX 的封存金鑰、SNP 的衍生金鑰、TPM 的封存都綁定單一機器；TDX 沒有封存金鑰。執行者退出或機器故障，資料就永遠無法解密 |
| 回滾攻擊 | 執行者把 Agent 重啟，餵給它一份舊的（但真實、簽名正確的）狀態，例如讓它重複支付、忘記已撤銷的權限 |
| 分叉攻擊 | 執行者用同一份狀態同時開兩份 Agent，讓兩份做出互相矛盾的行為 |
| 磁碟內容 | 執行者可以任意讀取、修改、替換磁碟 |

### 5.2 三層設計

1. **工作磁碟（本機，隨租約消失）**
   - 每次啟動在 TEE 內產生隨機的磁碟金鑰，用 dm-crypt + dm-integrity 加密並驗證完整性；根目錄用 dm-verity 唯讀。
   - 執行者只看得到密文，改動會被偵測。重啟後磁碟金鑰消失，本機資料作廢，一律從檢查點恢復。
2. **狀態檢查點（持久，可搬家）**
   - Agent 的持久狀態（記憶、向量資料庫、檔案、設定）打包後用 `bolt-vault` 加密。
   - 內容金鑰包給租用者的加密公鑰與現役 enclave 的 `E`（第二期再加保管小組）。
   - 每小時的上鏈檢查點建立一筆 `SwarmStorage` 保存委託（ADR 0014），由多個保存者各存一份並接受抽查；中間檢查點只放在租用者、執行者與保管小組的節點上。
   - 保存委託以增量方式建立：兩次檢查點之間沒變的分塊 CID 不變，保存者不必重新下載。
3. **金鑰（不落地）**
   - 每個 Agent 有一把「狀態主金鑰」，只存在於 TEE 記憶體中，或以 HPKE 包好後存放。
   - 第一期由租用者保管並負責交付；第二期加入保管小組（第 5.4 節），讓 Agent 在租用者離線時也能自己搬家。

### 5.3 防回滾與防分叉

- **防回滾**：Runtime 啟動時從鏈上讀取最新的檢查點版本號與狀態根雜湊，只接受相同或更新（且由現役或前任 `S` 簽名、版本號連續）的狀態。讀取鏈上資料不能只信執行者提供的 RPC：Runtime 內建輕節點，以最終性證明驗證狀態。
- **每小時上鏈的代價**：執行者最多可以把 Agent 回滾到約一小時前（最近一次上鏈的檢查點）。對策：
  - Agent 在做有價值的動作之前（付款、簽約、發送重要訊息）先強制送一次上鏈檢查點，這次不受每小時的限制，手續費從託管款扣。
  - 鏈上動作本身有帳戶 nonce，重播的交易會失敗。
  - 租用者與保管小組持有 10 分鐘一份的中間檢查點；搬家時用最新的一份。
- **防分叉**：合約只承認現役 `S` 的檢查點；新 enclave 產生新的 `S′`，秘密只交給完成證明的那一份。
- **可證明的破壞，罰沒全部押金**（決定 8）：同一把 `S` 對同一個版本號簽了兩份不同的狀態根（上鏈或中間檢查點都算），只可能是 TEE 被攻破，因為正確的 Runtime 不會這樣做。任何人都能把兩份簽名送上鏈：
  - 執行者押金 100% 罰沒：一半給檢舉人，一半燒掉。
  - 這台機器的 ID 列入黑名單，不能再登記。
  - 執行者名下其他租約的租用者可以立即終止，不受通知期限制。

### 5.4 保管小組（第二期）

租用者不可能一直在線，Agent 需要能在執行者失聯時自動搬家。做法：

- 狀態主金鑰以 Shamir 秘密分享拆成 n 份，交給 n 個**在其他執行者機器上、已通過證明的保管 enclave**（t-of-n，例如 5-of-9）。保管 enclave 只接受 T1。
- 保管 enclave 只在「鏈上顯示新的 enclave 已成為這份租約的現役」時，才把自己那一份用 HPKE 包給新 enclave。
- 保管 enclave 分散在不同執行者、不同機器 ID 上，攻擊者要同時攻破 t 台機器才拿得到金鑰。

## 6. 證明驗證問題

### 6.1 TDX 的鏈上驗證步驟

1. 解析 quote（v4 / v5）：標頭、TD 報告本體、簽章資料。
2. 用 quote 內的證明金鑰（P-256）驗證「標頭 + 本體」的簽章：1 次 P256VERIFY。
3. 驗證 QE 報告由 PCK 金鑰簽名，且 QE 報告的 REPORT_DATA 等於 `SHA-256(證明金鑰 ‖ QE 驗證資料)`：1 次 P256VERIFY + SHA-256。
4. 驗證 PCK 憑證鏈到 Intel 根金鑰：葉憑證 + 中繼憑證各 1 次 P256VERIFY。中繼憑證驗證一次後快取；同一台機器的葉憑證也可以快取。
5. 從 PCK 憑證取出 FMSPC、CPUSVN、PCESVN、PPID，查 `TeeCollateral` 裡的 TCB Info 得到 TCB 等級，並確認 PCK 沒有被撤銷。
6. 查 QE Identity，確認 QE 的身分與版本。
7. 比對 TD 屬性（debug = 0）、MRTD、RTMR0–3 與 `ImageRegistry`，比對 REPORT_DATA。

估計成本：DER 與 quote 解析是主要開銷，快取命中時約數十萬 gas，冷啟動時可能到一兩百萬 gas，在 3,000 萬的區塊上限內。**需要實作後做基準測試**，也要納入 `bench` 的最壞區塊測試（ADR 0002 的樹莓派考量）。每份租約只在啟用與搬家時驗證一次。

### 6.2 附帶資料（collateral）的新鮮度與撤銷

- Intel 會發布新的 TCB 公告，把舊的韌體版本降級為「過期」，並更新 CRL。這些資料都由 Intel 簽名，**不需要信任提交的人**。`TeeCollateral` 允許任何人提交，只接受 `tcbEvaluationDataNumber` 較新的版本。
- 沒人提交新資料時，合約會繼續接受已過期的平台。對策：節點內建自動提交的工作；每份資料都有 `nextUpdate`，過期太久時拒絕新的啟用。
- 已啟用的租約：任何人都能呼叫 `recheck(leaseId)`；降級到租約要求以下時，租用者可以立即終止並搬家，執行者不被罰。
- SNP 的 VCEK 與 CRL、TPM 的 EK 憑證撤銷、韌體黑名單，由驗證小組在驗證時各自向廠商取得。

### 6.3 量測值政策

- TDX 的 MRTD 取決於 TDVF 韌體版本與 VM 設定；T2 的 PCR 取決於機器韌體版本。`ImageRegistry` 允許一個映像登記多組量測值，每組附上適用的硬體與韌體版本。
- Agent 本身不放進映像：映像只含 Runtime，Agent 包的雜湊寫入 RTMR3 / 獨立的 PCR（或綁定資料），租約指定允許的 Agent 包雜湊。
- **開放登記**（決定 7）：`ImageRegistry` 不審核，任何人都能登記映像。安全性來自可重現建置：任何人拿原始碼建置都必須得到相同的量測值。
  - 錢包與 CLI 顯示每個映像的原始碼 CID，以及「有幾位不同的登記者獨立重現了相同的量測值」。
  - CAFECA 維護的官方映像也只是登記表中的一筆，沒有特權。
  - 租用者要自己決定信任哪個映像；CLI 預設要求明確指定，不自動挑選。

### 6.4 驗證小組背書（SEV-SNP、T2、GPU）

- 驗證小組沿用 `ComputeMarket` 的機制，每個 epoch 從委員會抽選（挖礦階段從質押者抽）。
- 小組成員用 `bolt-attest` 在鏈下驗證，以 BLS 聚合簽章回報；三分之二同意才算通過。
- T2 的 AK 挑戰需要與執行者即時互動：小組成員透過 P2P 把加密給 EK 的挑戰送給執行者，Runtime 用 TPM 解開並回傳。
- 信任假設比鏈上驗證弱（依賴小組誠實）；租約標示驗證方式。之後可以改成零知識證明（在 zkVM 裡驗證，鏈上用 BN254 預編譯驗證 Groth16），不影響其他部分。

### 6.5 機器 ID 公開

決定 4：機器 ID 在鏈上公開（TDX：PPID；SNP：CHIP_ID；T2：EK 公鑰雜湊）。用途：一機一執行者、黑名單、信譽、統計各等級的機器數量。代價是機器的所有權關係公開，執行者登記前要知道這件事。

## 7. Agent 對外行動的安全

- **Agent 的鏈上帳戶**：租用者的帳戶透過 EIP-7702（Osaka 已支援）委派給一份「限權錢包」合約，或另開一個合約錢包。現役 enclave 的 `S` 只是它的會話金鑰：每日支出上限、可互動合約的白名單、單筆上限，租用者可以隨時撤銷；換 enclave 時，舊的會話金鑰自動失效（合約讀 `EnclaveLease` 的現役 `S`）。
- **LLM 呼叫外部 API**（決定 6）：
  - API 金鑰以 HPKE 只交給已證明的 enclave，建議用有額度上限、可撤銷的金鑰。
  - TLS 在 enclave 內終結，執行者看不到內容；但 **LLM 業者看得到提示與回應**，這是這個選擇的代價，要在文件中寫清楚。
  - Runtime 內建常見 LLM API 的根憑證並檢查主機名稱，防止執行者用假的 API 伺服器攔截。
  - 因為推論在外部，T2 裝置的 GPU / NPU 不需要被證明；之後要在本機推論時再加入 GPU 證明（第三期）。
- **對外連線**：執行者可以阻擋或延遲連線，但無法看到內容。Runtime 記錄連線失敗，讓租用者判斷是否搬家。

## 8. 付款與押金

| 情況 | 處理 |
| --- | --- |
| 正常運行 | 每個上鏈檢查點付一小時；和 `ComputeMarket` 一樣，收入先扣 20% 累積押金 |
| 執行者關機或斷網 | 沒有檢查點就沒有收入；連續 2 小時缺席時租用者可以搬家。**不罰沒**，因為無法在鏈上證明是誰的錯 |
| 租用者拒付 | 託管款是預付的，執行者依檢查點直接領款 |
| 同一版本雙簽 | **罰沒 100% 押金**（一半給檢舉人、一半燒掉），機器 ID 列入黑名單 |
| 平台被廠商撤銷或降級 | 租約可以立即終止，不罰沒（非執行者可控） |
| 接單上限 | 依押金、信譽與等級決定可同時承接的租約數與託管金額上限 |

租用者可以要求「押金 ≥ X」才願意租用。Agent 帳戶的支出上限應該小於執行者押金，這樣攻破 TEE 的預期收益低於損失。

## 9. Boltchain 需要補充的設計

| 項目 | 內容 | 是否需要硬分叉 | 優先度 |
| --- | --- | --- | --- |
| `SwarmStorage` | 付費保存使用者資料，並取代 `HistoryRegistry` 的抽查（ADR 0014） | 是 | 高（**已開始**） |
| `TdxVerifier` + `TeeCollateral` | Solidity 實作 DCAP 驗證，用 P256VERIFY | 否 | 高 |
| `ImageRegistry` | 映像量測值登記，開放登記 | 否 | 高 |
| `EnclaveLease` | 租約、檢查點、計費、搬家、罰沒 | 是 | 高 |
| 驗證小組擴充 | SNP / TPM / GPU 證明；裁決憑證（BLS 聚合），M7 本來就要做 | 是 | 高（T2 必須依賴它） |
| 保管小組 | TEE 間的 t-of-n 秘密分享與釋出 | 是 | 中（第二期） |
| 限權錢包合約 | EIP-7702 委派、會話金鑰、限額 | 否 | 高 |
| `bolt-art` 映像 | T1 機密 VM 與 T2 開機映像，x86-64 與 arm64，可重現建置 | — | 高 |
| `bolt-attest` | TDX / SNP / TPM 證明驗證 | — | 高 |
| `boltchain enclave` / `lease` | 執行者與租用者 CLI | — | 高 |
| 節點提交附帶資料 | 自動抓 Intel PCS 更新並提交 | — | 中 |
| ADR 0002 | **不需要修改**：P-256 驗證已是 Osaka 預編譯，其他證明由驗證小組處理 | — | — |

## 10. 分期

1. **第零期：實機確認**
   - 在 DGX Spark、一台 Intel Core Ultra（最好是 vPro）、一台 Ryzen AI（最好是 PRO）上確認：TPM 2.0 型號與 EK 憑證、Secure Boot 與量測開機、Boot Guard / Platform Secure Boot、記憶體加密、IOMMU。
   - 產出：每款裝置能否達到 T2 的清單。
2. **第一期：SwarmStorage、T2 與 TDX，租用者保管金鑰（測試網）**
   - `SwarmStorage`（ADR 0014）
   - 驗證小組裁決憑證，加上 T2 驗證（TPM）
   - `TdxVerifier`、`TeeCollateral`、`ImageRegistry`、`EnclaveLease`
   - `bolt-art` 最小映像（x86-64 與 arm64），範例 Agent 呼叫外部 LLM API
   - 限權錢包
   - 驗收：在 AI PC 上啟動 Agent 並寫入記憶；關機後在 DGX Spark 恢復，記憶一致；用舊檢查點重啟會被拒絕；同版本雙簽會罰沒全部押金
3. **第二期：可自動搬家**
   - 保管小組
   - SEV-SNP
4. **第三期：本機推論**
   - GPU 機密運算（資料中心 GPU）；T2 裝置的本機推論另行評估
   - `ComputeMarket` 的 TEE 等級工作改用同一套證明

## 實作紀錄：第一期軟體部分（2026-10-14）

範圍（專案負責人決定）：合約、`bolt-attest`、驗證小組的 TPM 背書、`enclave` / `lease` 命令列，以模擬的 TDX quote 與軟體 TPM 測試；實機確認與 `bolt-art` 映像不在這次範圍。新合約放進主網 genesis，公開測試網以硬分叉 `tee` 加入。操作說明見 [`docs/tee.md`](../tee.md)。

### 合約（系統合約，固定位址）

| 位址 | 合約 | 內容 |
| --- | --- | --- |
| `0xB017…0008` | `ImageRegistry` | 開放登記映像（名稱、原始碼 CID、建置方式），登記者加入量測值（TDX、SNP、TPM 各自的格式），其他人宣告重現；`allows(image, kind, m)` |
| `0xB017…0009` | `TeeCollateral` | Intel SGX Root CA 公鑰編譯在合約裡；任何人提交 CA 憑證、CRL（只接受較新的、撤銷只增不減）、TDX TCB Info v3（含 TDX 模組身分）與 TD_QE 身分（依評估編號與發布日期只接受較新的），合約驗證 Intel 簽章；`tdxStatus`、`qeStatus` 依 Intel 的演算法算出 TCB 等級。開發鏈的 genesis 可以換成模擬的根（`devTeeRoot`） |
| `0xB017…000A` | `TdxVerifier` | DCAP quote v4（ECDSA-256）：證明金鑰簽章、QE 報告綁定、PCK 憑證鏈與撤銷、QE 報告簽章、SGX 擴充欄位、TCB 與 QE 狀態、附帶資料新鮮度（`nextUpdate` 後 14 天寬限）、拒絕 debug TD。DER / X.509 / CRL / PEM / JSON 解析都在 `TeeLib.sol` |
| `0xB017…000B` | `EnclaveLease` | 機器登記（TDX 當場驗證；TPM 交給驗證小組）、報價、押金（解除綁定 14 天）、租約、啟用、檢查點、按小時付款、退出（24 小時通知）、搬家、重新檢查、雙簽罰沒、驗證小組的請求與結果 |
| `0xB017…000C` | `LimitedWallet` | EIP-7702 委派目標：命名空間儲存、每日與單筆上限、目標白名單、租約現役 enclave 金鑰可直接或以簽名（meta-tx）執行、帳戶本身不受限、隨時撤銷 |

**實作時的決定**

- 證明綁定：登記機器時 REPORT_DATA / qualifyingData 為 `machineBinding(執行者)`；啟用時 TDX 為 `enclaveBinding ‖ Agent 包雜湊`，TPM 為 `keccak256(enclaveBinding ‖ Agent 包雜湊)`（qualifyingData 只放 32 bytes）。nonce 在建立與搬家時由 `prevrandao` 產生（原本設計用指定區塊的 blockhash；`prevrandao` 立即可用，啟用前也無法預先算出）。
- 檢查點的簽名內容 `(chainId, EnclaveLease, 租約, 版本, 狀態根, CID 雜湊, 最近看到的 blockhash)`，`seenBlock` 必須在最近 256 塊內。每個檢查點與 TDX 啟用付租約的中繼費給代送者，所以 enclave 與執行者都不需要 BOLT。
- 雙簽：兩份簽名可以是任何曾經在這份租約上現役的金鑰（記錄 `signerLease` 與 `signerMachine`），罰的是當時那台機器的執行者；押金（含解除綁定中）全部罰沒，一半給檢舉人，一半鎖在合約（燒掉）。
- 搬家條件：租約等待中、已降級、執行者已宣告退出或被罰沒、機器列入黑名單，或 2 小時沒有檢查點。
- 驗證小組：待審請求每一塊都交給當期小組（每個 epoch 第一筆請求時抽出，之後沿用），不必等 epoch 開始；1 天沒有結果的請求任何人都能讓它過期，啟用退回等待狀態可以重試。證明包不上鏈，只記 sha256，由小組成員向機器登記的端點取得（TPM 挑戰本來就要與機器互動）。
- `ComputeMarket` 與 `EnclaveLease` 的押金分開記帳（規則相同：收入扣 20% 到 64 BOLT）。

**gas（開發鏈測試）**：登記 TDX 機器約 560 萬、TDX 啟用約 555 萬；提交 Intel 的 CA 約 33 萬、PCK 平台 CRL 約 281 萬、真實的 TDX TCB Info（6 個等級）約 1,484 萬、QE 身分約 122 萬。TCB Info 接近 EIP-7825 的單筆上限 16,777,216，Intel 的等級再增加就需要優化 JSON 解析（例如只解析需要的欄位、或改成提交預先解析的結構加上原文雜湊）。

### `bolt-attest`（`crates/attest`）

- `tdx`：與 `TdxVerifier` 相同的步驟與結果（測試比對兩者的機器 ID、TCB 與 QE 狀態、PCK 序號、量測值）；`intel::Collateral` 與 `TeeCollateral` 相同的接受規則與 TCB 等級演算法。真實的 Intel 附帶資料放在 `fixtures/intel`（2026-10-14 取自 Intel PCS），鏈上與鏈下都驗證通過。
- `tpm`：TPMS_ATTEST 與 TPMT_SIGNATURE、AK（ECC P-256，必須是 restricted、fixedTPM、fixedParent、sensitiveDataOrigin、sign）、TCG crypto-agile 事件記錄重播（含 StartupLocality）、EK 憑證鏈（RSA 或 ECDSA 簽章）、MakeCredential（RSA-OAEP 標籤 `IDENTITY`、KDFa、AES-128-CFB、HMAC）。目前只支援 RSA EK。
- `sim`：模擬的 Intel PKI（根 CA → PCK 平台 CA → 帶 SGX 擴充欄位的 PCK 憑證；TCB 簽章憑證；CRL；TCB Info 與 QE 身分 JSON），名稱都是「Boltchain Simulated」；可以產生任意 TD 報告的 quote。`tpm_sim`：RSA-2048 EK（由模擬廠商 CA 簽發）、P-256 AK、量測開機、quote、ActivateCredential。開發鏈的 genesis 信任 `SimIntel::dev()` 的根，開發鏈的驗證者信任 `SimTpmCa::dev()`。

### 節點與命令列

- 驗證小組：`AttestVote` / `AttestCert`（網域 `boltchain/attest/v1`，內容為 epoch、請求、是否通過、機器 ID），與抽查、裁決憑證共用區塊的 `audits` 清單；鏈驗證請求仍在等待、指派給該 epoch 的小組、超過三分之二後呼叫 `recordAttestation`。`--tpm-roots <目錄>` 提供 TPM 廠商根憑證，沒有就棄權。
- `boltchain image register|measure|reproduce|list`、`collateral update|show`（從 Intel PCS 抓取、讀目錄或提交模擬資料；鏈上已有或不夠新的文件會跳過）、`enclave register|offer|bond|activate|exit|machines|withdraw|runtime`、`lease offers|create|show|verify|deliver|terminate|migrate|top-up|recheck|wallet`。
- `enclave runtime --simulate --kind tdx|tpm`：模擬的 Agent 執行環境，提供登記與啟用用的證明、證明包與 TPM 挑戰端點、接收秘密（bolt-vault）、定時送檢查點（經中繼或錢包），狀態保存在 `--state`（模擬封存）。
- `lease verify` 在本機用 `bolt-attest` 驗證 quote，附帶資料直接向 Intel PCS 取得（不依賴鏈），並確認綁定、Agent 包、映像量測值與 TCB 要求。
- 瀏覽器「TEE 租用」頁：信任根與附帶資料狀態、機器、租約、映像；租約與機器詳細頁。

### 測試

- 合約（`crates/system/src/tee_tests.rs`）：真實 Intel 附帶資料上鏈、模擬 quote 鏈上鏈下結果一致、租約完整流程與按小時付款、回滾被拒、搬家、平台降級、雙簽罰沒與黑名單、T2 經驗證小組、限權錢包上限。
- `bolt-attest`：真實附帶資料、模擬 quote 的竄改與撤銷、TPM 證明的竄改、挑戰只能由正確的 TPM 解開。
- 端到端（`crates/node/tests/m8_tee.rs`，3 節點 7 位驗證者）：以命令列完成上述流程，含經中繼啟用與檢查點、驗證小組實際取證明與挑戰模擬 TPM、EIP-7702 委派。

### 尚未完成

- 第零期實機確認，以及 `bolt-art` 映像（TDX 機密 VM、T2 開機映像，x86-64 / arm64，可重現建置）。
- ECC EK；內建的 TPM 廠商根憑證清單；韌體黑名單。
- 節點自動提交 Intel 附帶資料（目前用 `collateral update`，可以排程執行）。
- SEV-SNP、保管小組、GPU 證明（第二、三期）。

