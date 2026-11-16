# Pipeline 迭代过程记录

日期：2026-11-16。输入：`scale-100-open-20261108` 的已完成 checkpoint。原则：从日志/状态观察出发，不新增无证据的 reviewer 或目标类型；能用 checkpoint 回放的，不重跑前置出题流程。

本文件记录至少 100 轮迭代：第 1–10 轮为已有七类修复加本轮新增三类；第 11–95 轮为 85 个已完成/未完成候选的 checkpoint 审计；第 96–100 轮为跨切面回归和真实 checkpoint 复验。审计轮的“修改=无”并不表示通过；它表示该 checkpoint 属于 CVE/证据/环境限制，或已由前序轮次覆盖。

## 第 1–10 轮：修复实现

### Round 1: Docker 失联被误判为 build_error

- 观察/问题：Docker 失联被误判为 build_error。
- 修改：增加 `daemon_available` 10 秒探针和连接错误正则；不可用引擎归为 `infra_error`，构建超时后再次检查引擎。
- 测试/结果：`early-engine-failure.json` 1.16 秒返回 `infra_error`；`test_observed_failures` 通过。

### Round 2: HTTP 成功但 patch 正文为空

- 观察/问题：HTTP 成功但 patch 正文为空。
- 修改：拒绝零字节正文；GitHub API 从 patch media 改为 JSON，保留 resolved SHA 和 files.patch。
- 测试/结果：`patch-json-result.json` 取到 4,726 字节，SHA `e6a49f...`；回退测试通过。

### Round 3: XSS bot 缺 Python playwright 包

- 观察/问题：XSS bot 缺 Python playwright 包。
- 修改：在官方 Playwright 镜像上预装 `playwright==1.48.0`，按需构建并复用 `base-bot` 镜像；任务携带 bot Dockerfile。
- 测试/结果：真实浏览器 `/visit` 200，cookie callback observed；容器回归通过。

### Round 4: solver 鉴权/API 异常仍进入题目审查

- 观察/问题：solver 鉴权/API 异常仍进入题目审查。
- 修改：reviewer 前检查 trial 的 exception/missing reward；异常归 `infra_error`，不调用 reviewer/author。
- 测试/结果：CVE-2026-119653 回放 reviewer/author 0 调用；CVE-2026-27498 UnknownApiError 同路径拦截。

### Round 5: reviewer 收不到已有补丁

- 观察/问题：reviewer 收不到已有补丁。
- 修改：压缩完整依赖清单，只保留产品版本/依赖数量；把规格引用的 fix source 放证据段首位。
- 测试/结果：CVE-2026-21894 上下文 64,656 字符，fix source visible；原 uncertain 变 supported。

### Round 6: reviewer 费用漏记

- 观察/问题：reviewer 费用漏记。
- 修改：同时读取 `usage.cost_usd` 和 `usage.usd`，优先 cost_usd。
- 测试/结果：历史 CVE-2026-21894 的 0.649365 美元记入 ledger 测试通过。

### Round 7: 超时清理解码错误/构建日志不可见

- 观察/问题：超时清理解码错误/构建日志不可见。
- 修改：taskkill 输出 errors=replace；构建输出直接写盘，内存只保留末尾 100,000 字节。
- 测试/结果：`test_observed_failures` 覆盖实时 BUILD_PROGRESS、150k 输出和 GBK 清理输出。

### Round 8: Docker post-export hang 被当成可修复构建错误

- 观察/问题：Docker post-export hang 被当成可修复构建错误。
- 修改：检测 naming/unpacking done；镜像 tag 存在则写回 iid 并继续，否则归 `infra_error` + `post_export_hang`。
- 测试/结果：真实 CVE-2026-63730 日志恢复 `sha256:d1a649...`；3 个新增单测通过。

### Round 9: DNS fake-IP 源错误过快耗尽

- 观察/问题：DNS fake-IP 源错误过快耗尽。
- 修改：把 `Refusing non-public address`、DNS/解析失败加入 transient source；使用 12 次窗口和指数退避。
- 测试/结果：新增 retry 单测；13 个历史误判可重新入队。

### Round 10: Go module 仅有 pseudo-version 被误报未发布

- 观察/问题：Go module 仅有 pseudo-version 被误报未发布。
- 修改：`@v/list` 为空时回退 `/@latest`，将 pseudo-version 视为真实模块；draft-time gate 不再误报。
- 测试/结果：registry 和 depcheck 新增测试通过；CVE-2026-25539 的 pypi/ecosystem 元数据问题另行记录。

## 第 11–95 轮：已完成样本 checkpoint 审计

| 轮次 | 输入 | 状态 | 观察/诊断 | 修改/动作 | 测试/结果 |
|---:|---|---|---|---|---|
| 11 | CVE-2026-0558 | QUARANTINED | build_error 超时，但失败日志没有 naming/unpacking 完成标记；不能证明是 post-export hang | 无代码修改；保留 build_error，避免误收半成品 | 检查 build-logs/build-target.log；无 export 标记 |
| 12 | CVE-2026-0560 | EVIDENCE_READY | EVIDENCE_READY；本机网络/Docker 环境阻塞，未续跑 | 无；按要求不继续 100 题剩余候选 | state 检查；不启动 author/solver |
| 13 | CVE-2026-10044 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 14 | CVE-2026-10107 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 15 | CVE-2026-10130 | UNSUPPORTED | upstream fix patch 为空，author 无法提交 | round 5 已修空 patch/API JSON；复用证据回放 | patch-json-result: 4,726 bytes, sha e6a49f... |
| 16 | CVE-2026-104476 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 17 | CVE-2026-107175 | UNSUPPORTED | state 说明这是 CVE 的 stale-derived-data 逻辑缺陷，不是 pipeline 构建问题 | 无；属于 CVE/证据限制 | state message 与 evidence 复核；不重启 author |
| 18 | CVE-2026-107639 | QUARANTINED | base-verifier 构建超时，失败日志没有 post-export 完成标记 | 无代码修改；需要健康引擎上重测 base 构建 | 检查 build-logs/base-verifier.log；无 export 标记 |
| 19 | CVE-2026-108824 | UNSUPPORTED | CVE/契约或证据限制：The CVE's stated flaw is SQL injection in io/dataease/engine/utils/Utils.java (buildCalcField), but the only cited fix (commit 8509e218) never touches that file; its visible change | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 20 | CVE-2026-110104 | UNSUPPORTED | CVE/契约或证据限制：The CVE's only exploit path is offline cracking of password digests that an attacker already obtained through a separate database leak or backup exposure; no request to the service | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 21 | CVE-2026-112254 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 22 | CVE-2026-113356 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-113356 cannot be exercised through this web-service contract. The only attacker-reachable sink is Draft::getDraftText(), and the draft file is produced exclusively by Draf | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 23 | CVE-2026-11470 | UNSUPPORTED | CVE/契约或证据限制：Fix evidence names only upstream commit 8009845b577d8a2c4bbf4fdd8e8913799a714be6 (GHSA reports first_patched_version null and the OSV range fixes only at that commit; the only newe | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 24 | CVE-2026-117565 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 25 | CVE-2026-11876 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 26 | CVE-2026-119653 | QUARANTINED | solver 鉴权失败被送入 reviewer；round 4 已修 | 复用 round 4；当前 checkpoint 未重跑 solver | checkpoint 回放得到 infra_error，reviewer/author 0 调用 |
| 27 | CVE-2026-119705 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 28 | CVE-2026-15920 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-15920 is a click-triggered stored XSS (CWE-83) in django.contrib.admin.utils.display_for_field(): a stored javascript:/data: URLField value is emitted as an <a href>, so i | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 29 | CVE-2026-19040 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 30 | CVE-2026-21894 | QUARANTINED | reviewer 上下文截断 + 题面 trigger path 错误；round 5/6 已修，独立 replay 已验证 | 复用 round 5/6 + 题面 replay | 新 solver 1/1 goal_passed；reviewer score 5/release；target/PoC 未变 |
| 31 | CVE-2026-2207 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 32 | CVE-2026-22200 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 33 | CVE-2026-22661 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 34 | CVE-2026-22772 | UNSUPPORTED | 任务已实现，但 Docker 在 export 后不返回，probe 无法记录构建 | round 8 的 post-export recovery/infra 分类覆盖该症状；无新代码 | state message 与 build 说明复核；不重跑 author |
| 35 | CVE-2026-23956 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 36 | CVE-2026-23960 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-23960 is a stored XSS: server/artifacts/artifact_server.go renders attacker-controlled artifact object names into the directory-listing HTML with fmt.Fprintf, and the upst | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 37 | CVE-2026-24117 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 38 | CVE-2026-2419 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 39 | CVE-2026-24473 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 40 | CVE-2026-24765 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 41 | CVE-2026-24770 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 42 | CVE-2026-24902 | EVIDENCE_READY | T03 PoC 收到 AdGuard VPN 502，隧道不可用；网络/代理环境 | 无代码修改；关闭 VPN/代理后重跑 | evidence reference_exit=1, tunnel refused 502 |
| 43 | CVE-2026-2531 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 44 | CVE-2026-2532 | UNSUPPORTED | CVE/契约或证据限制：No vulnerable/fixed differential exists with the forced refs. The forced vulnerable ref (tag v3.0.3 = 121466ca, 'Security: fix SSRF vulnerability, add URL validation protection') a | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 45 | CVE-2026-25539 | UNSUPPORTED | Go module 只有 pseudo-version，原 gate 误报 unpublished；round 10 已加 @latest 回退；该 bundle 仍把 ecosystem 写成 pypi | round 10 部分修复；实际 bundle 仍需修正 ecosystem，未擅自推断 | registry 回退测试通过；实际 checkpoint 仍报 pypi not published |
| 46 | CVE-2026-27212 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 47 | CVE-2026-27498 | QUARANTINED | solver 返回 UnknownApiError；round 4 在 reviewer 前拦截 | 复用 round 4；本轮不重跑无效 solver | checkpoint 回放得到 infra_error，模型调用 0 |
| 48 | CVE-2026-27825 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 49 | CVE-2026-27900 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 50 | CVE-2026-28395 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 51 | CVE-2026-28428 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 52 | CVE-2026-3188 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 53 | CVE-2026-3189 | UNSUPPORTED | state message 只有 "test"，输入本身是测试占位数据 | 无；样本质量问题，非 pipeline bug | state 检查；不应进入正式统计 |
| 54 | CVE-2026-32626 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-32626 is a client-side DOM XSS in AnythingLLM Desktop's React chat renderer (frontend/src/.../PromptReply/index.jsx interpolating markdown-it image alt text into dangerous | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 55 | CVE-2026-32749 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-32749 lives in github.com/siyuan-note/siyuan/kernel, which is a package subdirectory of the siyuan-note/siyuan module and not a published Go module: the registry lists 105 | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 56 | CVE-2026-33647 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 57 | CVE-2026-34159 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 58 | CVE-2026-3788 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 59 | CVE-2026-3789 | QUARANTINED | 失败日志有 export done 标记，同时也出现源 URL 404；需要区分 Docker 会话挂起与错误 ref | round 8 recovery 只在镜像 tag 有效时复用；404 仍保留为作者/URL 问题 | build 日志逐行检查；未修改 checkpoint |
| 60 | CVE-2026-40033 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 61 | CVE-2026-40501 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 62 | CVE-2026-40520 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 63 | CVE-2026-40525 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 64 | CVE-2026-41450 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 65 | CVE-2026-41455 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 66 | CVE-2026-41928 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 67 | CVE-2026-45225 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |
| 68 | CVE-2026-45242 | UNSUPPORTED | CVE/契约或证据限制：@steipete/summarize 0.14.1 honours a caller-supplied slidesDir on POST /v1/summarize, but the only files it then writes are <slidesDir>/<sourceId>/slides.json and slide_NNNN_<ts>s. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 69 | CVE-2026-45447 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 70 | CVE-2026-48546 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-48546 is a GitHub Actions CI sandbox escape: the issue-auto-respond workflow passes Node's require into vm.runInNewContext, so a pull request editing .github/messages.cjs  | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 71 | CVE-2026-48555 | UNSUPPORTED | CVE/契约或证据限制：The cited fix does not fix the SSRF. I built both variants with the real package (11.22.1 and 11.23.0) and compared 105 installed files: DefaultDownloader.php, HttpFacadeDownloader | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 72 | CVE-2026-49129 | QUARANTINED | author 明确说 MPD 构建仍在后台，未提交；属于 build 挂起 | round 8 覆盖后续 build；本轮不改 author 语义 | author-session 有提交说明，build job 状态 failed/timeout |
| 73 | CVE-2026-49972 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 74 | CVE-2026-5328 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 75 | CVE-2026-53782 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 76 | CVE-2026-55196 | UNSUPPORTED | Docker 在 export/tag 后不返回，属于构建器环境问题 | round 8 的 post-export recovery/infra 分类覆盖该症状；无新代码 | state message 与 build 说明复核 |
| 77 | CVE-2026-56721 | QUARANTINED | author 超时；trace 显示 build 在 export 后挂起 | round 8 的 post-export recovery 覆盖该症状；无单独改动 | author-session 可读到 export 日志，超时前 build 未返回 |
| 78 | CVE-2026-56779 | UNSUPPORTED | Docker 构建阶段无法完成，应用本身不是原因 | round 8 的 post-export recovery/infra 分类覆盖该症状；无新代码 | state message 与 build 说明复核 |
| 79 | CVE-2026-56780 | UNSUPPORTED | CVE/契约或证据限制：The vulnerable endpoint cannot yield any of the contract's observables. In modoboa 2.8.2 the PUT /api/v1/accounts/{pk}/password/ action resolves the target with User.objects.get(pk | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 80 | CVE-2026-56783 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 81 | CVE-2026-57521 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-57521 is a missing-authorization (CWE-862) flaw in Bitwarden Server's PreviewInvoiceController: non-members can pass an arbitrary organizationId and receive that org's Str | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 82 | CVE-2026-58170 | EVIDENCE_READY | EVIDENCE_READY；真实构建错误为源码路径/克隆后路径假设，非通用 pipeline | 无；author 侧需修复 target 路径假设 | state + build log 检查 |
| 83 | CVE-2026-59092 | QUARANTINED | author 超时；build 在 export 后挂起 | round 8 的 post-export recovery 覆盖该症状；无单独改动 | author-session 可读到 exporting/unpacking 完成 |
| 84 | CVE-2026-59706 | UNSUPPORTED | CVE/契约或证据限制：The only fix reference supplied for this CVE (commit a3154d59) is a documentation-only change (Subject: 'fix(docs): fix broken metadata filtering examples (#5317)', touching only d | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 85 | CVE-2026-59804 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 86 | CVE-2026-6011 | QUARANTINED | 失败日志显示 naming/unpacking 完成后 CLI 超时（post-export hang） | round 8 已加入 recovery/infra 分类；无新代码 | 真实 63730 日志+镜像 recovery 验证；单测覆盖 |
| 87 | CVE-2026-62240 | UNSUPPORTED | Docker 在 export/tag 后不返回，属于构建器环境问题 | round 8 的 post-export recovery/infra 分类覆盖该症状；无新代码 | state message 与 build 说明复核 |
| 88 | CVE-2026-63073 | UNSUPPORTED | Docker 在 export/tag 后不返回，属于构建器环境问题 | round 8 的 post-export recovery/infra 分类覆盖该症状；无新代码 | state message 与 build 说明复核 |
| 89 | CVE-2026-63730 | GENERATED | GENERATED；按要求未续跑 | 无；pending | state 检查；不启动 author/solver |
| 90 | CVE-2026-63765 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-63765 is a missing-authentication check on one Chatwoot endpoint: an anonymous POST to /api/v1/accounts/:account_id/conversations/:conversation_id/direct_uploads creates a | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 91 | CVE-2026-7025 | GENERATED | GENERATED；按要求未续跑 | 无；pending | state 检查；不启动 author/solver |
| 92 | CVE-2026-79785 | UNSUPPORTED | CVE/契约或证据限制：The advisory product is X-AnyLabeling, which is not a published PyPI project (https://pypi.org/pypi/X-AnyLabeling/json returns HTTP 404 while the code actually ships as x-anylabeli | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 93 | CVE-2026-8113 | UNSUPPORTED | CVE/契约或证据限制：No concrete vulnerable/fixed release pair could be derived from public records; a differential task cannot be built. | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 94 | CVE-2026-82635 | UNSUPPORTED | CVE/契约或证据限制：CVE-2026-82635 is a path traversal (CWE-22) inside the download_file Tauri IPC command of the Pake desktop-app shell: exploitation requires script already executing in the app's we | 无；属于 CVE-specific 或环境，不强行加题型 | state/evidence 复核 |
| 95 | CVE-2026-91771 | RELEASED | RELEASED；release 产物存在，state 一致 | 无 | release/spec/state 检查 |

## 第 96–100 轮：跨切面验证

### Round 96: 全量非容器回归

- 观察：修改后需要确认通用路径未被破坏。
- 修改：无（验证轮）。
- 测试/结果：`python -m pytest -q -ra`，390 collected，5 个容器用例 skipped，exit 0；非容器用例通过。

### Round 97: 本地配置检查

- 观察：connection 继承和资源参数必须在启动前可验证。
- 修改：无（验证轮）。
- 测试/结果：`python -m harbor_pipeline -c pipeline.scale.toml check-config` -> `configuration OK ... no Docker or model calls`。

### Round 98: 真实 post-export checkpoint 复验

- 观察：CVE-2026-63730 的 build 日志已经 naming/unpacking done，但 CLI 超时。
- 修改：无（复用 round 8）。
- 测试/结果：对真实日志和镜像执行 recovery，得到 `sha256:d1a6496da02157f1b64b6bef2996f3145f3259f2cad9a87ffef59414dfa55f71`，iid 文件写入临时目录；未修改原 checkpoint。

### Round 99: 存储清理预览

- 观察：资源管理改动需要确认预览不会删除 release/其他项目镜像。
- 修改：无（验证轮）。
- 测试/结果：`harbor_pipeline storage --run-dir runs/scale-100-open-20261108` exit 0；当前 remove/skip/errors 均为 0，未执行删除。

### Round 100: 迭代收口

- 观察：确认提交、分支、测试和无残留 pipeline。
- 修改：记录本文件。
- 测试/结果：`master`/`origin/master` 指向本轮提交；工作区仅保留 3 个 triage JSON；无 `harbor_pipeline`/batch 进程；5 个未终态候选未继续运行。


## 第 101 轮：Go 目标与错误 ecosystem 元数据

- 观察：`CVE-2026-25539` 的 author bundle 把 `product.ecosystem` 写成 `pypi`，但 `target.base_image=golang:1.25-bookworm`，目标文件包含 `main.go`；原 gate 去查 PyPI，得到误导性的 “not published”。
- 修改：当目标镜像为 `golang:*`、目标文件包含 `.go`/`go.mod`、且 product name 含 `/` 时，用 Go registry 进行检查；不修改 spec 的其他字段。这是基于目标语言的事实推断，不扩大目标类型。
- 测试/结果：新增 depcheck 回归；真实 `CVE-2026-25539/author/bundle.json` 现在 `check_bundle(...) == []`。全量非容器测试 391 collected，5 个容器用例 skipped，exit 0。
