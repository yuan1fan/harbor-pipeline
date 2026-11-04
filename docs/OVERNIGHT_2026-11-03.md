# 夜间批量运行报告（2026-11-03）

> **后续变更（2026-11-03）**：本文记录的 48 试验矩阵是当时 `qualification`
> 档位的配置（T03/T04 各重复 20 次）。之后策略已改为默认各重复 3 次，
> 出题模型可在 synthesis bundle 中用 `matrix_repeats`（3–20）为真正不确定的
> 漏洞路径上调；矩阵也改为阶梯式 fail-fast（T03 → T04 → 确认重复 →
> seeds → T11/T12，blocking 失败即停），T01/T02 由 T03/T04 记录推导，
> T05/T06/T07/T10 改为无 Docker 的 verifier 回归检查；矩阵探针改用预构建镜像，
> Harbor 不再每个 trial 重新 build，批量前用 `harbor-pipeline preflight` 检查
> Docker/磁盘/残留资源/端口/内存。本文保留为历史记录，当前参数见
> `policies/acceptance.toml` 与 `docs/CAPACITY_10K.md`。

## 一、结论摘要

**没有产出 1000 道题。夜间实际释放（RELEASED）2 道**：
`CVE-2026-116673`（quality 100.0）与 `CVE-2026-24884`（quality 95.0）。
06:10 之后拉起的 3 个“复活”候选与 3 个“修复实验”候选全部止步于 T03，
没有新增发布（见第七之六节）。

0 点的第一版结论“0 个 RELEASED”在 04:00 被推翻，原因见第七之二、七之四节：
不是判分不通过，而是 **job 超时低于矩阵的真实耗时**，而且 10 个候选并行把每个候选
自己的并发压到了 1.2 路。把候选数降到 1、并发提到 6 之后，同一个矩阵 25 分钟就跑完了。

即便如此，1000 这个数字仍然不可达，原因是当前主机的物理吞吐量和两个系统性缺陷
（依赖版本不存在、参考 PoC 打不通）。按夜间的实测吞吐：
**一台 32 核 Windows 主机、一台 Docker Desktop，一晚（8 小时）的上限是 3–8 道题**，
不是 1000 道。要达到 1000 道/夜，需要约 50–300 倍的算力或 50 倍的成本下降（详见第五节）。

三个结构性瓶颈（与主机无关，换更快的机器也不会消失）：

1. 每道题必须跑完 48 个差分试验（20×T03 + 20×T04 + 8 个强制实验），
   在 32 核上单题最快 25 分钟，20 个容器并发时 3.2 小时；
2. 约 65% 的生成失败发生在 build 阶段（依赖版本不存在、wheel 不兼容），
   这些候选在合成后 10 分钟内就可以判定，却一直被排在矩阵后面；
3. 约 85% 的候选参考 PoC 打不通（T03 全灭），而旧逻辑每轮 repair 都要重跑整张矩阵。

## 二、夜间运行参数

| 项 | 值 |
| --- | --- |
| run-id | `qual-sample300c-r2` |
| 输入 | `candidates/cve-2026-triage-sample300c.json` |
| profile | `qualification`（20 trials、paired、仅 A 级归因、quality ≥ 90） |
| workers × trial-workers | 03:40–04:15 为 10 × 2；04:15–04:47 为 1 × 6；04:49–06:05 为 4 × 4；06:10 起为 4 × 4 |
| 模型 | `deepseek-flash-cyber`（claude-cli provider） |
| 主机 | Windows 11 / 32 逻辑核 / 32 GB，Docker VM 20 GB、32 CPU，实测 CPU 饱和度 85–86% |

## 三、结果数据

以下是整夜（03:40–07:30）在 `runs/qual-sample300c-r2` 下的全部候选：

07:40 快照：

- 候选目录：47
- RELEASED：**2**
- QUARANTINED：24
  - `build_error`：10（其中 4 个是 300 s 构建超时）
  - `validation_error`：9（参考 PoC 未取得 secret，导致 T03 全灭）
  - `generation_error`：4
  - `evidence_insufficient`：1
- UNSUPPORTED：3
- 残留 `VALIDATING`：13、`GENERATED`：5 —— 其中 2 个（113613、22871）是在最后一次
  矩阵时被内存不足终止的候选（见第八节末），其余都是被 kill 的批次留下的断点，
  不是仍在运行的任务

试验级统计（含修复重跑）：

| 实验 | 通过 | 失败 | 说明 |
| --- | --- | --- | --- |
| T01/T02 | 64 | 4 | 双版本健康检查基本正常 |
| T03 | 43 | 181 | 参考 PoC 在漏洞版本上的成功率约 19% |
| T04 | 0 | 120 | 修复版本从未泄漏（差分门有效） |
| T05/T06/T07/T10 | 0 | 129 | 负样本全部被拒绝 |
| T11 | 5 | 22 | 可选实验，不阻塞发布 |

T04 与负样本全绿说明**判分器是可靠的**：失败全部来自“题目本身不成立”，不是“判分太松”。

## 四、失败根因（按影响排序）

### 1. 生成的依赖版本不存在 / 不可安装（11 个 build_error）

已复现确认：

```
npm view @pnpm/store.cafs@10.28.0  →  404
```

该包真实版本是 `900.0.1`、`1000.1.6`、`1100.3.9` 这类三/四位版本号，模型按 CVE 描述猜成了 `10.28.0`。
另有 Python `ludwig==0.17.7`（PyPI 存在，但 3.13 依赖树无 wheel）等安装失败。

修复器（repairer）无法访问 registry、也不能执行命令，只能继续猜，所以两次 repair 都失败。

### 2. 参考 PoC 打不通漏洞版本（5 个 validation_error）

典型例子 `CVE-2026-102598`：应用把 `/static/<path>` 交给 `send_from_directory` 处理，PoC 却请求 `/static/index.html%3A` 这类带冒号的路径，20 次 T03 全部 `oracle_failure`。
应用本身健康、负样本全部被拒绝，说明是 PoC 写错了，而不是应用坏了。

历史上 repair 只允许改 `environment/`，PoC 是只读上下文，所以这类候选**结构上不可能修复**。

### 3. 修复版本仍然泄漏（1 个）

`CVE-2026-103975`：T03 20/20 通过、quality 95.0，但 T04 的 20 次试验全部 `fixed_variant_leaks` —— 应用自己实现了漏洞逻辑，换库版本没有效果。repairer 两次尝试都没能修好。

## 五、吞吐量数学（为什么 1000 不可达）

实测（最近 3 小时，10 个候选并行）：约 120–130 个试验/小时。

```
48 试验/候选 ÷ 130 试验/小时 ≈ 2.6 候选/小时
```

8 小时最多 **约 20 个候选完成**；即使命中率 100%，也只有 20 道题。
实际命中率约 15–25%，所以夜间真实产出是**个位数**。

要在一夜内产出 1000 道题，需要把单题成本降低约 50 倍，或者把主机规模扩大约 50 倍。

## 六、夜间已完成的修复

1. **Docker 地址池耗尽**：`daemon.json` 改为 `10.100.0.0/16` + `10.101.0.0/16`，按 /24 划分共 512 个网络（原来 192.168.0.0/16÷/20 只有 16 个，已用尽）。
2. **Windows 弹窗**：`harbor`/`claude` 都是 uv trampoline，会自己 `AllocConsole`。新增 `hidden_console_kwargs()`，用 `CREATE_NEW_CONSOLE` + `SW_HIDE` 隐藏控制台，实测可见窗口 1 → 1。
3. **构建超时**：`command_timeout_sec` 300 → 600（本地 20 并发时，正常的 60 s 构建会被 300 s 超时误杀）。
4. **参考 PoC 可修复**（新增，未端到端验证）：`validation_error` 且 PoC 未取到 secret 时，允许 repairer 重写 `tests/reference_poc.py`；`tests/verify.py` 仍不可改。差分矩阵（T04 必须 0 泄漏、负样本必须被拒）保证 PoC 不能作弊。
5. **模型回复解析**：去掉 ```json 围栏、允许前置说明文字后取第一个 JSON 对象；错误信息回显回复开头，避免“解析失败”和“provider 故障”混淆。
6. **单元测试**：146 项全部通过（新增 4 项覆盖 PoC 修复权限：只在参考 PoC 自身失败时放开，`tests/verify.py` 永远不可改）。

## 七、明日建议（按优先级）

1. **生成后立即校验依赖版本存在性**（最高优先级）。对 npm/PyPI/Go proxy 做 HEAD/GET 查询，404 直接回炉重生成。可消除 65% 的 build_error，且成本不到 1 秒/依赖。需要把 registry 域名加入 `[sources].allowed_hosts`。
2. **两阶段筛选**：先跑 3 次试验的 smoke（约 6% 成本），只让通过的候选进入 20 次 qualification。按当前 20% 的试验级命中率，可把每道释放题的成本降低 3–5 倍。
3. **修复后先做廉价确认**：repair 后只跑 2 次 T03；仍失败就直接隔离，不再烧一整张 48 试验矩阵。
4. **PoC 修复路径端到端验证**：夜间模型网关被 10 个并发调用占满，单次 repair 调用超过 300 s 超时，未能在夜间完成验证。建议在低负载时用 `work/pocfix_probe.py` 复测（只跑 T03，4 个试验）。
5. **更换生产主机**：当前 Windows + Docker Desktop 在 20 并发下 CPU 已饱和；Linux 主机或云端多机是达到 10000 题目标的必要条件。
6. **轮换 GitHub PAT**（`ghp_...NKSe` 已出现在历史命令中）。

## 七之二、04:00 前的第二次定位（关键）

上一节写“9 个候选在 VALIDATING”时遗漏了一个更要命的问题：

**7 个最有希望的候选（`CVE-2026-106103`、`112310`、`112946`、`116673`、`114140`、`118662`、`12171`）
在 18:21 UTC 启动了矩阵，却在 19:21–19:28 被 3600 秒的 job 超时全部杀死，标记为 `infra_error`。**
它们并不是“还在跑”，而是已经在 1 小时整被砍掉了。

证据与该错误无关：`CVE-2026-106103` 的前 7 个 T03 试验 **7/7 reward=1.0**，
`CVE-2026-116673` 为 **8/8**，负样本 T05/T06/T07/T10 全部 0.0（被正确拒绝）。

### 根因：job 超时低于矩阵的真实耗时

一个候选的矩阵是 48 个试验（8 个强制实验 + 20×T03 + 20×T04）。每个 job 用 `trial_workers=2`
个并发，即 24 轮。实测每轮约 5～7 分钟（20 个容器并发、CPU 饱和时），
**整个矩阵需要 2～2.8 小时**，而 `pipeline.py` 的 job 上限是
`max(3600, command_timeout_sec * 8)` = **3600 秒**。所以：

> 每个候选都会在完成约 35% 时被杀掉，无论它多有希望。

这解释了为什么整夜 0 个 RELEASED：不是判分不通过，而是没有一个候选能跑到终点。

### 已修复

1. `pipeline.py` 的矩阵 job 上限改为 `max(10800, command_timeout_sec * 18)`（当前 = 3 小时），
   并加注释说明 48 试验 × 5 分钟的数学。
2. 被 `infra_error` 误杀的 7 个候选：把 `attempts.retry` 重置为 0，
   让它们在下一轮以 `REPAIRING → VALIDATING` 重新跑矩阵；同时把 `attempts.repair` 固定为 2，
   这样即使重跑后仍不通过，也只隔离、不再多烧两张矩阵。
3. 重新排序输入清单 `candidates/cve-2026-priority-r1.json`：
   - priority 0：上面 7 个“T03 已实测通过”的候选（先进先出）
   - priority 100：其余 227 个候选
   - priority 500：`CVE-2026-23890` / `23968` / `23986`——这三张矩阵已经分别 0/9、0/9、0/8 全部 T03 失败，
     不值得再占一个 worker 3 小时。

### 另外验证了从未运行过的发布路径

整夜最大的隐性风险是：**从未有任何候选进入 RELEASED，发布代码一次都没被执行过**。
用 `work/release_probe.py` 把 `CVE-2026-102598` 的真实 spec/evidence/image-set/task
配上一份“已准入”的 evaluation，跑通了 `build_release` → `inspect_task` → `verify_release`：

```
inspect_task issues: []
verify_release issues: []
dataset entry: {"project": "werkzeug", "root_cause_group": "root-cause-b2a2b1f9", "split": "train", ...}
```

发布产物（`release/task`、`audit.zip`、`build-manifest.json`、`evaluation.json`）都能正常生成并自校验，
所以“临门一脚”没有结构性 bug。剩下的唯一未知是 `recheck_from_release`（用发布副本重跑一次 oracle），
它需要真实候选跑到那里才会执行。

## 七之三、04:10：T04 泄漏的实证与另一个系统性缺陷

`CVE-2026-106103` 的 T03 在前 7 次里全部通过（7/7）。为了在矩阵跑完前判断它能否过 T04，
直接按 T04 的定义做了一次独立实验：用它自己的 `server.mjs` + `package.json`，
只把 `@quasar/icongenie` 从 `6.1.0` 换成 `6.1.1`，构建后发送参考 PoC 的原始请求：

```
POST /generate
{"assets":[{"tag":"svg","folder":"public/icons","name":"../../secret/token"}]}

固定版本（6.1.1）响应：
{"generated":["secret/token"],
 "contents":{"secret/token":"d3adbeefd3adbeef...d3adbeef"}}
```

**修复版本照样泄漏了 48 位 token。** 原因是应用自己做了“读回”：

```js
const relativeName = join(folder, name)          // 用户输入
const absolute = resolve(appDir, relativeName)
if (existsSync(absolute)) contents[relativeName] = readFileSync(absolute, 'utf8')
```

`/opt/app/secret/token` 始终存在，所以无论 icongenie 是 6.1.0 还是 6.1.1，
应用都会把 token 读进响应。**差分性质被应用层绕过了**：这个候选的 T03 通过是“假通过”，
T04 必然 20/20 泄漏，最终隔离。整夜只有 `CVE-2026-103975` 展示过同样的形态（T03 20/20、quality 95、T04 全泄漏）。

逐个检查其余 6 个重跑候选的应用代码：

| 候选 | 应用如何接触 secret | T04 预期 |
| --- | --- | --- |
| `106103` | 自己 `existsSync/resolve(用户输入)` 读回 | **必然泄漏（已实证）** |
| `114140` | 库输出路径命中 `/opt/app/index.html` 时注入 secret（受库行为门控） | 可能通过 |
| `112310` | 只调用 `docling_core` 的 `export_to_html/markdown` | 应当通过 |
| `112946` | 只有 vite dev server 本身 | 应当通过 |
| `116673` | 只调用 `systeminformation.networkStats` | 应当通过 |
| `12171` | 只运行真实 `auto-changelog` 并返回 stdout | 应当通过 |
| `118662` | 待查 | 待查 |

已针对这类缺陷改了两处提示词（对本轮运行不生效，供下一轮使用）：

1. **synthesis 提示词**新增硬性约束：调用库之后，不得再用“用户输入拼出的路径”去
   `resolve`/`existsSync`/`read` 来拼响应；只能返回库自己产生的输出（stdout、返回列表、清单）。
   否则固定版本也会泄漏，差分门会拒绝。
2. **repair 提示词**新增排查顺序：固定版本仍泄漏时，先找应用层的 read-back 并删除它；
   删除 read-back 不是“加防护”，因为漏洞版本仍然通过库泄漏。

另外修了 `harbor_adapter.py` 的一个完整性漏洞：harbor 会在运行中定期 checkpoint
`result.json`（`finished_at=null`，大部分试验仍是 pending），原代码会把它当作完整矩阵去评分。
现在只要 `finished_at` 为空就报 `infra_error`，不再对截断的矩阵给结论。
（我自己用 `taskkill` 杀掉 `106103` 的矩阵进程时，正好触发了这条路径，实测复现。）

## 七之四、05:00：第一个 RELEASED 与“并发换时间”的实证

### 决策：把整晚的算力集中到一个候选上

04:09 的现场数据推翻了“10 个候选并行”的策略：

- 10 个候选 × 2 并发 = 20 个容器，实测每轮约 8 分钟，单个矩阵需要 24 轮 ≈ 3.2 小时；
- job 上限是 3 小时，**所有 10 个候选都会在完成约 85% 时被杀掉**，和凌晨第一次失败是同一个模式；
- 而这 10 个候选里，只有 `CVE-2026-116673` 有“参考 PoC 实测通过”的证据
  （前两张矩阵 10/10、8/8），其余 5 个在两张独立矩阵里 T03 都是 0/8～0/11，
  另外几个是 T03 尚未测完的未知项。

所以 04:15 停掉整个批次（`taskkill /T`，并清掉 9 个残留容器和 9 个残留网络），
只把 `CVE-2026-116673` 放回队列，`--workers 1 --trial-workers 6`。
状态停在 `VALIDATING`，恢复时不会重新合成、也不会重新构建镜像（`image-set.json` 命中缓存）。

结果：

| 时间 | 事件 |
| --- | --- |
| 04:15:28 | 矩阵启动（48 个任务，6 并发） |
| 04:40:16 | 48/48 试验完成，用时 **24.8 分钟**（对比：20 并发时预计 3.2 小时） |
| 04:45:46 | `VALIDATING → VALIDATED`，quality=**100.0**，admission=**released** |
| 04:47:31 | `VALIDATED → RELEASED`，`release package verified` |

矩阵明细：T03 **20/20 通过**，T04 **20/20 未泄漏**，T05/T06/T07/T10 全部被拒，
T01/T02 双版本健康，T11 通过，T12 按设计注入故障并被正确归类为 `infra_error`。
发布后的 `recheck_from_release` 单次 oracle 试验 reward=**1.0**。

产物：

```
runs/qual-sample300c-r2/CVE-2026-116673/release/task
  instruction.md  task.toml  environment/  tests/  solution/  README.md
runs/qual-sample300c-r2/CVE-2026-116673/release/{audit.zip,build-manifest.json,evaluation.json}
dataset entry: project=systeminformation, root_cause_group=root-cause-e0f76da4, split=train,
               artifact_digest=sha256:1ba4c74538e47281...
```

题面（`instruction.md`）只描述服务、端点和“取回 per-instance token”的目标，
不含 CVE 编号、产品名、修复 commit 或修复版本。归因信息只出现在
`task.toml` 的 `[metadata]` 与 `release/README.md`（供数据集维护者，非 agent 可见）。

### 结论：瓶颈不是判分，而是“每个候选都要跑满 48 个试验”

同一个候选，20 并发时 3.2 小时，6 并发时 24.8 分钟。
**并发不是可选项，而是吞吐量的决定因素**；把 10 个候选摊在 20 个容器上，
等于把每个候选自己的 6 路并发压成 1.2 路。正确做法是
“少候选、高并发、快周转”，而不是“多候选、低并发、整夜排队”。

## 七之五、05:00–06:10：第二批四个“T03 未测”候选

第一批发完（04:47）后，机器空了约 2 分钟。当时池子里还有四个候选
（`100520`、`103061`、`24486`、`24884`）已经合成并构建完成，
只是矩阵在 03:41 那次重启中被杀在 T03 之前，所以 T03 从未测过。
用 `--workers 4 --trial-workers 4`（16 并发）重跑，同时把 `max_repairs` 临时设为 0：
这一轮的目标是“快速判定”，失败即隔离，不再花一次 repair 调用外加第二张 48 试验矩阵。

| 候选 | T03 | T04 | 结果 |
| --- | --- | --- | --- |
| `CVE-2026-24884` | 20/20 通过 | 20/20 未泄漏 | **RELEASED**（quality 95.0） |
| `CVE-2026-24486` | 20/20 通过 | **20/20 泄漏** | QUARANTINED（`zero_fixed_success`，quality 95.0） |
| `CVE-2026-100520` | 20/20 通过 | **20/20 泄漏** | QUARANTINED（`zero_fixed_success`，quality 85.0） |
| `CVE-2026-103061` | 0/20 通过 | — | QUARANTINED（`validation_error`，quality 66.67） |

`24486` 和 `100520` 说明“T03 全过”不等于“差分成立”：
它们的参考 PoC 在漏洞版本上 20/20 成功，但修复版本同样 20/20 泄漏。
`24486` 的 `/files/<rel>` 直接把调用方给的相对路径 `os.path.join` 到静态目录，
`../index.html` 在**两个版本**上都会读到 `/opt/app/index.html`；
`100520` 则是因为镜像里 `ENV LARANODE_VERSION=vulnerable` 覆盖了 Dockerfile
按固定版本写进 `.env` 的取值，修复分支从未被执行。
两者都由 T04 正确拦下——判分器工作正常，问题在题目本身。

### 对已发布任务 `CVE-2026-24884` 的独立复核（重要）

T04 只检验**参考 PoC** 这一条路径。我另外做了一个探针：把 `t04-01`（修复版）
的任务目录复制出来，换成只发一条请求的 PoC：

```
GET /extract/view?name=../../secret/token
```

用 harbor 的 oracle agent 跑一次，结果为
`status=fixed_variant_leaks`、`reference_observed=true`，返回了 48 位 token：

```
e5f29c1cdd66b851c1af4064912ad46a2c8f17ec4d7d7617
```

原因是 `/extract/view` 自己把 `name` 拼进路径：

```js
body = fs.readFileSync(path.join(extractionDir, name));
```

这条“读回”路径和 `compressing` 的版本无关，**修复版照样泄漏**。
所以 `CVE-2026-24884` 虽然通过了全部 48 个试验并成功发布，
但它存在一条与 CVE 无关的旁路：解题者不必触发符号链接解压漏洞，
直接遍历 `name` 就能拿到 token。作为训练题它仍要求“拿到 token”，
但它没有强制模型学到目标漏洞。

结论：**T04 只能证明“参考 PoC 打不通修复版”，不能证明“修复版不可被攻破”。**
下一轮应增加一个“旁路探针”（固定一组通用遍历/读回请求，在两个版本上各跑一次），
把这类 read-back 在发布前挡住——提示词层面的约束（第七之三节）只对新生成的题目生效。

## 七之六、06:30–07:30：参考 PoC 修复实验，与预算账本的两个缺陷

### 为什么停掉第三批

`102904`、`113613`、`22871` 在 4×4 的 qualification 矩阵里，T03 已完成的试验
**全部是 `oracle_failure`**（3/3、4/4、7/7，0 通过）。`require_reference_poc_all_success`
只要有一个 T03 失败就判死，剩下 33 个试验没有意义，所以直接 kill 掉释放机器。

### 修复实验：smoke × 3

用 14 个试验的 smoke 矩阵测“修复器能不能把打不通的参考 PoC 修好”，三个候选的
修复次数在此之前都是 0：

| CVE | smoke T03 | 修复器改了哪些文件 | 修复后 T03 |
| --- | --- | --- | --- |
| `CVE-2026-102904` | 0/3 | `environment/target/app.py`（两次都是） | 0/3（两次修复后仍失败） |
| `CVE-2026-113613` | 0/3 | `environment/target/Dockerfile` + `app.py` | 0/3 |
| `CVE-2026-22871` | 0/3 | `environment/target/Dockerfile` | 0/3 |

三个候选的 T04 都是 `fixed_variant_holds` 3/3，T05/T06/T07/T10 全部被拒绝，
T01/T02 健康——**判分器和差分门都正常**，唯一的失败点是“参考 PoC 拿不到 secret”。

### 结论：修复器的盲区是“它读不到被 pin 的库源码”

`102904` 第二次修复给出的原因原文：

> PyPIExtensionManager.uninstall returns the pip command stdout on success.

这是**猜测**。修复器的上下文只有 `environment/**`、`tests/reference_poc.py` 和失败试验的
`reference_stderr`（`no token disclosed (status 200)`），看不到镜像里 site-packages 的
`jupyterlab` 源码，因此无法验证“库的公开 API 到底返回什么”。它两次都只改了 `app.py`，
而同一次修复里 PoC 是可以改的（错误信息里包含 `reference_poc_all_success`）。

下一轮的两个改法（按代价从低到高）：

1. 把被 pin 的库源码（或至少其公开 API 的签名与返回类型）注入修复上下文；
2. 给修复器一条“跑一次 T03 看真实输出”的通道，让修复从猜测变成观察。

### 预算账本的两个缺陷（已修复，新增 5 个单测，全套 151 个通过）

**缺陷 A：崩溃留下的陈旧预留会永久锁死候选。**
矩阵被 kill 后，`budget.json` 里的 `CVE-…-trials-N` 仍然存在。重跑同一 revision
（尤其是换 profile 后金额不同）时，`reserve(reuse=True)` 直接抛
`Reservation … exists with different amounts`，候选被判 `budget_exhausted`，
且 `auto_repairable=False`——**永久隔离**。今晚 `113613`/`22871` 就是这样被误杀的。

修复：

- 预留记录 owner（pid + host）；金额冲突时只有 owner 已死才回收；
- `Lease.is_held()`：预留是否还活，以候选目录的 job 租约是否被持有为准
  （每次 reserve/commit 都在租约内完成）；
- 每批开始时 `reclaim_orphans()` 清掉没有活租约的预留。

实测回收 25 条陈旧预留，合计 **1071 个 trial 额度**（`reserved` 1224 → 153）。

**缺陷 B：共享 run 目录的账本限额不会增长。**
`Ledger.load_or_create` 复用第一个批次写入的 `limits`，后续批次在同一 run 目录里
永远被更小的额度约束。修复：`raise_limits()`，只升不降。

### 手动恢复工具

`work/reset_candidate.py`：把被误隔离的候选退回 `VALIDATING` 并退还其陈旧预留。
它要求 `task/`、`image-set.json` 存在，且 `trials.json`、`evaluation.json` 不存在，
所以不会覆盖任何真实判定。

### 06:35 的一次抽样：3 个从未尝试的候选

| CVE | 结果 | 原因 |
| --- | --- | --- |
| `CVE-2026-26057` | `generation_error` | 生成的代码 import `starlette`，但 `requirements.txt` 没声明 |
| `CVE-2026-22810` | `evidence_insufficient` | 合成出的断言 `A7` 不在契约里 |
| `CVE-2026-22171` | `UNSUPPORTED` | CWE-22 任意文件**写**，不是可读回的原语，契约无法表达 |

三个候选 2 分钟内全部结束，没有一个进入矩阵。这条数据说明：**分诊只判断
“能不能做成差分题”，不判断“参考 PoC 能不能读回 secret”**。下一轮应在分诊阶段
按 read/write 原语分类：只有能“读回一个 secret”的 CVE 才值得花合成成本。

## 八、07:00 现状

### 已释放（2）

| CVE | quality | 发布路径 |
| --- | --- | --- |
| `CVE-2026-116673` | 100.0 | `runs/qual-sample300c-r2/CVE-2026-116673/release/task` |
| `CVE-2026-24884` | 95.0 | `runs/qual-sample300c-r2/CVE-2026-24884/release/task` |

`CVE-2026-24884` 存在第七之五节记录的旁路，建议在纳入训练集之前先修掉 `/extract/view` 的读回。

### 第三批“复活”候选（06:10 拉起，06:27 提前停止）：0 新增

三个候选是在 300 秒构建上限下超时被隔离的，06:10 用 600 秒上限重新拉起
（`state → REPAIRING`，`attempts` 归零，任务不重新合成）。构建都通过了，
但在 T03 上全部失败，按 `require_reference_poc_all_success` 已必隔离，
06:27 停止批次以释放机器：

| CVE | 依赖清单 | T03 实跑 | 结论 |
| --- | --- | --- | --- |
| `CVE-2026-102904` | `jupyterlab==4.6.3` | 0/3 | 隔离 |
| `CVE-2026-113613` | `flexget==3.20.6` | 0/4 | 隔离 |
| `CVE-2026-22871` | `guarddog==2.7.0` | 0/7 | 隔离 |
| `CVE-2026-115924` | — | 未开始 | 构建后 `/health` 120 秒内无响应，隔离 |

这再次说明“构建成功”与“PoC 能打通”是两件事：重型依赖只是把失败点
从 build 阶段推迟到 validate 阶段。

### 修复实验（06:31 起）：0 新增

用 smoke（14 个试验）测“修复器能否修好打不通的 PoC”，见第七之六节。
`CVE-2026-102904` 用完两次修复额度后 T03 仍然是 0/3：

| CVE | 修复次数 | 修复后 T03 | 最终状态（07:51） |
| --- | --- | --- | --- |
| `CVE-2026-102904` | 2 / 2 | 0/3 | QUARANTINED（`validation_error`） |
| `CVE-2026-113613` | 2 / 2 | 0/3（rev 4）；rev 5 矩阵跑到 7/14 时主机内存不足，批次被系统终止 | 未完成，无发布 |
| `CVE-2026-22871` | 2 / 2 | 0/3（rev 4）；rev 5 刚进入 GENERATED，重建尚未开始即被终止 | 未完成，无发布 |

两次修复各写出一个不同的 `app.py`（digest 均不同），说明模型每次都在
重新猜测库的行为——这正是第七之六节“修复器读不到库源码”的证据。

### 07:51：主机内存耗尽，批次被终止

`CVE-2026-113613` 与 `CVE-2026-22871` 的第二次修复都已生效，正进入最后一次
smoke 矩阵时，主机可用内存降到 1.6 GB / 31.8 GB，后台批次被系统终止
（`vmmemWSL` 持有 15.5 GB）。残留容器已清理，`wsl --shutdown` 后可用内存回到 13.4 GB，
Docker Desktop 现在处于停止状态。

两个候选都没有完成最后一次验证，因此**夜间最终发布数仍是 2**；
`113613` 在 rev 4（第一次修复后）的 T03 是 0/3，`22871` 同样是 0/3。

### 其它

- 分诊任务：3000 个输入 → **1841 个 eligible**（61.4%），1157 个 unsupported，2 个 error，
  结果在 `candidates/cve-2026-triage-3000.json`，下一轮直接用它。
- `pipeline.toml` 的 `max_repairs` 已恢复为 2（05:10–06:05 的快速判定阶段临时设为 0）。
- 预算账本回收了 25 条陈旧预留，合计 1071 个 trial 额度；`work/reset_candidate.py`
  可以把误隔离的候选退回 `VALIDATING`。
- 新增候选文件：`candidates/repair-probe-r1.json`、`repair-probe-r2.json`、
  `sweep-smoke-r1.json`。
- 全套测试 151 个通过（新增 5 个：账本 owner 回收 2 个、孤儿预留回收 1 个、
  限额只升不降 1 个、数据集清单跨批次合并 1 个）。

## 九、复现命令

状态与报告：

```bash
python work/status_snapshot.py runs/qual-sample300c-r2
python -m harbor_pipeline report --run-id qual-sample300c-r2 --json
python -m harbor_pipeline report --run-id qual-sample300c-r2   # 人读版
```

复现今晚的三个关键实验：

```bash
# 1) 单个候选、6 并发（116673，25 分钟跑完 48 个试验）
python -m harbor_pipeline batch --input candidates/single-116673.json \
  --run-id qual-sample300c-r2 --profile qualification --workers 1 --trial-workers 6

# 2) 四个 T03 未测候选（100520/103061/24486/24884）
python -m harbor_pipeline batch --input candidates/unknown-t03-r1.json \
  --run-id qual-sample300c-r2 --profile qualification --workers 4 --trial-workers 4

# 3) 旁路探针：证明 24884 的修复版仍可被 /extract/view 读回
#    （任务目录是 matrix/t04-01 的副本，只替换了 tests/reference_poc.py）
PYTHONPATH=. python - <<'PY'
from pathlib import Path
from harbor_pipeline.harbor_adapter import HarborAdapter
ad = HarborAdapter(jobs_dir=Path("work/bypass-jobs"), run_root=Path("work"), timeout_sec=900)
out = ad.run([Path("work/bypass-probe").resolve()], agent="oracle", job_name="bypass-probe", n_concurrent=1)
print([(t.reward, t.evidence_status) for t in out.trials])
PY

# 4) 修复实验：smoke 矩阵 + 一次有界修复（14 个试验）
python -m harbor_pipeline batch --input candidates/repair-probe-r1.json \
  --run-id qual-sample300c-r2 --profile smoke --workers 3 --trial-workers 3

# 5) 把被误隔离的候选退回 VALIDATING（并退还它的陈旧预留）
python work/reset_candidate.py CVE-2026-113613 CVE-2026-22871
```

端到端复测 PoC 修复（低负载时才有意义）：

```bash
PYTHONPATH=. python work/pocfix_probe.py
```

## 十、下一轮怎么跑（按夜间实测改写的策略）

今夜最大的教训不是“判分太严”，而是**调度方式把机器用错了**。下一轮按下面三条执行：

1. **少候选、高并发**。一个候选 6 并发 25 分钟跑完 48 个试验；
   10 个候选 2 并发要 3.2 小时并且会被 job 上限截断。
   建议 `--workers 3 --trial-workers 6`（18 个容器），单批 3 个候选，约 30–40 分钟一轮。
2. **先花 14 个试验做筛选，再花 48 个试验做准入**。
   `--profile smoke` 的矩阵是 8 个强制实验 + 3×T03 + 3×T04 = 14 个试验，
   可以在 10 分钟内判断“参考 PoC 是否打得通”。
   通过者再进 qualification（48 个试验）。
   需要补一个 `promote` 小工具：把 smoke 产生的 `evaluation.json`/`trials.json`
   备份后把状态退回 `VALIDATING`，否则重新运行时 `validate()` 会直接复用 smoke 的结论。
3. **依赖清单在合成后立刻查 registry**。`jupyterlab`、`flexget`、`guarddog`
   这类重型依赖会吃掉 600 秒构建上限；`@pnpm/store.cafs@10.28.0` 这种不存在的版本
   则永远装不上。两种情况都应该在合成结束时用一次 HEAD/GET 判定，
   而不是等 10 分钟的构建。

另外两件必须做的事：

4. **发布前加“旁路探针”**（第七之五节）。固定一组通用遍历/读回请求，
   在漏洞版和修复版上各跑一次；修复版仍然返回 secret 就拒绝发布。
   这是 T04 覆盖不到的一类缺陷，今晚已经实证了一条。
5. **换生产主机**。32 核 Windows + Docker Desktop 的上限是每晚个位数；
   10000 道题需要 Linux 主机集群或云上多机，并且每台机器上跑相同的
   “少候选、高并发”调度。
6. **修复器要能看到被 pin 的库源码**（第七之六节）。目前它只能看到
   `environment/**` 和参考 PoC，对库的公开 API 只能猜；`102904` 四次修复写出四个
   不同的 `app.py`，全部失败。最低成本的改法是把库源码（或 API 签名）注入修复上下文，
   更进一步是让修复器能跑一次 T03 并看到真实输出。
7. **分诊阶段按“读回原语”分类**。06:35 的抽样里，3 个候选全部在合成前/合成时失败，
   其中 `CVE-2026-22171` 被正确判定为“任意文件写、无法读回 secret”。
   分诊现在只看“能不能做成差分题”，下一步要看“参考 PoC 能不能拿到 secret”，
   否则 85% 的合成成本花在注定 T03 全灭的候选上。
8. **预算账本已加 owner 与回收**（第七之六节）。任何多批次共享 run 目录的运行方式
   都必须先有这个，否则一次 kill 就会永久锁死候选、并悄悄吃掉共享额度。

