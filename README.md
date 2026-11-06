# CVE → Harbor Task Pipeline

把公开 CVE 证据自动转换成 **Harbor 安全训练题**：每道题包含一个真实漏洞应用、一个参考 PoC、一个修复后版本，以及一套固定的差分测试矩阵。评分不依赖 LLM。

---

## 1. 来源（Evidence Sources）

一次 `collect` 只从以下来源抓取，全部经过 **https + 主机白名单 + 公网 IP 校验 + DNS pinning**：

| 来源 | 用途 |
|---|---|
| **MITRE CVE JSON 5.0**（`cveawg.mitre.org` / `www.cve.org`） | CVE 元数据、描述、参考链接、CVSS |
| **NVD**（`nvd.nist.gov`，支持年度 gzip feed 缓存） | CPE、受影响产品、补丁/配置信息 |
| **OSV**（`api.osv.dev`） | 跨生态系统的受影响版本区间与修复提交 |
| **GitHub Advisory**（`api.github.com`） | 安全公告、GHSA 映射、修复链接 |
| **PyPI**（`pypi.org`） | Python 发布版本、`requires_python`、制品 digest |
| **npm**（`registry.npmjs.org`） | JavaScript 发布版本、`engines`、dist tarball |
| **Go module proxy**（`proxy.golang.org`、`sum.golang.org`） | Go 模块版本与校验和 |
| **Maven Central**（`repo1.maven.org`） | Java 制品版本 |
| **上游 commit patch**（`github.com` / `raw.githubusercontent.com`） | 修复提交的 diff，作为 `fix_basis` 和断言依据 |

抓取结果写入 `evidence/` 与 `evidence-index.json`，带 `sha256`。冻结后的 `CveSpec` 只能引用已抓取且 `status=ok` 的来源。

> 题面（`instruction.md`）由框架生成，**不得包含** CVE id、产品名、修复 commit、修复版本。

---

## 2. 出题过程（Native Claude Code Authoring）

### 2.1 一个候选 = 一个原生 Claude Code 会话

不再先让模型一次性盲写草稿、失败后再用自制 JSON action 循环修补。每个候选直接启动一个**原生 Claude Code** 会话：

- 工作区：`runs/<run>/<CVE>/author/`
  - `bundle.json`：元数据（product/versions/preconditions/root_cause/impact/goal/assertions）
  - `target/`：靶机应用源码，agent 用原生 `Read`/`Edit` 修改
  - `target-fixed/`：fixed variant 专属文件
  - `poc/reference.py`、`poc/alternate.py`：两套参考利用
  - `inputs/`：只读的 `discovery.json`、`spec.json` 与原始证据
- harness：`claude -p --bare --restricted`，只允许 `Read/Write/Edit/Grep/Glob` 和 `Bash(harbor-author:*)`；其余命令在 `--permission-prompts none` 下自动拒绝。
- 上下文：由 Claude Code 原生多轮对话、prompt caching 和 auto-compaction 管理；不再每步重发所有文件。
- 预算：`--max-turns`、`--max-budget-usd`、会话超时，加上 helper 自己的 build/probe/exec 计数上限。

### 2.2 `harbor-author` helper（内循环）

agent 只能通过 `harbor-author` 接触外部世界：

| 命令 | 作用 |
|---|---|
| `validate` | 组装 bundle，跑 schema、`normalize_bundle`、依赖真实性、read-back 检查 |
| `build` | 只构建 vulnerable/fixed 两个 **target** 镜像；agent 镜像全局共享，verifier 按 variant 薄构建（Harbor 必须把 `tests/` 烘进 verifier 镜像） |
| `probe` | 直连 compose 跑真实 `tests/verify.py`：target + observer（file_write）+ verifier main |
| `probe --alternate` | 用备选 PoC 作为 submitted，验证另一条等价 payload |
| `exec -- <cmd>` | 在最后一次构建的 vulnerable target 镜像内执行（`--network none`） |
| `registry` | 查询 PyPI / npm / Go / Maven 真实版本 |
| `submit` / `decline` | 提交已验证的树，或明确声明该 CVE 不适合当前 Web 契约 |

`probe` 的网络设为 `internal: true`，PoC 不能访问外网；marker volume 只挂 target 和独立 observer，verifier main 不挂载。这样内循环不需要每个候选每轮起 Harbor job，也不需要重复构建 6 个镜像。

### 2.3 固定验收门

`submit` 只代表 agent 自己验证通过。pipeline 仍会重新 `freeze → generate → build → validate`：

1. 用真实的 `build_spec` + `freeze` 生成 `CveSpec`。
2. 渲染固定的 instruction、`task.toml`、`verify.py`（agent 无法修改这些文件）。
3. 构建 target 镜像和 variant 专属的薄 verifier 镜像，跑完整 T01–T12；agent 使用全局预构建镜像（verifier 不能 pin 通用镜像，否则 `/tests` 为空）。
4. 最终矩阵失败时，用 `claude --resume <session-id>` 把失败证据发回**同一个会话**，让 agent 在原有上下文里继续修；次数由 `author_max_resumes` 限制。
5. 无法在 Web 契约下真实复现的 CVE 走 `decline` → `UNSUPPORTED`，不再强行包一层 `:8080` 胶水代码。

> 过渡期保留 `authoring = "legacy"`，可回退到旧的 one-shot draft + JSON repair 链路；canary 与重跑对比通过后删除。

### 2.4 解题 Agent 反馈回路（solver review）

“oracle 能打成功”不等于“解题者能想到”。有些题依赖隐藏路由、符号链接、内部配置文件或库的内部结构，黑盒信息不足时就会变成猜谜题。

矩阵通过后，框架会：

1. 渲染一份带当前 `presentation` 的 solver task，用 Harbor 跑一次真实的 `claude-code` solver（turn / USD / 时间都有上限）。agent runtime 使用预构建的 `base-solver` 镜像（含 node/npm/claude CLI），跳过每次 trial 的 apt/npm 安装。
2. 把 instruction、target 源码、**参考 PoC** 和 solver 的 reward/失败类型一起交给 reviewer，返回结构化评价：
   `solved / fair / guess_work / recommended_mode / missing_context / score / verdict / recommendations`。
3. `verdict=revise` 或 `score < solver_min_score` 时，把评价发回**同一个 author 会话**，要求加白盒上下文或 hints；`decline` 则判 `UNSUPPORTED`；`release` 才进入 release 阶段。

#### 黑盒 vs 白盒

- `black_box`（默认）：只给 instruction。
- `white_box`：额外把 `environment/target/` 只读挂载到 `/workspace/source`，并在 instruction 中列出 `source_paths` 与 `hints`。用于隐藏路由、符号链接、特殊配置、库内部结构等无法从服务表面推断的场景。
- hints 不得包含 CVE id、产品名、修复 commit/版本，也不得包含答案本身；源码里可以自然出现产品信息，因为这是白盒设计的一部分。

#### 已观测案例

| CVE | 黑盒 solver | reviewer | 白盒修订 | 白盒 solver | 最终 |
|---|---|---|---|---|---|
| 102904 (JupyterLab 扩展卸载 pip 注入) | 路由 fuzz，1.78M input tokens，$2.60，失败 | `revise` / white_box / score 3 | 5 turns，$0.84；补 `/lab/api/extensions`、请求体、反向连接、库源码摘录 | 首次成功，585k tokens，$1.16 | `release` / score 4 / tier A |
| 106103 (@quasar/icongenie profile 穿越) | 路由 fuzz 900s 超时，1.14M input tokens，失败 | `revise` / white_box / score 3 | 14 turns，$3.88；补 `/api/assets/stage`、schema、路径深度、`get-assets-files.js` 摘录 | 首次成功，228k tokens，$0.37 | `release` / score 4 / tier A |

两个任务在 black-box 下都退化成“枚举路由/深度”的猜谜；白盒 + 针对性提示后，solver 都能从源码推理出利用链，reviewer 也认为路径可推导而非猜测。

---

## 3. 验证（Fixed Verifier, No LLM Scoring）

所有判定来自**固定脚本**和真实容器行为，LLM 不参与打分。

### 3.1 差分矩阵 T01–T12

| 测试 | 内容 |
|---|---|
| T01 / T02 | vulnerable / fixed 健康检查与业务路由 |
| T03 | 参考 PoC 在 vulnerable 上成功（可重复） |
| T04 | 同一 PoC 在 fixed 上**不**成功 |
| T05 | 不提交 PoC → 不得得分 |
| T06 | 伪造成功输出 → 不得得分 |
| T07 | bypass / 默认 secret → 不得得分 |
| T08 | 去掉前置条件后漏洞消失（可选） |
| T09 | 独立重建多次仍一致 |
| T10 | 非法 PoC 必须执行失败 |
| T11 | 备选 PoC 也被接受（质量 A 档） |
| T12 | 注入 target 启动故障 → 必须归类为 infra error，而不是题目缺陷 |

### 3.2 通过条件

- **必须**：T03 全部成功、T04 全部不泄漏、T05/T06/T07/T10 固定负载全部被拒绝、目标健康、spec/证据一致。
- **认证题**：verifier 会额外用**去掉凭据**的同一参考 PoC 再打一次；仍然成功则判失败（说明认证不是必需前置条件）。
- **质量档**：T11 通过 = A，否则 B；没有 100 分加权总分。
- 评分输出：`task_gates`（卡点）、`framework_health`（框架自检）、`quality_tier` / `quality_flags`。

### 3.3 权限与隔离

- 不可信 PoC 以非特权 `replay` 用户、独立进程组运行，超时 `killpg`。
- `/tests` 对 PoC 只读；`/logs/verifier` 与 `/logs/artifacts` 权限隔离。
- verifier 独立镜像、独立环境，不复用 target 容器。

---

## 4. 题目分类（Goal Families）

按**漏洞后果**分类，而不是按 CWE。每个 family 有独立的 observable 和负例。

### 4.1 读取 secret（`secret_read`）

- **目标**：通过 CVE 自身的机制读到目标上的随机 48-hex token。
- **observable**：PoC 输出中出现该 token。
- **验证指标**：T04 fixed 不泄漏；T05/T06/T07 不得分；token 随机生成、不写入镜像；T09 重建稳定。
- **primitive**：path traversal、SQLi、SSRF、命令执行、反序列化、XXE、SSTI、auth bypass、信息泄漏等。

### 4.2 写文件（`file_write`）

- **目标**：让 target 把攻击者控制的内容写到预期目录之外。
- **observable**：target 写出 marker 文件；独立 observer 读回的内容等于 PoC 打印的 48-hex nonce。
- **验证指标**：PoC 运行在 verifier main，**不挂载** marker volume，无法直接写 marker；observer 只读；fixed 版本不产生 marker；T05/T06 无写不得分。
- **适用**：arbitrary write、zip-slip、import/extract 路径穿越等。

### 4.3 列目录（`directory_listing`）

- **目标**：列出预期之外的目录，得到一个框架随机生成的文件名。
- **observable**：PoC 输出该随机 `.txt` 文件名（不是文件内容）。
- **验证指标**：期望文件名由 target 在启动时发布到共享 volume；verifier 在运行任何 PoC **之前**读取并删除发布文件，PoC 无法从 verifier 容器或 `/tests` 中直接拿到答案；fixed 版本不返回该列表。

### 4.4 XSS / Admin Bot（规划中）

- **目标**：注入的脚本在 admin bot 的会话中被执行，并回传 admin session / 受保护数据。
- **observable**：bot 回调（callback）携带的随机 nonce 或 admin-only 数据。
- **验证指标**：bot 不访问攻击者可控的外部站点；callback 只能由真实 bot 会话触发；无注入时不得触发；fixed 版本不执行。
- **状态**：尚未实现。

> Windows 容器 / 仅客户端漏洞 / 安装期 UI 交互类 CVE 暂不支持。

---

## 5. 快速开始

```bash
# 环境
export ANTHROPIC_BASE_URL=...
export ANTHROPIC_AUTH_TOKEN=...

# 先验证原生 agent 的鉴权、工具和权限
python -m harbor_pipeline doctor --agent

# 单题（任意 CVE，agent 直接出题）
python -m harbor_pipeline -c pipeline.repair2.toml run \
  --cve CVE-2026-113664 --scenario auto --profile qualification --json

# 批量
python -m harbor_pipeline -c pipeline.repair2.toml batch \
  --input candidates/cve-2026-scale-r2.json \
  --run-id scale-YYYYMMDD --profile qualification --workers 1 --trial-workers 1

# 验证器/评分修复后，重评已隔离候选：复用已存储的 matrix，不重建镜像、不重跑试验
python -m harbor_pipeline -c pipeline.repair2.toml recheck \
  --cve CVE-2026-112005 --run-id scale-YYYYMMDD --profile qualification
```

`recheck` 只对 `QUARANTINED` 候选生效：重新计算 build lock、用当前 evaluator 重打分；只有 admission 变成 `released` 才会解除隔离并进入 release 重放。

主要阶段：`collect → author → freeze → generate → build → validate → solver → release → dataset`。
`--until solver` 会跑完矩阵后执行一次真实解题 + 公平性评价；`--until validate` 只跑矩阵，不跑 solver。

---

## 6. 目录

```
harbor_pipeline/          # pipeline 源码
  goals.py                # goal family / auth 原语
  agent.py                # 原生 Claude Code 会话 runner
  authoring.py            # author 工作区、bundle 组装、agent 契约
  author_tool.py          # harbor-author helper（validate/build/probe/submit）
  author_probe.py         # 直连 compose probe 与全局基础镜像
  solver_review.py        # 解题 Agent 尝试 + 白盒/黑盒公平性评价
  synthesis.py            # bundle 校验与确定性规格
  repair.py               # legacy one-shot draft + JSON repair（过渡期）
  scenario.py             # 固定 target / verifier / 负例模板
  differential.py         # T01–T12 差分矩阵
  evaluator.py            # 卡点 / 框架健康 / 质量档
schemas/                  # 数据契约
policies/                 # 验收策略与实验定义
tests/                    # 单元与集成测试
docs/                     # 设计与运维文档
```
