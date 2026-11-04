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

## 2. 出题过程（Draft → Fixed Tests → Tool Agent）

### 2.1 草稿生成（Draft，一次 LLM 调用）

成本控制：先用**一次**结构化 LLM 调用生成完整草稿，而不是让一个 agent 反复探索：

- 输入：确定性提取的版本/commit（`discovery.json`）+ 证据摘录 + 固定的 target 契约 + schema。
- 输出：`synthesis.json`（bundle），包含 root cause、preconditions、goal、target 文件、参考 PoC、备选 PoC。
- 确定性校验立即执行：产品/版本/commit 强制取自证据；断言必须引用来源；Dockerfile 禁止逃逸构建沙箱；`{{REF}}` 必须出现在依赖版本里；修复版本必须真实切换上游 release。
- 校验失败 → 把具体问题喂回模型，最多 3 次；仍失败则 `generation_error`（可修复）或 `UNSUPPORTED`（不可表示）。

### 2.2 固定构建 + T03/T04 门

草稿通过后，框架**立即**：

1. 构建 vulnerable / fixed 两套镜像（agent / target / verifier 共 6 个镜像）。
2. 跑 **T03**（参考 PoC 打 vulnerable）和 **T04**（同一 PoC 打 fixed）。
3. 只有 T03 通过、T04 不泄漏，才继续跑完整矩阵；否则进入修复。

### 2.3 工具型 Repair Agent（测试失败后）

修复器不是一次性补丁模型，而是一个**带工具的作者 agent**（40 步、最多 6 次 verifier、4 次 build）：

- 读 bundle / spec / 文件；写 `environment/` 与 `tests/reference_poc.py`；创建新文件。
- 改版本 pin（`set_version`）、启动命令（`set_start_command`）、fixed-only override（`set_fixed_override`）。
- 查 registry（PyPI / npm / Go / Maven）确认真实版本，不靠猜。
- `build` 看真实构建日志；`run_verifier` 跑真实 T03+T04。
- 容器内探查：读取已安装库的导出/源码，运行 `curl`/`import` 探针。
- 框架自有文件（target entrypoint、主 Dockerfile、compose、verifier、instruction、task.toml）**只读**，agent 无法改评分门。

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

# 单题（任意 CVE，自动合成）
python -m harbor_pipeline -c pipeline.repair2.toml run \
  --cve CVE-2026-113664 --scenario auto --profile qualification --json

# 批量
python -m harbor_pipeline -c pipeline.repair2.toml batch \
  --input candidates/cve-2026-scale-r2.json \
  --run-id scale-YYYYMMDD --profile qualification --workers 1 --trial-workers 1
```

主要阶段：`collect → draft → freeze → generate → build → validate → release → dataset`。

---

## 6. 目录

```
harbor_pipeline/          # pipeline 源码
  goals.py                # goal family / auth 原语
  synthesis.py            # 草稿生成与确定性校验
  repair.py               # 工具型 repair agent
  scenario.py             # 固定 target / verifier / 负例模板
  differential.py         # T01–T12 差分矩阵
  evaluator.py            # 卡点 / 框架健康 / 质量档
schemas/                  # 数据契约
policies/                 # 验收策略与实验定义
tests/                    # 单元与集成测试
docs/                     # 设计与运维文档
```
