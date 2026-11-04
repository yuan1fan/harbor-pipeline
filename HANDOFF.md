# Harbor CVE 产线工作交接

更新时间：2026-11-02  
交付状态：自动化产线已实现并完成模板 CVE 的正式资格验收；任意 CVE 自动发现与合成路径已端到端跑通，12 输入试点批次、oracle 与真实模型难度基线均已测量。当前支持“输入 CVE 编号 → 自动发现证据 → 合成 Harbor 题目 → 差分验证 → 输出量化指标”，不再需要为每个 CVE 人工编写场景模板。2026-11-02 新增：合成应用差分失败的自动修复路径、Go/Maven registry 身份、10k 批量所需的 shard/plan-only/prune 与网络、租约恢复能力。

本项目为 LLM 的 Web 安全与渗透测试训练批量构建 Harbor 题目。每个 CVE 对应一道主任务，必须用真实版本、根因证据、修复对照和可信判题证明考察点一致。详细方案见 [FRAMEWORK_PLAN.md](docs/FRAMEWORK_PLAN.md)，日常操作见 [OPERATIONS.md](docs/OPERATIONS.md)，10k 容量与分片运行见 [CAPACITY_10K.md](docs/CAPACITY_10K.md)。

## 1 已完成的能力

- 六类数据契约与 JSON Schema：EvidenceIndex、CveSpec、BuildManifest、TrialRecord、Evaluation、DatasetManifest。
- 任意 CVE 自动路径：MITRE/OSV/GitHub Advisory/NVD 发现 → 修复 patch 与 registry 版本元数据 → synthesizer 生成 target/PoC → 确定性校验 → 通用 target/verifier → T01–T12 差分 → V/P/M/D/I 评分。缺版本对、缺可抓取修复 commit 或不属于未认证远程文件读取时进入 `UNSUPPORTED`，并保留量化原因。
- 双渲染模式：未知 CVE 默认合成；`cves.py` 内置 CVE 默认走版本化模板；`--scenario auto` 可强制合成。`task-manifest.json` 用 `generation_mode` 与 `synthesis_digest` 区分来源。
- 可恢复状态机：`DISCOVERED → EVIDENCE_READY → SPEC_FROZEN → GENERATED → BUILT → VALIDATING → VALIDATED → RELEASED`，失败进入 `REPAIRING`/`QUARANTINED`，不支持的 CVE 进入 `UNSUPPORTED`。
- 受限证据采集：仅 HTTPS、主机白名单、公网 IP 校验、DNS pinning；失败源落盘为错误快照并可重试。
- 真实双版本环境：漏洞版与修复版镜像、独立 verifier、T01–T12 差分矩阵、正常业务探针、参考解法与负例。
- 量化验收：`F = 20V + 15P + 25M + 30D + 10I`，Wilson 置信区间、20 组成对 qualification 样本、硬条件准入。
- 本地发布包：不可变任务副本、spec、evaluation、build manifest、matrix、`audit.zip`；发布后从副本 oracle 复检。
- 批次与并发：候选解析/去重/limit、共享预算账本（进程锁 + 文件锁 + 预留）、worker 异常终态、数据集 split 审计与难度基线。
- 模型难度基线：在不可变发布任务上固定 agent/模型/提示/预算运行多次，记录成功率、中位耗时、token 与费用；凭据只以 `${VAR}` 模板进入 Harbor 配置。
- 有限自动修复：仅允许改 `environment/` 既有文件，受调用/token/费用预算约束；冻结规格、题面和测试不可修改。`validation_error` 也进入修复路径：当目标健康、负例被拒但参考 PoC 拿不到 secret（或修复版仍泄漏）时，修复器会收到 oracle 失败的 stderr 和只读的 `tests/reference_poc.py`，并保持同一漏洞类别与路由/参数接口。修复响应结构不合法时最多带反馈重问 3 次；provider 故障归为可重试的 `infra_error`，不会把模型故障误判为候选缺陷。提示还要求不能依赖 `process.stderr.write` 捕获继承 stdio 的子进程输出，Node.js 目标需包装可变默认导出的 `child_process.spawn` 并改为 pipe。
- 四类 registry 身份：PyPI sdist SHA-256、npm tarball SRI、Go sumdb `h1:` dirhash、Maven `.jar.sha256`；`go.mod`/`pom.xml` 参与 `dependency_lock`，Go `+incompatible` 版本会归一化。无摘要的候选保留 `unverified` 标记，不伪造 digest。
- 10k 批量运维：稳定 `--shard-index/--shard-count`、`--plan-only`、`--prune-images`、启动时清理残留 `task__*` 网络、按 pid 回收已死进程的 job lease；trial 预算按修复轮次放大，避免 repair 后资格验收超支。
- 证据发现重新覆盖 Go/Maven：OSV 声明生态的 Go/Maven 记录会抓取 `.info`/sumdb 或 Maven 校验和；generic 产品名仍只对 PyPI/npm 做 registry probe。
- 本地 NVD feed 索引：`nvd-cache` 把年度 feed 建成单 CVE 的 SQLite 索引（2026 年 83,505 条、约 415 MB、实测 8.6s），triage 从磁盘取 NVD 记录（实测 1–10 ms/次）；快照中没有的新 CVE 自动回落 API。匿名 NVD API 只有 5 次/30 秒，13,687 条全量 triage 的 NVD 等待时间因此从约 22.8 小时降到可忽略。

## 2 验收结果

首个真实 CVE `CVE-2024-23334`（aiohttp 3.9.1 → 3.9.2，修复 commit `1c335944d6a8b1298baf179b7c0b3069f10c514b`）已在 Docker/Harbor 实机完成 qualification：

| 指标 | 结果 |
| --- | --- |
| 最终状态 | `RELEASED` |
| 质量分 | `100.0` = 20V + 15P + 25M + 30D + 10I |
| 成对样本 | 20 组，有效 trial 51 |
| 成功率置信区间 | `[0.8389, 1.0]` |
| T01/T02 健康 | 均 `1.0` |
| T03 / T04 | oracle `20/20` 成功；修复版 `20/20` 失败（smoke 档位为 3/3） |
| 负例 T05/T06/T07/T10 | 全部按预期拒绝 |
| T08 controlled | `fixed_variant_holds` |
| T11 业务探针 | 通过 |
| T12 故障注入 | 正确归类为 `infra_error` |
| 任务摘要 | `85f24502df2a977a9cf7f6263fe7d423e8f64ed0207336adb46a6afa8c6603bf` |
| 制品 digest | `sha256:1638d3e47b1726755bbf7d2c1d1eadf23dc43739387218b325a411d635ed5037` |
| 发布复检 | `verify_release` 无问题；oracle `reward = 1.0` |
| 数据集 split | `test`（project + root_cause_group 稳定分组） |
| 模型难度基线 | `claude-code 2.1.316` + `deepseek-flash-cyber`，3/3 成功，中位 `68.34s`，`$0.58558` |
| 12 输入试点 | `RELEASED = 1`、`UNSUPPORTED = 11`、产出率 `0.0833`，全部输入有终态 |

产物位于 `work/runs/qual-01/CVE-2024-23334/`，批次聚合报告位于 `work/runs/qual-01/batch-report.json`，模型基线位于 `work/runs/qual-01/model-baseline.json`。这些是真实 Docker/Harbor 与付费模型调用结果，不是 fixture 模拟。

### 2.1 自动合成首题：CVE-2023-40587

输入只有 CVE 编号，没有为该 CVE 编写任何场景模板。产线自动发现 product `pyramid`（PyPI）、版本对 `2.0.1 → 2.0.2`、修复 commit `347d7750da6f45c7436dd0c31468885cc9343c85`，抓取 7 个来源；synthesizer `deepseek-flash-cyber` 合成 Pyramid 静态视图 NUL 路径穿越 target 与两个 PoC。随后在真实 Docker/Harbor 上完成 20 组成对 qualification：

| 指标 | 结果 |
| --- | --- |
| 最终状态 | `RELEASED` |
| 质量分 | `98.0` = 20V + 15P + 25M + 30D + 8I |
| 成对样本 | 20 组，有效 trial 50 / 总计 51 |
| 成功率置信区间 | `[0.8389, 1.0]` |
| T01/T02 健康 | 均 `1.0` |
| T03 / T04 | oracle `20/20` 成功；修复版 `20/20` `fixed_variant_holds` |
| 负例 T05/T06/T07/T10 | 全部按预期拒绝 |
| T08 controlled | `not_applicable`：合成 target 无框架可控变体，理由写入 evaluation |
| T11 业务探针 | 通过 |
| T12 故障注入 | 正确归类为 `infra_error` |
| 任务摘要 | `1e0d7568261ac694dbf2949c92fb0ffc4c7d8f8e8a3797d6451903f31a19cf4e` |
| 制品 digest | `sha256:5c855dfa8a457b7b1cf6f1e105b09b5c5880b2ebda99c4e0c851600caeb3d03c` |
| 发布复检 | `verify_release` 返回空列表；oracle `reward = 1.0` |
| 数据集 split | `validation`（project=`pyramid`，root_cause_group=`path-traversal`） |
| 合成用量 | input `145` / output `2404` tokens；prompt `9c338a68…b4eb0`；synthesis `d17561f5…408af` |

`I1-goal-impact` 是唯一失分项：该候选的 synthesis 生成于“confidentiality 强制 high”规则上线之前，spec 中仍是模型低估的 `low`；当前版本新建 synthesis 会把读取框架 secret 的 confidentiality 强制为 `high`。为保持制品与模型输出摘要的可追溯性，没有回写旧 bundle，因此以 `98.0` 发布而不是声称 100。产物位于 `runs/auto-pyramid9/CVE-2023-40587/`。

### 2.2 自动合成与自动修复：CVE-2026-87794

输入同样只有 CVE 编号。产线自动发现 product `bestzip`（npm）、版本对 `3.0.2 → 3.0.3`、修复 commit `2adb637b0acb05b8475de7db5af4b86ffcf40aaf`，按 CWE-88 参数注入合成 Node.js target 与参考 PoC；随后在真实 Docker/Harbor 上完成 20 组成对 qualification：

| 指标 | 结果 |
| --- | --- |
| 最终状态 | `RELEASED`，`revision = 4`，`attempts.repair = 3` |
| 质量分 | `95.0` = 20V + 15P + 25M + 30×0.8333 + 10I |
| 成对样本 | 20 组，有效 trial 50 / 总计 51 |
| 成功率置信区间 | `[0.8389, 1.0]` |
| T01/T02 健康 | 均 `1.0` |
| T03 / T04 | oracle `20/20` 成功；修复版 `20/20` `fixed_variant_holds` |
| 负例 T05/T06/T07/T10 | 全部按预期拒绝 |
| T11 / D6 | `fail`：另一种参数组合被目标拒绝（`goal_failed`、`reward=0.0`），扣 5 分；D6 是非硬条件 |
| 归属等级 | `A`，无 unknown assertions |
| 任务摘要 | `d8141bc789e8e4701b602e2fa3dca41836ff9626b851437f63a7918a02260f1a` |
| 制品 digest | `sha256:df9fdb1076ba8e1fb9f251eb586e41e70f90a5351ba45ad44100776b646dcecd` |
| 发布复检 | `verify_release` 无问题；oracle `reward = 1.0`，`reference_observed = true`，`health_ok = true` |
| 数据集 split | `train`（project=`bestzip`，root_cause_group=`injection`） |
| 合成用量 | input `8964` / output `3348` tokens |
| 修复用量 | #1 provider 故障；#2 input `320` / output `2363`；#3 input `8024` / output `2806` |

三次修复都不是针对该 CVE 的人工改模板，而是模型在失败反馈下自行修改 `environment/`：第 1 次是 repairer 误用 `claude-cli` 的 provider 故障；第 2 次修复了应用崩溃，但 `bestzip` 用继承 stdio 启动子进程，输出绕过 `process.stderr.write`，T03 报 `token not disclosed`；第 3 次按只读参考 PoC 的契约包装 `node:child_process.spawn`，强制 `stdio: ['ignore','pipe','pipe']` 并把 stdout/stderr 汇入响应，随后通过全部硬条件。本次为允许第 3 次修复使用了临时配置 `runs/pipeline.repair3.toml`；生产配置的 `max_repairs` 仍为 2。产物位于 `runs/auto-2026-bestzip-qual3/CVE-2026-87794/`。

出题有两条路径：未知 CVE 由 synthesizer 从证据合成 target/PoC，内置 CVE 走确定性场景模板；两条路径的 secret、entrypoint、题面与 verifier 均由框架生成。验题使用独立 verifier、T01–T12 差分和 oracle，不调用 LLM；模型基线则用 `claude-code` 测量难度。当前所有可配置模型入口统一为 `deepseek-flash-cyber`（`models.default`、`models.repairer`、`models.synthesizer` 与 benchmark 默认值）。合成与修复都必须使用 `anthropic` 补全端点：`claude-cli` 的 agentic 模型会请求工具，`--max-turns 1` 下以 `error_max_turns` 退出，或输出 DSML tool-call 而不是 JSON。

模型基线是“难度测量”而不是“质量提升”：它使用 `harbor-bench/cve-2024-23334-claude:1` 作为 benchmark-only agent 运行时，只替换发布副本的 `environment/Dockerfile`，题面、tests、verifier 与 target 不变；该副本不参与资格验收或发布。3 次样本只是一条工程基线，不是统计分布。

### 2.3 PyPI 自动合成冒烟与启动前护栏：CVE-2026-24486

输入 CVE 编号，自动发现 `python-multipart` `0.0.21 → 0.22` 并合成 Python target 与参考 PoC。第一次运行（`runs/auto-py-multipart1/`）暴露了一个此前没有覆盖的失败模式：模型生成的 `app.py` 导入 `starlette`，但 `requirements.txt` 只声明了 `python-multipart` 与 `uvicorn`。`pip install` 不会 import 应用，镜像构建成功，容器一启动就 `ModuleNotFoundError` 退出；17 个 trial 全部在评分前失败，被 `classify_trial` 归为 `infra_error`，修复器完全没有机会介入，最终 `state.error = None`、`quality = 54.67`。

针对该模式增加两层确定性护栏：

1. **合成阶段依赖声明校验**（`synthesis.py`）：解析 `requirements.txt` 与 Dockerfile 的 `pip install`（Node 为 `package.json`），对比源文件里的 import；忽略标准库、本地模块和常见 import/distribution 别名映射。未声明即返回 issue，触发带反馈的合成重试，错误停在出题阶段而不是 40+ 个 trial 之后。
2. **构建后 target preflight**（`backend.py` → `pipeline.build`）：`docker run` 启动刚构建的 target，轮询 `/health`；容器退出或超时即抛 `build_error`，容器日志（含 traceback）进入修复反馈。`build_error` 是 `auto_repairable`，修复循环会补依赖或修入口，而不是把它记成基础设施故障。

重跑（`runs/auto-py-multipart2/`，配置 `pipeline.api.toml`）：preflight 0.7s 通过；T03 5/5 成功、T04 3/3 泄漏，`quality = 95.0`，硬条件仅 `zero_fixed_success` 失败；修复循环真实介入 2 次（第 1 次补上传回调，第 2 次在应用层加文件名净化），最终 `QUARANTINED`，没有发布假题。预算：9 builds、5 calls、`65,051` tokens、51 trials；修复 #1 input `2,857` / output `1,302`，#2 input `7,850` / output `6,829`。

结论：T04 再次挡住了一个“看起来通过”的假题——该合成应用把框架的 `/opt/app/index.html` symlink 直接挂在 `/` 上，秘密不需要任何漏洞即可读取；两次修复都没有把它改成“必须走漏洞路径”。这类候选只能隔离。合成 prompt 已补充“symlink 是资产不是路由”的约束，修复 prompt 明确禁止在应用层加净化/校验来让 fixed 变体成立。

`resume` 语义也据此调整：对 `build_error`/`generation_error`/`validation_error`，`_prepare_retry` 在恢复时先调用一次有上限的修复，再重跑矩阵；只重跑相同输入无法改变这些模型缺陷的结论。`attempts.repair` 与 `max_repairs` 仍然是硬上限。

## 3 代码结构

| 模块 | 职责 |
| --- | --- |
| `harbor_pipeline/cli.py` | `doctor/run/collect/freeze/generate/build/validate/release/batch/benchmark/resume/report` |
| `harbor_pipeline/pipeline.py` | 阶段编排、断点恢复、修复循环、预算预留、报告重建 |
| `harbor_pipeline/state.py` | 状态机、原子 checkpoint、跨进程 lease |
| `harbor_pipeline/contracts.py` | 六类契约校验、策略加载、冻结摘要 |
| `harbor_pipeline/sources.py` | 白名单 HTTPS 采集、重试、来源快照 |
| `harbor_pipeline/discovery.py` | 任意 CVE 的版本对、修复 commit、registry 身份发现；缺失即 `unsupported` |
| `harbor_pipeline/synthesis.py` | synthesizer prompt/调用、bundle 规范化、证据强制覆盖、确定性安全校验 |
| `harbor_pipeline/cves.py` | 内置模板 CVE 事实；`get_optional` 返回 `None` 时走自动路径 |
| `harbor_pipeline/spec.py` | 从证据冻结 CveSpec |
| `harbor_pipeline/generator.py` | 任务渲染与越权路径限制 |
| `harbor_pipeline/backend.py` | Docker 镜像构建与 digest |
| `harbor_pipeline/harbor_adapter.py` | Harbor 0.23.0 调用、能力探测、verifier 隔离 |
| `harbor_pipeline/trials.py` | T01–T12 期望判定 |
| `harbor_pipeline/evaluator.py` | 五维评分、Wilson 区间、准入 |
| `harbor_pipeline/release.py` | 发布包、审计包、不可变制品复检 |
| `harbor_pipeline/batch.py` | 候选计划、共享预算、批次报告、数据集切分 |
| `harbor_pipeline/benchmark.py` | 不可变任务上的模型难度基线、agent 运行时覆盖 |
| `harbor_pipeline/worker.py` | 单候选隔离执行，异常一律转终态 |
| `harbor_pipeline/repair.py` | 受限模型修复与预算结算 |
| `harbor_pipeline/providers/` | `fixture`、`anthropic`、`claude-cli` provider |
| `policies/` + `schemas/` | 冻结验收策略与契约 schema |
| `tests/test_pipeline_units.py` | 预算、批次、worker、修复与审计回归测试 |
| `tests/test_auto_synthesis.py` | 自动发现、bundle 规范化、证据强制覆盖、合成题渲染与安全校验 |
| `tests/test_evaluator.py` | 修复版观察状态判定、T08 `not_applicable` 语义 |

## 4 运行方式

```bash
python -m harbor_pipeline doctor
python -m harbor_pipeline run --cve CVE-2024-23334 --profile qualification --run-id qual-01
python -m harbor_pipeline run --cve CVE-2023-40587 --profile smoke --run-id auto-01
python -m harbor_pipeline run --cve CVE-2023-40587 --scenario auto --profile qualification --workers 3 --run-id qual-auto-01
python -m harbor_pipeline batch --input builtin --profile smoke --workers 2 --run-id batch-01
python -m harbor_pipeline batch --input candidates/pilot-web-cves.json --profile qualification --workers 2 --run-id qual-01
python -m harbor_pipeline nvd-cache --year 2026 --refresh   # 预处理 NVD 年度 feed，triage 不再逐条打 API
python -m harbor_pipeline benchmark --run-id qual-01 --cve CVE-2024-23334 --output-dir work/runs --agent claude-code --model deepseek-flash-cyber --attempts 3 --max-turns 30 --max-budget-usd 1.0 --docker-image harbor-bench/cve-2024-23334-claude:1
python -m harbor_pipeline report --run-id qual-01 --output-dir work/runs
```

完整参数、退出码、产物布局和错误分类见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

## 5 接手注意事项

1. **真实付费调用**：`claude-cli`/`anthropic` provider 已接入，自动修复会真实计费。默认模型已固定为 `deepseek-flash-cyber`；无需模型调用的测试应显式配置 `fixture`，程序不会静默降级。
2. **网络限制**：当前 Windows Docker Desktop 缺少 `CONFIG_NFT_FIB_INET`，Harbor 无法使用 `allowlist`，量产环境记录为 `public`，策略中 `require_network_allowlist = false`。Linux 正式主机应改回 `true` 并重跑资格验收。
3. **自动合成与模板并存**：未知 CVE 走自动发现与合成，不需要在 `cves.py` 增加条目；内置 CVE 仍默认走版本化模板。合成与修复模型都必须使用 `anthropic` 补全端点（`models.synthesizer`、`models.repairer`），`claude-cli` 的 agentic 行为会请求工具并破坏 JSON。自动路径的固定范围是未认证远程文件读取；缺版本对、缺可抓取修复 commit 或模型判定不适用时进入 `UNSUPPORTED`，不能伪造。
4. **隔离与权限**：不可信 PoC 由非特权 `replay` 用户、独立进程组、超时 `killpg` 执行；`/tests` 与 `/logs/verifier` 权限隔离。修改 verifier 时不要破坏这两条边界。
5. **答案泄漏**：`instruction.md` 不包含 CVE id、产品名、修复 commit 或修复版本；`README.md`、`spec.json`、`evaluation.json` 只用于发布归档，不得挂载到 agent 环境。
6. **数据切分**：`split` 按 `project + root_cause_group` 哈希，新增同族 CVE 后检查 `batch-report.json` 的 `split_audit`，避免近重复样本跨集合。
7. **仓库状态**：Git 基线为 `44070f0 chore: baseline skeleton + plan docs`；当前实现与文档改动待提交。`work/` 与 `runs/` 被忽略，证物需另行归档。提交信息需带 `Co-Authored-By: Claude Code <noreply@anthropic.com>`。
8. **预算**：共享账本使用文件锁，必须放在本地文件系统；不要把 `work/` 放到网盘同步目录。
9. **下一步**：自动路径已覆盖 PyPI/npm 生态，并接入 OSV 声明生态的 Go/Maven；CVE-2021-41773 这类没有可抓取上游修复 commit 的输入会明确 `UNSUPPORTED`，不能计入题库。下一阶段应按类别扩大自动合成的支持面（更多生态、更多目标类型）、统计各类别自动产出率、补人工审查记录，并在 Linux allowlist 主机上重跑资格验收。模型基线目前为 `deepseek-flash-cyber` 的 3 次工程样本，更换模型、预算或题面后需重测；不要跨 run 复制该结果。

    Go 冒烟 `CVE-2026-32758`（filebrowser `2.61.2 → 2.62.0`）已跑到差分阶段：合成与构建成功，但 T04 发现修复版仍泄漏，因为修复器在应用里自写了复制路由，没有真正走 pinned package 的 handler。候选被 `QUARANTINED`（quality `93.0`、17 trials、3 builds、6 calls、`53,095` tokens），没有发布。这证明 T04 能挡住“看起来像”的假题，也说明当前模型对需要真实框架 handler 的 Go 目标产出率低（该样本 `0/1`）。10k 排期必须按生态分别统计 yield，不能把 npm/PyPI 的成功率套到 Go。
10. **2026 候选覆盖**：NVD 2026 feed 83,505 条，预筛 13,687 条；300 条原始样本中 257 条 eligible。对 257 条用当前代码重跑 triage：eligible 237、unsupported 14、error 6；生态分布 npm 36、PyPI 36、Go 16、Maven 1、NuGet 1、generic 147；两版 registry 身份齐全 85 条（PyPI 36、npm 36、Go 12、Maven 1）。Go 相比旧代码的 1 条显著增加，但仍有 4 条 sumdb 未返回。该样本比例不能外推为全量产出率；正式 10k 运行前应在 Linux 主机用 `--plan-only` 核算容量，并统计最终 `RELEASED`。
11. **10k 运行前检查**：Docker 预定义地址池（Linux 配置 `default-address-pools`）、磁盘与镜像清理、`workers × trial_workers` 的容器峰值、共享账本所在本地文件系统、每个 shard 的预算与 `--prune-images`。`--plan-only` 只写计划，不验证 Docker 或模型凭据。
12. **验证修复的边界**：`validation_error` 只修 `environment/`，不会改 verifier、题面或测试；如果失败集中在小程序路由/参数解析，先看 `repair-log.json` 与 T03 trial 的 stderr。不要把“负例被接受”或“目标不健康”误判为应用实现问题。
13. **启动前护栏与 resume**：自动合成的 target 在构建后必须先通过 `preflight_target`（`docker run` + `/health`），否则记为 `build_error` 并进入修复；不要删除这一步，否则未声明的运行期依赖会再次退化成无法修复的 `infra_error`。`resume` 对 `build_error`/`generation_error`/`validation_error` 会先做一次有上限的修复；对 `infra_error` 则直接重跑阶段。`attempts.repair` 与 `attempts.retry` 都受 `max_repairs` 约束。
14. **凭据与外部配额**：`GITHUB_TOKEN` 只提升 GitHub API 配额（匿名 60 次/小时/IP，认证 5,000 次/小时）；`NVD_API_KEY` 把 NVD API 从 5 次/30 秒提到 50 次/30 秒。两者只从环境变量读取，不写 TOML、不写产物；`Authorization` 只发给 `api.github.com`，`apiKey` 只发给 `services.nvd.nist.gov`，重定向不跨主机转发。全量 triage 已不依赖 NVD key：`[sources].nvd_feed_cache = "work/harvest"` 复用 harvest 下载的 feed，未命中、feed 不可读或年份早于 2002 时回落 API，原因写入 `discovery.json` 的 notes。GitHub 仍建议配 token，否则 13,687 条约需 9.5 天匿名配额。
15. **生态 yield 的失败归因**：不要只看 `RELEASED` 数量。PyPI 的两次失败分属两类：`CVE-2026-24486` 第一轮是未声明运行期依赖（`infra_error`，已由依赖校验与 preflight 拦下），第二轮是题面设计让 `/` 直接读取 symlink，与漏洞无关，T04 正确隔离。Go 的 `CVE-2026-32758` 是模型用 `filepath.Join` + `os.ReadFile` 自写了遍历，pinned module 只在 `/rules/check` 被调用，切换 `2.61.2 → 2.62.0` 不改变泄漏，因此 T04 必然失败。按生态统计 yield 时要把“基础设施失败 / 题面设计失败 / 未真正走 upstream 代码”分开计数。

## 6 验证命令

```bash
python -m pytest -q
python -m harbor_pipeline doctor
python -m harbor_pipeline report --run-id qual-01 --output-dir work/runs --json
python -m harbor_pipeline report --run-id auto-pyramid9 --output-dir runs --json
python - <<'PY'
from pathlib import Path
from harbor_pipeline.release import verify_release
print(verify_release(Path("work/runs/qual-01/CVE-2024-23334/release")))
PY
```

当前测试基线：`142 passed`（全仓），`ruff check harbor_pipeline tests` 通过。发布包复验必须返回空列表；任何一项非空都不得把任务当作已发布。
