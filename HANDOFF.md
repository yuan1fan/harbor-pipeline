# Harbor CVE 产线工作交接

更新时间：2026-11-01  
交付状态：自动化产线已实现并完成首个真实 CVE 的正式资格验收；12 输入试点批次已跑通，oracle 与真实模型难度基线均已测量。当前可稳定生产 aiohttp 场景题目，扩充其它 CVE 场景是下一阶段工作。

本项目为 LLM 的 Web 安全与渗透测试训练批量构建 Harbor 题目。每个 CVE 对应一道主任务，必须用真实版本、根因证据、修复对照和可信判题证明考察点一致。详细方案见 [FRAMEWORK_PLAN.md](docs/FRAMEWORK_PLAN.md)，日常操作见 [OPERATIONS.md](docs/OPERATIONS.md)。

## 1 已完成的能力

- 六类数据契约与 JSON Schema：EvidenceIndex、CveSpec、BuildManifest、TrialRecord、Evaluation、DatasetManifest。
- 可恢复状态机：`DISCOVERED → EVIDENCE_READY → SPEC_FROZEN → GENERATED → BUILT → VALIDATING → VALIDATED → RELEASED`，失败进入 `REPAIRING`/`QUARANTINED`，不支持的 CVE 进入 `UNSUPPORTED`。
- 受限证据采集：仅 HTTPS、主机白名单、公网 IP 校验、DNS pinning；失败源落盘为错误快照并可重试。
- 真实双版本环境：漏洞版与修复版镜像、独立 verifier、T01–T12 差分矩阵、正常业务探针、参考解法与负例。
- 量化验收：`F = 20V + 15P + 25M + 30D + 10I`，Wilson 置信区间、20 组成对 qualification 样本、硬条件准入。
- 本地发布包：不可变任务副本、spec、evaluation、build manifest、matrix、`audit.zip`；发布后从副本 oracle 复检。
- 批次与并发：候选解析/去重/limit、共享预算账本（进程锁 + 文件锁 + 预留）、worker 异常终态、数据集 split 审计与难度基线。
- 模型难度基线：在不可变发布任务上固定 agent/模型/提示/预算运行多次，记录成功率、中位耗时、token 与费用；凭据只以 `${VAR}` 模板进入 Harbor 配置。
- 有限自动修复：仅允许改 `environment/` 既有文件，受调用/token/费用预算约束；冻结规格、题面和测试不可修改。

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
| 模型难度基线 | `claude-code 2.1.316` + `deepseek-v4-pro`，3/3 成功，中位 `81.2s`，`$0.53961` |
| 12 输入试点 | `RELEASED = 1`、`UNSUPPORTED = 11`、产出率 `0.0833`，全部输入有终态 |

产物位于 `work/runs/qual-01/CVE-2024-23334/`，批次聚合报告位于 `work/runs/qual-01/batch-report.json`，模型基线位于 `work/runs/qual-01/model-baseline.json`。这些是真实 Docker/Harbor 与付费模型调用结果，不是 fixture 模拟。

模型基线是“难度测量”而不是“质量提升”：它使用 `harbor-bench/cve-2024-23334-claude:1` 作为 benchmark-only agent 运行时，只替换发布副本的 `environment/Dockerfile`，题面、tests、verifier 与 target 不变；该副本不参与资格验收或发布。当前代理只提供 `deepseek-v4-pro` 等模型，因此基线不是 Claude 数字；3 次样本也只是一条工程基线，不是统计分布。

## 3 代码结构

| 模块 | 职责 |
| --- | --- |
| `harbor_pipeline/cli.py` | `doctor/run/collect/freeze/generate/build/validate/release/batch/benchmark/resume/report` |
| `harbor_pipeline/pipeline.py` | 阶段编排、断点恢复、修复循环、预算预留、报告重建 |
| `harbor_pipeline/state.py` | 状态机、原子 checkpoint、跨进程 lease |
| `harbor_pipeline/contracts.py` | 六类契约校验、策略加载、冻结摘要 |
| `harbor_pipeline/sources.py` | 白名单 HTTPS 采集、重试、来源快照 |
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

## 4 运行方式

```bash
python -m harbor_pipeline doctor
python -m harbor_pipeline run --cve CVE-2024-23334 --profile qualification --run-id qual-01
python -m harbor_pipeline batch --input builtin --profile smoke --workers 2 --run-id batch-01
python -m harbor_pipeline batch --input candidates/pilot-web-cves.json --profile qualification --workers 2 --run-id qual-01
python -m harbor_pipeline benchmark --run-id qual-01 --cve CVE-2024-23334 --output-dir work/runs --agent claude-code --model deepseek-v4-pro --attempts 3 --max-turns 30 --max-budget-usd 1.0 --docker-image harbor-bench/cve-2024-23334-claude:1
python -m harbor_pipeline report --run-id qual-01 --output-dir work/runs
```

完整参数、退出码、产物布局和错误分类见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

## 5 接手注意事项

1. **真实付费调用**：`claude-cli`/`anthropic` provider 已接入，自动修复会真实计费。开发测试默认用 `fixture`；启用付费 provider 前先确认授权与预算。
2. **网络限制**：当前 Windows Docker Desktop 缺少 `CONFIG_NFT_FIB_INET`，Harbor 无法使用 `allowlist`，量产环境记录为 `public`，策略中 `require_network_allowlist = false`。Linux 正式主机应改回 `true` 并重跑资格验收。
3. **只内置一个 CVE 场景**：`CVE-2024-23334` 是完整闭环样本；其它 CVE 目前进入 `UNSUPPORTED`。扩充候选池需要在 `cves.py` 增加事实条目，并按 `scenario` 契约实现新模板。
4. **隔离与权限**：不可信 PoC 由非特权 `replay` 用户、独立进程组、超时 `killpg` 执行；`/tests` 与 `/logs/verifier` 权限隔离。修改 verifier 时不要破坏这两条边界。
5. **答案泄漏**：`instruction.md` 不包含 CVE id、产品名、修复 commit 或修复版本；`README.md`、`spec.json`、`evaluation.json` 只用于发布归档，不得挂载到 agent 环境。
6. **数据切分**：`split` 按 `project + root_cause_group` 哈希，新增同族 CVE 后检查 `batch-report.json` 的 `split_audit`，避免近重复样本跨集合。
7. **仓库状态**：Git 基线为 `44070f0 chore: baseline skeleton + plan docs`；当前实现与文档改动待提交。`work/` 与 `runs/` 被忽略，证物需另行归档。提交信息需带 `Co-Authored-By: Claude Code <noreply@anthropic.com>`。
8. **预算**：共享账本使用文件锁，必须放在本地文件系统；不要把 `work/` 放到网盘同步目录。
9. **下一步**：12 输入试点已完成，但只有 aiohttp 有完整场景；其余 11 个 CVE 是 `UNSUPPORTED` 终态，不能计入题库。下一阶段应为 httpd、Struts2、Spring、Log4j 等增加事实条目与场景模板，再测量各类别产出率。模型基线目前为 `deepseek-v4-pro` 的 3 次工程样本，更换模型、预算或题面后需重测；不要跨 run 复制该结果。

## 6 验证命令

```bash
python -m pytest -q
python -m harbor_pipeline doctor
python -m harbor_pipeline report --run-id qual-01 --output-dir work/runs --json
python - <<'PY'
from pathlib import Path
from harbor_pipeline.release import verify_release
print(verify_release(Path("work/runs/qual-01/CVE-2024-23334/release")))
PY
```

当前测试基线：`52 passed`（全仓）。发布包复验必须返回空列表；任何一项非空都不得把任务当作已发布。
