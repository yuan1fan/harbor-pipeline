# 10k 生产运行设计与容量核算

本文件把“从 CVE 2026 产出 10,000 道题”拆成可核算的漏斗、并发、存储和运维步骤。所有数字都区分**实测**与**计划假设**；没有实测的字段不写成结论。

## 1 输入漏斗

| 阶段 | 数量 | 来源 |
| --- | --- | --- |
| NVD 2026 feed | 83,505 | `harvest` 实测 |
| 预筛候选（Web/网络、有 secret-disclosure 原语、非本地） | 13,687 | `candidates/cve-2026.json` 实测 |
| 300 条原始样本中 triage eligible | 257 | `candidates/cve-2026-triage-sample300b.json` 实测 |
| 对 257 条用当前代码重跑 triage：eligible / unsupported / error | 237 / 14 / 6 | `candidates/cve-2026-triage-sample300c.json` 实测（1,339s，4 workers） |
| 生态分布（eligible） | npm 36、PyPI 36、Go 16、Maven 1、NuGet 1、generic 147 | 同上 |
| 两版 registry 身份齐全 | 85（PyPI 36、npm 36、Go 12、Maven 1） | 同上；Go 另有 4 条 sumdb 未返回 |
| 剩余 generic（私有项目或非 registry 分发） | 147 | 同上 |

关键结论：

- 13,687 是**预筛候选**，不是可发布题目数。真正能进入合成的候选必须先得到真实版本对、可抓取修复 commit 与 registry 身份。
- 237/257 eligible 只表示“证据足以尝试合成”，不表示 qualification 会通过。合成、构建、差分与 20 组成对验收都会继续淘汰。
- Go/Maven 身份只在 OSV 或引用链接给出完整坐标时可用；generic 产品名无法可靠 probe 到 Go module 或 Maven 坐标。因此不能把 85/237 当作最终固定率，也不能把 147 条 generic 直接计为失败。

正式 10k 运行前，应先用新一轮 triage 统计四类分布：`pypi`、`npm`、`go`、`maven`、`generic`，并分别记录 `by_ecosystem`、`eligible` 与最终 `RELEASED`。只有 `RELEASED` 进入数据集。

## 2 单候选预算

单候选 trial 上限：

```text
(mandatory + 2 × trials + 3) × (max_repairs + 1) + 10
```

qualification 档位参数：`mandatory` 是除 T03/T04/T09 外的必需实验数，`trials = 3`，`max_repairs = 2`。矩阵现在是**阶梯式 fail-fast**：T03 首次 → T04 首次 → 确认重复 → T09 seeds → T11/T12，每个 blocking 步骤是一个独立 Harbor job，失败即停。全通过的候选跑 11 次 trial；死在 T03 的候选只跑 1 次 trial，死在 T04 的候选跑 2 次。T01/T02 的 health/business 检查由 T03/T04 的 verifier 先做并记录，因此从这两类记录推导 verdict，不再起独立容器；T05/T06/T07/T10 的 payload 是框架常量，改为一次性、无 Docker 的 verifier 回归检查。出题模型可以在 synthesis bundle 里用 `matrix_repeats`（3–20）上调，前提是它判断漏洞路径存在真实的不确定性。批次账本在合成之前规划，因此仍按上限 20 预留额度（约 170 次 trial、22 次 build），但那是上限而非实际消耗。每个 revision 构建 6 个镜像（两个 variant × agent/target/verifier）；矩阵探针在 `task.toml` 和 compose 里锁定这些镜像，Harbor 不再每个 trial 执行 `docker compose build`，因此不会重复生成 build history 和项目级镜像。smoke 档位显著更低，不能用于发布。

批次上限按候选数量乘以上式，再额外预留 30 trial / 6 build。一个 4 shard、13,687 候选的 plan-only 实测输出：

| 字段 | 值 |
| --- | --- |
| 每 shard 候选 | 3,422 |
| 每 shard trials 上限 | 533,862 |
| 每 shard builds 上限 | 61,608（每 revision 6 个镜像 × 3 个 revision × 3,422 候选 + 6） |
| 每 shard wall_sec 上限 | 24,638,400（7,200 × 3,422） |

`wall_sec` 是账本累计墙钟预算，不是单机 deadline；多 worker 并行时实际 elapsed 远小于该值。它只防止单候选无限重试，不能替代生产调度。

## 3 并发模型

两个旋钮相乘决定峰值：

```text
峰值 trial 数 = workers × trial_workers
峰值容器数 ≈ 峰值 trial 数 × 2（target + main，verifier 在 separate 模式下另计）
峰值网络数 = 峰值 trial 数
```

- `--workers`：单个批次进程内并行的 CVE 数。
- `[pipeline].trial_workers`：单个候选内部同时运行的 Harbor trial 数，默认 2。
- 不要在同一个 Docker 主机上把两者同时拉满：Harbor 每个 trial 都创建 compose 网络和目标/agent 容器，地址池、内存和构建缓存会先于 CPU 成为瓶颈。

按 qual3 实测，2 个 CVE worker × 2 个 trial worker 时：全通过的候选约 11 次 trial（T03/T04 各 3 次 + 3 次 seed + T11/T12 各一次），约 6–10 分钟；在 T03 首次就失败的候选只跑 1 次 trial，约 1.5–2 分钟（加上 1 次 job 启动开销）。如果出题模型把 `matrix_repeats` 上调到 20，确认步骤回到约 45 次 trial。默认档下单候选（含一次 repair）约 8–24 分钟；下表的上界应按此下调，正式排期仍以实测替换：

| 每 shard worker 数 | 3,422 候选的粗估 elapsed |
| --- | --- |
| 4 | 24–60 天 |
| 16 | 6–15 天 |
| 32 | 3–8 天 |

这些是**排队模型估算**，没有计入大量候选在 discovery/generation 阶段快速进入 `UNSUPPORTED` 的节省，也没有计入 repair 失败。正式排期必须用 shard 的 plan-only 加小批量实测替换。增加 worker 前先确认 Docker 地址池、内存、磁盘和 Harbor 的 compose 并发限额。

## 4 Docker 地址池

被杀或超时 trial 会在 `task__*` 下留下 dangling 网络；积累后 Docker 报 `all predefined address pools have been fully subnetted`，后续 trial 在启动阶段全部失败。产线已在每次 CLI 启动时调用 `prune_orphan_networks()` 删除这些网络，但这只是兜底。

Linux 生产主机应在 `/etc/docker/daemon.json` 显式扩大地址池，例如：

```json
{
  "default-address-pools": [
    { "base": "10.100.0.0/16", "size": 24 }
  ]
}
```

这会提供 256 个 `/24` 网络。按 `workers × trial_workers` 控制在 100 以内时，单主机有足够余量；多主机各用互不重叠的 `/16`（例如 `10.100`、`10.101`、…），避免路由冲突。修改后需要重启 Docker daemon，并先确认现有网络不与新池重叠。

## 5 存储与清理

每个候选最多三个构建镜像（agent/target/verifier），实测通常 1–2 GB 总量。10k 全量保留会占 10–20 TB，因此生产运行必须：

- 使用 `--prune-images`，在候选进入 `RELEASED`/`QUARANTINED`/`UNSUPPORTED` 后删除该候选镜像；
- 保留 `release/` 任务源码与 `audit.zip`，它们不依赖镜像；resume 会用构建缓存重建；
- 定期清理未使用的 build cache，但不要在批次运行中执行全量 `docker system prune -a`，否则并发中的其他候选会失去基础层缓存；
- 把 `runs/` 与发布包放在本地文件系统或支持可靠文件锁的存储上。共享账本使用进程锁 + 文件锁，NFS/SMB 的锁语义不可靠。

峰值磁盘粗估：

```text
峰值镜像 ≈ 并发候选数 × 2 GB
峰值构建缓存 ≈ 并发候选数 × 1–3 GB
发布包 ≈ 每道题数十 MB × RELEASED 数量
```

10k 全部 `RELEASED` 的发布包按 20–50 MB/题估算为 200–500 GB；这只是任务源码与审计材料，不含镜像。

## 6 多主机 shard

```bash
# 每台主机使用相同输入、不同 shard，输出到各自的 run-id
python -m harbor_pipeline batch \
  --input candidates/cve-2026.json \
  --shard-index 0 --shard-count 8 \
  --run-id cve2026-s0 \
  --profile qualification \
  --workers 8 \
  --prune-images \
  --output-dir /data/harbor-runs
```

规则：

1. `--shard-index/--shard-count` 使用稳定取模，同一 CVE 在重试时仍落在同一 shard；不要在不同主机上复用同一个 `run-id`，除非它们共享可靠的文件锁并且候选集不相交。
2. 每台主机先跑 `--plan-only`，核对 `batch-plan.json` 的候选数与预算；plan-only 不调用模型、不构建镜像。
3. 中断后用同一命令、同一 `run-id`、同一 shard 重启。`state.json` 与 artifact digest 会跳过已完成阶段；被 kill 的进程留下的 lease 会按 pid 回收。
4. 每个 shard 的输出目录独立。汇总时合并各 shard 的 `batch-report.json`、`dataset-manifest.json` 与 `reports/`，不要手工拼接 `budget.json`。
5. 共享候选文件只读；不要把 `budget.json` 放到 NFS。

## 7 成本与产出率

必须分别报告：

- `eligible / inputs`：证据是否足以尝试合成；
- `RELEASED / eligible`：合成与资格验收的真实产出率；
- `UNSUPPORTED / inputs`：不可支持及其量化原因；
- 每道 `RELEASED` 的模型 token、构建次数、trial 数与墙钟。

qual3 的 CVE-2026-87794 合成实测 input `8,964` / output `3,348` token（合计 `12,312`；账本 reservation 曾是 `42,433`，只是上限估计）。该候选的两次模型修复另计：第 2 次 input `320` / output `2,363`，第 3 次 input `8,024` / output `2,806`（第 1 次是 provider 故障，无 usage）；整候选合计 `25,825` token。repair 每次另计一次模型调用；生产 `max_repairs = 2`，单次修复在结构不合法时最多重问 3 次。不要用“每候选固定 3 次调用”估算 13,687 候选的总成本；应以 triage 后的 eligible 数量乘以实测合成/修复分布，并把修复次数分布而不是上限作为均值。

按当前样本，PyPI 与 npm 已有 `RELEASED`，Go 冒烟 `CVE-2026-32758` 因 T04 检出修复版仍泄漏而 `QUARANTINED`（quality `93.0`、17 trials、3 builds、6 calls、`53,095` tokens），该样本 Go 产出率为 `0/1`。不要把 npm/PyPI 的 yield 外推到 Go；Go 目标需要模型真正调用上游 handler，当前模型更容易自写等价逻辑，T04 会正确拒绝。全量 10k 前应按生态分别记录 `RELEASED / eligible`。

PyPI 冒烟 `CVE-2026-24486` 的第一轮（`auto-py-multipart1`）在合成后直接失败：应用导入未声明的 `starlette`，容器启动退出，17 个 trial 均记 `infra_error`，修复器没有介入。加入依赖声明校验与 target preflight 后重跑（`auto-py-multipart2`）：9 builds、5 calls、`65,051` tokens、51 trials，两次修复（#1 input `2,857`/output `1,302`；#2 input `7,850`/output `6,829`），最终 `QUARANTINED`（quality `95.0`，T04 `3/3` 泄漏）。这说明每候选的修复调用次数应按实际分布统计：一次失败合成会把整体 token 从单次合成的 `12k` 级推到 `65k` 级，且仍不一定能发布。preflight 本身只增加一次 `docker run` 与 1–2 秒，远低于一个 trial 的构建与启动成本。

10k 容量规划还应把“应用能启动”与“应用真正可被漏洞利用”分开统计：preflight 只能排除启动类失败（未声明依赖、入口错误），不能保证 T03 成功或 T04 不泄漏。以 PyPI 冒烟为例，preflight 通过后仍因题面设计（直接挂载 symlink）在 T04 被隔离；这类候选的修复成本是整轮矩阵，而不是一次构建。

全量 triage 的外部配额分两段。GitHub 每条候选一次 advisory 查询：匿名 60 次/小时/IP，带 `GITHUB_TOKEN` 为 5,000 次/小时，13,687 条约 2.7 小时，匿名则约 9.5 天。NVD 每条候选一次记录查询：匿名只有 5 次/30 秒，约 22.8 小时，且 429 会被记成 `source_error` 污染产出率统计。启用 `[sources].nvd_feed_cache` 后，NVD 记录改为本地索引查询：2026 feed 83,505 条，建索引实测 8.6s、415 MB，单次查询 1–10 ms；只有快照之后发布的新 CVE 回落 API。批次开始前用 `nvd-cache` 单独构建一次，多个 shard 共享同一目录；剩余外部瓶颈是 GitHub advisory（需要 token）与 registry/修复 commit 抓取，而不是 NVD。

当前补全网关不返回 `usd`，且曾把 8 KB prompt 的输入回报成 134 token。产线会把 `input_tokens` 与两项 cache token 相加，并在回报低于 prompt 长度估算的四分之一时改用估算值（usage 中标记 `input_tokens_estimated`）。因此 `budget.json` 的 token 数是保守记账，不是账单金额；10k 排期必须另外向网关核对单价与真实计费。

## 8 上线检查清单

- [ ] Linux Docker 已配置不重叠的 `default-address-pools`，并重启 daemon。
- [ ] 每台主机 `workers × trial_workers` 的峰值容器数低于内存与地址池上限。
- [ ] 输入 manifest 已用新代码重新 triage，记录 pypi/npm/go/maven/generic 分布。
- [ ] 每个 shard 的 `--plan-only` 预算已核对，`max_repairs` 与 qualification 档位一致。
- [ ] `nvd-cache --year <year>` 已建好索引，`[sources].nvd_feed_cache` 指向 shard 可共享的目录；`GITHUB_TOKEN` 已通过环境变量注入。
- [ ] `--prune-images` 已启用，发布包写入独立持久化目录。
- [ ] 账本与 `runs/` 位于本地文件系统；跨主机只合并报告，不共享账本。
- [ ] 首批 20–50 个候选完成端到端 qualification，记录真实产出率、失败分类与单位成本，再放大到 10k。
