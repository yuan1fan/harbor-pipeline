# 0.2 容量与验收成本

0.1 的历史批次是 20 个候选、17 个发布，但那批结果使用旧验证协议，不能直接换算成 0.2 的产出率。0.2 增加了运行时依赖身份、候选级负例、干净重建、分层质量抽样和独立复核字段；本文件给出单候选的最小 trial 预算、质量抽样方法和 10k 规模的分片方式。

## Trial 预算

| 项目 | 最小 trial 数 |
| --- | ---: |
| T03/T04 成对（含确认重复） | 6 |
| T05/T06/T07/T10 候选级负例 | 4 |
| T09 干净重建（3 seeds × vulnerable/fixed） | 6 |
| T11/T12 | 2 |
| **合计** | **18** |

T01/T02 由 T03/T04 的 trial 记录推导，不再单独起容器。T09 现在使用 `--no-cache` 重建 vulnerable 与 fixed 两个 variant，并记录实际 image ID；复用预构建镜像不再算作干净重建。上表是最小 blocking 集合，策略要求的重复次数会继续放大成对样本，实际预算以 `batch-plan.json` 为准。

除 trial 外，每个候选还有：

- 一个原生 author 会话，以及 helper 的 build/probe/exec 次数上限；
- 可选的 solver 试次（Harbor `claude-code` agent）和 reviewer 结构化评审；
- 发布阶段的不可变副本 oracle 重放。

这些成本计入 USD、token 与 wall-clock，但不计入上表的 18 个 trial。

## 质量抽样

发布率不能当作“真实复现准确率”。运行结束后用 `quality` 对 RELEASED 包做分层抽样，并单独统计独立复核结果：

```bash
python -m harbor_pipeline batch --input candidates/cve-2026.json --shard-index 0 --shard-count 8 \
  --run-id capacity-s0 --profile qualification --workers 1 --trial-workers 1 --plan-only

python -m harbor_pipeline quality --run-dir runs/capacity-s0 \
  --output work/capacity-quality.json --sample-size 30 --seed 0
```

报告按 ecosystem × goal-family 轮转抽样，分别给出候选状态、失败类别、release 率、独立复核的接受数与 Wilson 区间。没有 `--review-file` 时，独立正确率必须写 `null`，不能用发布率填充。

## 并发与内存

`workers × trial_workers` 决定容器峰值：每个 trial 至少起 target、verifier main、fixed-runner/target-fixed 等容器，还可能有 observer。Windows Docker Desktop 的 WSL VM 有硬内存上限，出题批次应保持 `workers = 1`、`trial_workers = 1`；提高并发前先用 `preflight` 检查内存预算和可回收磁盘。

## 分片与数据集合并

大规模运行用稳定取模分片，同一 CVE 在重试时仍落在同一 shard：

```bash
python -m harbor_pipeline batch --input candidates/cve-2026.json \
  --shard-index 0 --shard-count 8 --run-id capacity-s0 --profile qualification
```

各 shard 完成后先用 `dataset-merge` 重新计算全局划分，不要直接拼接局部 manifest：

```bash
python -m harbor_pipeline dataset-merge \
  --input runs/capacity-s0/dataset-manifest.json runs/capacity-s1/dataset-manifest.json \
  --output work/dataset-v2.json
```

合并时按归一化后的项目身份、仓库、修复 commit/patch 和 CVE alias 建连通分量，再按分量划分 train/validation/test（数据集版本 `2026.11.2`）。不同任务版本、旧协议条目或同族跨集合冲突会被拒绝或报告，不能静默合并。
