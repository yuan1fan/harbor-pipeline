# 磁盘与并发资源管理

2026 年 11 月 16 日对 `scale-100-open-20261108` 的现场检查发现，主要空间增长来自 Docker 镜像和虚拟磁盘，而不是题目日志。改动不降低 T01–T12 验收要求，也不减少正式试验次数。

## 现场基线

| 项目 | 清理前读数 |
| --- | --- |
| 物理内存 | 31.8 GiB |
| WSL 内存上限 | 20 GB 配置，Docker 报告约 19.5 GiB |
| C 盘可用空间 | 约 52.7 GiB |
| D 盘可用空间 | 约 102.1 GiB |
| Docker 数据文件 | `C:\Users\lishu\AppData\Local\Docker\wsl\disk\docker_data.vhdx`，213.5 GiB，非 sparse |
| Docker 镜像 | 200 个，Docker 汇总 190.4 GB，其中 180.4 GB 标记可回收 |
| BuildKit 缓存 | 20.34 GB |
| 本轮 run 文件 | 约 0.269 GiB |
| 本轮状态文件 | 22 RELEASED、40 QUARANTINED、34 UNSUPPORTED、2 GENERATED |

Docker 的 GB 汇总和 Windows 文件大小的 GiB 不能直接相减，镜像之间还可能共享层。“可回收”也包含其他项目资源，不能直接执行全局 `system prune -a --volumes`。

## 本次处理结果

已删除 135 个已结束候选的遗留镜像标签，清理无错误。Docker 镜像数量由 200 降至 65，汇总大小由 190.4 GB 降至约 150 GB。完成 TRIM、Docker／WSL 停机和离线压缩后，VHDX 由 213.50 GiB 降至约 173.45 GiB，C 盘可用空间由约 52.4 GiB 增至约 92.7 GiB。空间回收发生在清理与停机维护整体流程中，不能全部归因于最后一条 DiskPart 命令。

维护后曾恢复并检查原服务；用户随后要求所有容器保持关闭，最终以零运行容器为目标。清理明细位于 `runs/scale-100-open-20261108/storage-cleanup.json`，维护与最终状态记录位于 `work/resource-maintenance-20261116/`。上述目录按现有规则不进入 Git。

代码全套回归为 351 项通过、4 项需显式启用 Docker 的集成测试跳过。资源测试覆盖跨进程并发上限、进程退出回收、内存／磁盘压力等待、嵌套操作、子进程配置传递，以及镜像清理的所有权、发布制品保护和标签变化保护。实际模型批次的吞吐提升需后续测量。

## 修复内容

原清理逻辑只读最后一次 `image-set.json`。在写入该文件之前失败、只由 author 构建、或来自早期修订的镜像不会被清理。现在按终态候选扫描全部修订，并给新构建添加所有者标签，覆盖后续产生的无标签旧版本和干净重建镜像。启用 `prune_images` 时，每次成功构建还会回收同候选已经被覆盖、没有标签、没有容器引用且不属于 release 的旧镜像，避免长时间 author 会话把旧镜像一直留到最终结束。

清理始终保留以下对象：任何容器引用的镜像、公共基础镜像、其他项目镜像、其他 run 拥有的镜像、未完成或持有活动 lease 的同 CVE 候选，以及 release manifest 记录的精确镜像 ID。删除前重新检查标签身份和候选状态，使用不带 `--force` 的 image rm。来源、题目、日志、轨迹、报告和发布包文件不参与删除。

正式发布镜像会随题库规模增加，需要独立的存储容量与归档预算。本次修复控制的是中间产物和失败构建的泄漏；长期规模化运行应将精确发布制品归档到容量充足的存储，再设置明确的保留策略。

BuildKit 缓存仍按 `build_cache_keep_gb` 做最佳努力清理；它是 Docker daemon 共享缓存，不能理解成某个 CVE 的精确空间配额。已取消全局 dangling image prune，避免误删其他项目的未打标签镜像。Docker 的缓存 GC 与最终镜像是不同生命周期，见 [Docker 缓存回收说明](https://docs.docker.com/build/cache/garbage-collection/)。

新资源队列将模型候选并发与 Docker 重资源阶段分开。构建、运行检查、author probe 和 Harbor job 在进入执行前获取跨进程槽位；author helper 通过受控环境变量继承同一个绝对路径队列。队列按 FIFO 放行，回收已退出进程的记录，在宿主可用内存或监测磁盘低于水位时等待，超时记基础设施错误。

Harbor 的内部 `n_concurrent_trials` 也受总槽位限制，避免候选数乘以 trial 并发数再次放大。在资源模式下，author 进入 build/probe 前释放两个持久 debug target；scratch 工作区保持原语义。probe 即使写日志失败也执行 compose down。仍在等待模型的 author 客户端、持久 scratch/debug 服务和其他项目会消耗额外内存，槽位数不是整机内存硬上限。

两个批次脚本原先只用 `--output-dir` 决定进度和日志位置，没有传给实际 pipeline；现在传递到子进程。进度脚本恢复批次时追加日志，避免覆盖前一轮记录。

## 推荐运行方式

启动前可以只检查本地配置，确认连接设置已能加载：

```powershell
python -m harbor_pipeline -c pipeline.scale.toml check-config
```

`pipeline.scale.toml` 已启用 `inherit_claude_settings = true`。当当前 shell 完全没有连接覆盖时，CLI 从用户的 `~/.claude/settings.json`（设置了 `CLAUDE_CONFIG_DIR` 时使用该目录）读取 `ANTHROPIC_BASE_URL` 和匹配的认证变量，仅用于当前进程及其子进程。不会导入其他环境变量、模型覆盖、权限或 hooks，也不会把凭据写入日志。若 shell 已设置连接组中的任一变量，保留整个显式配置，不将保存的密钥与另一个端点自动拼接；此时应在 shell 中提供完整匹配的连接设置。

`check-config` 只验证本地配置和环境展开，不验证远端 API 可用性，也不会启动 Docker 或模型会话。普通配置默认关闭此继承选项。批次进度脚本遇到异常退出会显示 `failed`、退出码和本次日志末尾；历史状态不会再被当作这次成功完成，实际批次报告文件名为 `batch-report.json`。

`pipeline.scale.toml` 已启用如下配置，其他配置默认 `docker_slots = 0`，保持旧行为：

```toml
[pipeline]
trial_workers = 1
docker_slots = 2
resource_dir = "work/resources"
min_free_memory_mb = 4096
min_free_disk_gb = 15
resource_wait_sec = 7200
```

模型候选数可以先从 6 开始，观测稳定后再试 8；构建和验证同时最多占用 2 个槽位。这样可以重叠模型等待时间，不能保证 8 道题同时运行整套容器，也未对本机做付费模型吞吐压测。Java、浏览器等高内存任务应继续下调 Docker 槽位或使用更大／独立的 worker 主机。

```powershell
python -m harbor_pipeline -c pipeline.scale.toml preflight --workers 6 --trial-workers 1 --task-memory-mb 4096 --min-free-gb 15
python scripts/run_batch_progress.py --config pipeline.scale.toml --input candidates/sample-100-open-20261108.json --run-id scale-100-open-20261108 --workers 6 --trial-workers 1
```

恢复前应核对原始输入清单；若原批次使用 triage 后的清单，继续使用同一文件。模型凭据与原运行环境相同，不在配置或文档中保存。`work/resources/docker-queue.json` 显示正在执行、等待的 PID、操作类型和等待原因；活跃运行中不要删除或另换队列目录。不同批次／分片必须使用同一个本机队列目录才能共享额度。

默认监测产物所在卷和 Windows 默认 Docker 数据目录所在卷。如果 Docker 已迁到其他目录，通过 `resource_disk_paths = ["D:/DockerData"]` 加入实际数据卷。检测的是宿主卷空闲空间，不是 Docker 虚拟文件系统内的可用容量；远程 Docker 主机还需在远端独立监测。

## Author 模型连接

默认 `author_runtime = "container"`。worker 在宿主随机端口启动一个仅本次调用有效的服务：

- `GET/POST /model/...` 是模型代理。worker 从原有连接配置读取上游地址和凭据，容器内的 `ANTHROPIC_BASE_URL` 指向 `http://<host.docker.internal>:<port>/model`，`ANTHROPIC_API_KEY` 是随机生成的本次调用凭证；
- `POST /helper` 是 helper RPC。容器内的 `harbor-author` 只是客户端，实际 `validate/build/probe/debug/submit` 由宿主执行，并绑定当前候选与 revision。

宿主缺少凭据时会在启动 author 前报错。author 容器的 egress 防火墙只放行本机服务地址和端口、本题 debug 靶机 IP 以及公网，拒绝宿主局域网和私网地址；容器没有 Docker socket。

`author_runtime = "host"` 时使用旧的 `127.0.0.1` 回环模型代理，author 在宿主受限运行，通用命令通过 `harbor-author shell` 进入 scratch 容器。两种模式的上游都必须是 HTTPS，本机回环服务可以使用 HTTP。

两种模式都转发 Messages 与 token counting 请求，保留 API 版本、beta 标记和 SSE 流式响应，不跟随上游重定向。容器服务把请求的 `model` 固定为 `models.author.model`，并发上限为 2，每次调用最多 `max(32, 8 × max_turns)` 次请求；host 模式回环代理检查模型、按 `max_output_tokens` 限制单次生成，并分配 `4 × max_turns` 次请求。worker 结束调用时撤销凭证、关闭端口并中断活动连接。宿主账户对文件和进程的访问权限仍由操作系统控制。

容器模式下，每个候选有独立的 `harbor-author-<owner>-home` volume，挂载到容器的 `/home/node`；CLI 配置和会话历史在 `/home/node/.claude`。容器在会话之间停止但不删除，`runs/<run>/<CVE>/author/.harbor/runtime.json` 保存容器名、lab/egress 网络、镜像和最近的 session ID，`--resume` 复用同一容器和同一对话。候选进入 `RELEASED` / `UNSUPPORTED` 时删除容器、网络和 home volume。

host 模式下 CLI 配置和会话历史放在 `runs/<run>/<CVE>/author-cli/.claude/`。恢复旧版会话时，worker 按 session ID 和工作目录匹配宿主默认 CLI 目录中的对话记录，只复制该会话的 JSONL。可以在安装了 Claude Code 的机器上设置 `HARBOR_TEST_CLAUDE_CLI=1`，运行 `python -m pytest tests/test_author_model_proxy.py`，用本地模拟上游检查 host 模式真实 CLI 的首次调用和恢复。

## 检查和清理旧批次

```powershell
# 默认只预览，无需模型配置和 API 凭据。
python -m harbor_pipeline storage --run-dir runs/scale-100-open-20261108

# 应用限定范围的清理，记录到该 run 的 storage-cleanup.json。
python -m harbor_pipeline storage --run-dir runs/scale-100-open-20261108 --apply

docker system df
```

自动批次清理写入各候选的 `storage-cleanup.json`。旧 run 的同名 CVE 若仍标记未完成，将保守阻止其历史镜像清理；先核实该 run 的状态，再处理它，不要绕过保护。更早版本已经删除的精确发布镜像无法由清理功能恢复；重新构建后仍需按既有协议验证身份。

## Windows 虚拟磁盘回收

Docker 删除镜像释放的是 Linux 文件系统内部空间。非 sparse VHDX 的文件大小可能保持不变，之后构建可以复用内部空闲块，但 C 盘可用空间未必立即增加。

当前 `.wslconfig` 的 `autoMemoryReclaim=gradual` 原先位于 `[wsl2]`，已迁至 `[experimental]`，原文件备份为 `work/wslconfig-before-20261116.ini`。它用于回收闲置内存缓存，需要下一次 WSL 完全停止后重启生效；不能代替磁盘压缩。[微软 WSL 配置说明](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

需要立刻返还 C 盘空间时，先安排 Docker／WSL 停机窗口，保存当前容器清单和恢复方法，再退出 Docker Desktop 并停止 WSL。提供的脚本默认只预览；`-Apply` 要求管理员 PowerShell、相关进程已停止且磁盘未锁定。优先使用 `Optimize-VHD`，未安装对应模块时使用 Windows 自带的 DiskPart：

```powershell
powershell -NoProfile -File scripts/compact_docker_disk.ps1
# 仅在完成停机准备后执行：
powershell -NoProfile -File scripts/compact_docker_disk.ps1 -Apply
```

该脚本不会停止服务或搬迁磁盘。维护后需要恢复原运行容器并检查健康状态。DiskPart 分支仅选择已检查的 Docker 数据文件并压缩，依据微软的 [compact vdisk](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/compact-vdisk) 离线流程执行。

Docker 数据盘迁移使用 Docker Desktop 的 Settings → Resources → Advanced 中的存储位置配置。[Docker WSL 存储位置说明](https://docs.docker.com/desktop/features/wsl/) 仅搬迁 `runs` 目录不能迁移 Docker VHDX。当前 D 盘可用约 102 GiB，小于清理前 213.5 GiB 的数据文件，迁移前必须先压缩并验证目的卷空间，不应直接移动正在挂载的 VHDX。
