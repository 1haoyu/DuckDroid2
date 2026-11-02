# Runtime 契约：syscall 三态清单

> 最后更新：2026-11-02。这张表的目标不是"列全 Linux"，而是让每个目标的
> 接入结果可比较：同一个 syscall 在四个目标里是完整实现、降级还是不支持，
> 必须能一眼看出来。
>
> 维护规则：新增 handler 时，凡"返回了值但跳过了部分效果"的，必须调用
> `SyscallContext::degrade(reason)`；没有 handler 的自动是 Unsupported。
> `svc.log` 的 note 列会写出三态。

## 三态定义

| 状态 | svc.log note | 含义 | 接入时怎么处理 |
| --- | --- | --- | --- |
| **Supported** | `{}` | 可观察语义已完成 | 不动 |
| **Degraded** | `{"degraded":1,"reason":"..."}` | 返回值看似正常，但已知的效果被跳过；目标可能因此走回退路径 | 看目标输出是否依赖它：不依赖就冻结并记录；依赖就补最小语义 |
| **Unsupported** | `{"unsupported":1,...}` | 没有任何 handler，返回 `ENOSYS` | 同上；涉及网络/进程/信号投递的，升级为设计决策，不顺手实现 |

## 当前 Degraded（代码里显式标记）

| syscall / 分支 | reason | 跳过的语义 |
| --- | --- | --- |
| `rt_sigaction`、`rt_sigprocmask`、`sigaltstack` | `signals are not delivered` | 信号处理函数、屏蔽字、备用栈都没有真正生效 |
| `kill`、`tkill`、`tgkill` | `signals are not delivered` | 返回 0，但没有投递；目标的"自检信号"探测会走正常路径 |
| `clone` 且缺 `CLONE_VM\|CLONE_THREAD` | `clone without CLONE_VM\|CLONE_THREAD` | 进程级 clone（fork/vfork，例如 `popen` 的 `posix_spawn` 探测）返回 `EINVAL`，目标走回退 |
| `futex` `WAIT_BITSET`/`WAKE_BITSET`，mask ≠ `0xffffffff` | `futex bitset mask is ignored` | 等待队列不按 bit 匹配；mask 全 1（bionic condvar 的常见值）视为完整实现 |
| `fcntl` `F_GETLK`/`F_SETLK`/`F_SETLKW` | `file locks are not modelled` | 没有锁管理器，`GETLK` 永远报告未加锁 |
| `fcntl` `F_SETFL` | `fcntl F_SETFL flags are not tracked` | `O_NONBLOCK` 等标志不保存，读仍按阻塞语义处理 |
| `prctl`（除 `PR_GET_NAME`、`PR_SET/GET_TAGGED_ADDR_CTRL`） | `prctl option is accepted but not modelled` | `PR_SET_NAME`、`DUMPABLE`、`NO_NEW_PRIVS` 等返回 0 但不改状态 |
| `set_robust_list` | `robust futex list is not modelled` | 注册被接受，线程退出时不按 robust list 唤醒/置位 |

## 当前 Unsupported（主要家族）

以下是"没有 handler，直接 ENOSYS"的典型条目；实际以 `svc.log` 为准。

- **网络**：`socket`、`bind`、`connect`、`listen`、`accept`、`sendto`、`recvfrom`、
  `getsockopt`、`setsockopt`、`shutdown`。得物 6.1.5.10 实测只调一次
  `socket(AF_INET, SOCK_STREAM, 0)`，结果无关，维持 ENOSYS。
- **进程**：`fork`、`vfork`、`execve`、`wait4`、`setpgid`、`getpgid`。
  进程级 clone 走上面的 degraded 分支。若目标依赖子进程成功，应在 Worker
  层实现，不改线程调度器。
- **io 变体**：`readv`、`writev`、`preadv`、`pwritev`、`sendfile`、`splice`、
  `tee`。`pread64`/`pwrite64` 已实现（M10）。
- **futex 其他操作**：PI、requeue、`*_OP`。
- **其余 ioctl 请求**：`ioctl(2)` 本身是 Supported（打开的 fd 返回 `ENOTTY`，
  未知 fd 返回 `EBADF`），但没有任何请求被具体建模。

## VFS 语义（M10）

固定的命名空间：`/` = `OverlayFs(upper=可写沙箱, lower=只读宿主根…)`，
`/proc` = `ProcFs(宿主快照优先 + 合成回落)`，`/dev`、`/dev/__properties__`
= 合成只读挂载。匹配按 guest 路径最长前缀。

- **覆盖层**：读按 upper → lower 顺序；变更只落 upper。
  - 只在 lower 的删除/重命名/写意图 open → `EROFS`。
  - 删除 upper 且 lower 同名 → 记录实例内内存白障，lower 副本不再出现；
    实例回收 = 换进程，白障不持久化。
  - 跨挂载 `renameat` → `EXDEV`；同挂载 rename 不改变 `st_ino`。
  - `O_CREAT` 命中 lower 时复制到 upper 并遮蔽；`O_EXCL|O_CREAT` 命中
    lower → `EEXIST`；无 `O_CREAT` 的写意图 → `EROFS`。
- **身份**：宿主节点用宿主 `st_dev/st_ino`；合成节点用
  `hash64(mount_id, guest_path)`。`getdents64` 的 `d_ino` 与随后
  `fstatat` 的 `st_ino` 一致。
- **目录**：`open` 目录得到快照描述（首次打开时快照，关闭即释放）。
  `getdents64` 的 `d_off = index+1`；部分 buffer 不消费未写出的条目；
  首条放不下 → `EINVAL`；EOF → 0；`lseek(fd, 0, SEEK_SET)` 复位；
  `dup` 共享游标。子挂载点（`/proc`、`/dev`、`/dev/__properties__`）会
  出现在父目录列表里。
- **dirfd**：`openat/fstatat/faccessat/unlinkat/renameat/mkdirat/readlinkat`
  接受目录 fd；`AT_FDCWD` 表示 `/`；非目录 fd → `ENOTDIR`，未打开 → `EBADF`；
  `..` 在根处夹断。
- **stdio**：0/1/2 是描述符表里的永久条目；`close(0/1/2)` 返回 0 但不丢弃，
  `dup(1)` 共享宿主 stdout，`F_GETFL` 返回真实访问模式与 `O_APPEND`。
- **错误保真**：后端在入口只翻译一次 errno，可写 open 不再折叠成 `EACCES`；
  `ENOENT/EISDIR/EROFS/EEXIST/EXDEV` 都可区分。`renameat2` 已支持 flags=0
  的形式（现代 bionic 的 `rename(3)` 会用到）。

## 已知的"值级近似"（未标 degraded）

这些不是跳过了效果，而是编造了一个合理值。接入新目标时如果发现输出对不上，
优先怀疑这一组：

- `getppid()` → 0
- `getrlimit()` / `prlimit64()` → 无穷大
- `sched_getaffinity()` → 单 CPU mask
- `getcwd()` → `/`
- `ioctl()` → 对所有普通/合成 fd 都是 `ENOTTY`

## 接入新目标的固定流程

1. 跑一次目标，产出 `svc.log`。
2. 提取 `"unsupported":1` 与 `"degraded":1` 两类。
3. 每条按三态表处理：
   - 结果无关 → 冻结为当前行为，写进本文件的对应表；
   - 结果相关、代价小 → 补最小语义，并把标记去掉；
   - 涉及网络/进程/信号投递/抢占 → 单独设计，不在接入 PR 里顺手做。
4. gate 里加断言：关键 syscall 的 `SvcSupport` 不能是 Unsupported/Degraded
   （例如 `07g_dy7_plugin` 已经断言 JNI 面零 Unsupported）。
