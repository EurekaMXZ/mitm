# AGENTS.md

此文件用于规范、约束 Agent 行为，文件作用域为整个项目，任意深层的 `AGENTS.md` 均可修改并覆盖此文件的部分规则。

## 项目范围

当前仓库只开发 Rust core。core crate 必须位于 `core/` 目录，包名固定为 `mitm-core`。

Windows、Linux、Android 接入、证书安装、系统代理设置、UI、规则编辑界面和平台集成模块均不属于当前开发重点。相关目录可以存在，但当前阶段只围绕 `mitm-core` 开发。

## 开发参考文档

开发前必须先扫描 `docs/` 目录下的所有文档，再阅读与本轮任务相关的内容。`docs/TODO.md` 和 `docs/PROPOSAL.md` 是每次开发都必须阅读的核心文档。开始任何代码修改前，必须把这两个文档作为恢复上下文和核对设计依据的固定入口。

1. `docs/TODO.md`
   - 查看“当前开发状态”。
   - 查看当前阶段任务清单。
   - 开发前同步当前重点、下一步和阻塞项。
   - 开发结束后勾选完成任务并更新状态。

2. `docs/PROPOSAL.md`
   - core 架构设计提案。
   - handler chain、Decision、HandlerContext、SOCKS5、TLS MITM、HTTP body、Lua hook、upstream、测试策略均以该文档为设计依据。

3. `AGENTS.md`
   - 当前文件，记录协作规则、可执行命令和开发前后动作。

如果 `docs/` 下新增文档，例如设计补充、测试说明、协议说明或阶段计划，开发前必须先确认其是否与本轮任务相关。相关文档需要在动手前阅读，避免基于过期上下文开发。

如果文档与代码产生冲突，先更新文档中的当前状态或提出需要确认的问题，再继续修改代码。

## 开发前必须做的事情

每次开始代码开发前执行以下步骤。即使只是继续上一轮未完成任务，也必须重新执行文档阅读步骤：

1. 执行 `rg --files docs` 或等价命令，确认 `docs/` 下当前有哪些文档。
2. 完整读取 `docs/TODO.md`，重点查看“当前开发状态”、当前阶段清单、下一步和阻塞项。
3. 完整读取 `docs/PROPOSAL.md`，重点查看本轮任务涉及的架构契约、模块职责和验收要求。
4. 阅读 `docs/` 下与本轮任务相关的其他文档。
5. 确认当前阶段与本轮要完成的 checkbox 任务。
6. 使用 `git status --short` 检查工作区，确认是否存在其他未提交或未跟踪文件。
7. 如果本轮任务会修改阶段状态，先更新 `docs/TODO.md` 的：
   - `当前阶段`
   - `当前重点`
   - `下一步`
   - `阻塞项`
   - `最后同步时间`
8. 如果遇到上下文压缩、会话恢复或任务切换，重新执行以上步骤。

## 开发后必须做的事情

每次结束代码开发后执行以下步骤：

1. 更新 `docs/TODO.md` 的“当前开发状态”。
2. 对实际完成且验证通过的任务勾选 checkbox。
3. 未完成或未验证的任务保持未勾选，并补充简短状态说明。
4. 更新 `最近完成`、`下一步`、`阻塞项`、`最后同步时间`。
5. 运行本轮任务对应的验证命令。
6. 使用 `git status --short` 检查最终变更。
7. 在最终回复中说明：
   - 修改了哪些文件。
   - 完成了哪些 TODO。
   - 执行了哪些验证命令。
   - 哪些验证未执行以及原因。

## 可执行命令

仓库尚未创建 Rust workspace 前，可以执行：

```powershell
git status --short
rg --files
rg --files docs
Get-ChildItem -Force
Get-Content -Raw docs/TODO.md
Get-Content -Raw docs/PROPOSAL.md
```

Rust workspace 创建后，优先使用以下命令：

```powershell
cargo fmt --all
cargo fmt --all -- --check
cargo test --workspace
cargo test -p mitm-core
cargo check -p mitm-core
cargo clippy --workspace --all-targets -- -D warnings
cargo metadata --format-version 1
```

如果 `cargo` 命令因为依赖下载、索引访问或缓存目录权限失败，应请求授权提升后重试。禁止通过把 `CARGO_HOME`、`pnpm-store` 等缓存目录迁移到项目目录来绕过权限问题。

## 代码组织约束

1. Rust core 只放在 `core/` 目录。
2. `core/Cargo.toml` 的 package name 必须是 `mitm-core`。
3. 根 `Cargo.toml` 只作为 workspace 管理入口。
4. 当前阶段不实现平台接入模块。
5. core 对外 API 应以 `docs/PROPOSAL.md` 的“公开 API 边界”为依据。
6. handler chain、Decision、状态机、TLS MITM、Lua hook、body 状态机的实现必须优先参考 `docs/PROPOSAL.md`。
7. 每个阶段完成前必须补齐对应单元测试或集成测试。

## 文档维护约束

1. 任何会改变开发阶段、任务优先级或架构契约的修改，都需要同步 `docs/TODO.md` 或 `docs/PROPOSAL.md`。
2. 新增任务必须加入 `docs/TODO.md` 对应阶段，或新增阶段。
3. 只有实际完成并通过验证的任务才能勾选。
4. 如果实现与提案产生偏差，需要在同一轮修改中更新 `docs/PROPOSAL.md` 的对应章节。
5. 上下文压缩后，以 `docs/TODO.md` 的“当前开发状态”为恢复依据。
