# mitm-core TODO

## 当前开发状态

本节用于在上下文压缩、会话切换或多人协作时保留开发状态。每次开始开发前必须先读取并同步本节；每次结束开发后必须更新本节和下方阶段清单。

```text
当前阶段：阶段 3 Task 3B 质量审查修正已完成
当前重点：第三阶段已完成最终验证与双 reviewer 复审，当前重点转入阶段 4 的 HTTP/1.1 明文适配准备
最近完成：已实现 Session 基础类型、SOCKS5 method negotiation、no-auth、CONNECT 解析、reply code 映射、阻塞式 SOCKS5 ingress、SessionInit 前置策略执行点和 close reason 记录；已补充 SOCKS5 ingress 普通 I/O 错误、domain、IPv6 和 unsupported ATYP 覆盖测试；已实现阶段 2 Task 2 的 Handler 基础类型、Intercept 基础类型、最小 AuditEvent、Decision 与 Patch 阶段合法性校验，并补充 Decision 适用矩阵测试；已完成阶段 2 Task 3 的 HandlerContext、StreamSlot、Tag 派生、线性 chain runner、非法 Decision 审计事件和状态迁移测试；已修正 Task 3 审查反馈中的 Pause 停止语义、Session 强状态 getter、runner 当前阶段校验说明、TagSet 单值命名空间覆盖、runner 阶段权威来源和多余 Decision 复制；已删除 docs/superpowers 目录；阶段 3 Task 1 已完成同步 PeekBuffer 与 ReplayStream 基础实现，并补充前缀顺序回放、分段读取、一次性消费测试；已修正 Task 1 功能审查反馈中的 PeekBuffer 单次读取语义与 ReplayStream prefix 优先返回语义；阶段 3 Task 2 已完成 HTTP/1、TLS ClientHello、h2c prior knowledge、Raw TCP 分类基础，h2c 与 Raw TCP 当前进入 RawTunnel 模式，TLS 仅记录协议提示；阶段 3 Task 3A 已完成 StreamSlot 真实 stream 所有权容器、ctx.stream 分类读取入口、NeedMore/Complete 纯函数结果、handler 层读取结果控制语义、PeekBuffer::from_vec、ReplayStream Write 委托和 loopback TcpStream replay 完整字节序测试；阶段 3 Task 3B 已完成同步阻塞版 RawTunnelHandler、raw_tunnel_report、会话级 `UpstreamConnectFailed` 与 `TunnelIoError` 关闭原因映射、首事件关闭归因保留规则，以及稳健的 raw tunnel upstream connect fail 与首事件保留测试；本轮已完成 `cargo fmt --all`、`cargo fmt --all -- --check`、`cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`，并完成功能性审查与代码质量审查回收
下一步：进入阶段 4，围绕 HTTP/1.1 request/response 解析、捕获与 HttpAdapter 事务循环开展实现；阶段 3 的补充测试项纳入后续补强
阻塞项：无，保留若干非阻塞测试补强项
最后同步时间：2026-05-01
```

## 开发状态维护规则

1. 开发前执行 `rg --files docs` 或等价命令，确认 `docs/` 目录当前文档列表。
2. 开发前完整读取 `docs/TODO.md`，重点查看“当前开发状态”和当前阶段清单。
3. 开发前完整读取 `docs/PROPOSAL.md`，重点查看本轮任务涉及的架构契约、模块职责和验收要求。
4. 开发前阅读 `docs/` 目录下与本轮任务相关的其他文档。
5. 开发前更新“当前重点”“下一步”“阻塞项”，保证本轮工作目标可追踪。
6. 开发中如果调整范围，需要同步更新当前阶段的任务描述或新增任务。
7. 开发后勾选完成的 checkbox，并更新“最近完成”“下一步”“阻塞项”“最后同步时间”。
8. 如果任务部分完成，保持 checkbox 未勾选，并在该任务后补充简短状态说明。
9. 如果新增阶段或重排优先级，需要保持阶段编号稳定，避免历史记录失去参照。
10. 只在任务实际完成并通过对应验证后勾选 checkbox。

## 阶段 0：项目骨架与开发约束

目标：建立 Rust workspace、`core/mitm-core` crate 骨架、开发文档和最小验证命令。

- [x] 编写 `docs/PROPOSAL.md`，明确 core 架构、handler chain、TLS MITM、Lua hook、upstream、body、测试策略。
- [x] 编写 `docs/TODO.md`，建立阶段任务与状态同步机制。
- [x] 补充根 `AGENTS.md`，明确开发前后动作、参考文档和可执行命令。
- [x] 明确每次开发前必须扫描 `docs/` 并阅读 `docs/TODO.md`、`docs/PROPOSAL.md` 和相关补充文档。
- [x] 创建根 `Cargo.toml` workspace。
- [x] 创建 `core/Cargo.toml`，包名为 `mitm-core`。
- [x] 创建 `core/src/lib.rs` 与初始模块声明。
- [x] 建立基础 crate 级 lint、format 和 test 命令。
- [x] 添加最小 smoke test，验证 crate 可编译。
- [x] 补充 GitHub Actions 基础 CI，运行 rustfmt、metadata、check、test 和 clippy。

## 阶段 1：SOCKS5 与 Session 基础

目标：实现 SOCKS5 TCP `CONNECT` 接入，建立 Session 生命周期与基础事件。

- [x] 定义 `SessionId`、`TransactionId`、`FlowId`、`TargetAddr`、`IngressSource`。
- [x] 定义 `SessionState`、`ProcessingMode`、`ProtocolHint`、`TlsPolicy`、`ApplicationProtocol`。
- [x] 实现 SOCKS5 method negotiation。
- [x] 实现 SOCKS5 no-auth。
- [x] 预留 username/password auth 结构。
- [x] 实现 SOCKS5 `CONNECT` 请求解析，支持 IPv4、IPv6、domain。
- [x] 实现 SOCKS5 reply code 映射。
- [x] 实现 `SessionInitHandler` 前置策略执行点。
- [x] 实现 SOCKS5 success 回复时机：连接级策略通过后再回复 success。
- [x] 实现 session close reason 记录。
- [x] 添加 SOCKS5 negotiation、auth、CONNECT parser 单元测试。
- [x] 添加 `curl --socks5-hostname` 明文 HTTP smoke test 方案。
- [x] 补充 SOCKS5 ingress 普通 I/O 错误保持为 `Socks5IngressError::Io` 的测试。
- [x] 补充 SOCKS5 ingress domain、IPv6 成功路径与 unsupported ATYP 错误映射测试。

## 阶段 2：Handler 契约与线性 SessionChain

目标：实现线性 handler chain 的调度基础，固定 `Decision`、`HandlerOutcome`、`HandlerContext` 的职责边界。

- [x] 定义 `Decision`、`PatchSet`、`PatchOp`、`DropSpec`、`InterceptSpec`、`ResumeDecision`。
- [x] 定义 `HandlerOutcome` 与 `HandlerResult`。
- [x] 实现 chain runner，统一应用 `Decision`。
- [x] 实现 `HandlerContext` 与 `StreamSlot` 基础结构。
- [x] 实现标签派生规则，确保强类型状态为权威来源。
- [x] 实现 `SetRawTunnel`、`SetTlsMitm`、`SetTlsBypass` 的合法阶段校验。
- [x] 实现非法 `Decision` 拒绝与审计事件。
- [x] 添加 Decision 适用矩阵单元测试。
- [x] 添加状态迁移与标签派生单元测试。

## 阶段 3：协议识别、PeekBuffer 与 Raw Tunnel

目标：实现 TCP 首包识别、统一 replay buffer、Raw TCP 透传。

- [x] 实现 `PeekBuffer` API。（Task 1 已补充同步 `Read` 版本基础实现与行为测试；Task 2 已补充 `into_vec` 所有权转移接口；Task 3A 已补充 `from_vec`。）
- [x] 实现 `ReplayStream`，保证已读字节按原始顺序回放。（Task 1 已补充同步 `Read` 版本基础实现与行为测试；Task 2 已将拆出接口调整为 `try_into_inner`，剩余前缀存在时返回原 replay stream；Task 3A 已补充 `Write` 委托。）
- [x] 实现 `ProtocolClassifierHandler`。（Task 3A 已改为从 `ctx.stream` 持有的真实 downstream `TcpStream` 读取 prefix；审查修正已补充分层读取结果与失败停止语义。）
- [x] 识别 HTTP/1.1 方法前缀。
- [x] 识别 TLS ClientHello 前缀。
- [x] 识别 h2c prior knowledge，并按首版策略进入 raw tunnel 或 unsupported。
- [x] 将 `ProtocolHint::RawTcp` 映射到 `ProcessingMode::RawTunnel`。
- [x] 将 `StreamSlot` 调整为真实 downstream stream 所有权容器，并补充所有权移动辅助方法。
- [x] 分类纯函数区分数据不足结果，短前缀保持 `NeedMore`。
- [x] 实现 `RawTunnelHandler` 的 upstream TCP 连接与双向复制。
- [x] 实现 raw tunnel 字节计数、耗时、关闭原因。
- [x] 添加 HTTP/1、TLS、h2c、Raw TCP 分类测试。（Task 3A 已改为 loopback `TcpStream` 驱动 handler；审查修正已改为通过 `ReplayStream` 校验完整字节序。）
- [x] 添加 replay buffer 顺序与一次性消费测试。
- [x] 添加 raw tunnel 回放首包测试。
- [ ] 补充 `ProtocolClassifierHandler` 在 `NeedMore`、`LimitExhausted`、`IoError` 三类结果下的 handler 级停止语义测试。（审查后补强项）
- [ ] 补充 `StreamSlot::TlsClientHelloParsed` 进入 `RawTunnelHandler` 时的回放测试。（审查后补强项）
- [ ] 补充 `RawTunnelHandler` 的 `ClientClosed` 与 `TunnelIoError` 关闭原因测试。（审查后补强项）

## 阶段 4：HTTP/1.1 明文捕获与透传

目标：实现明文 HTTP/1.1 request/response 解析、捕获、透传和 keep-alive transaction 循环。

- [ ] 定义 `HttpRequestView`、`HttpResponseView`、`HttpMessageView`。
- [ ] 实现 raw header 保存，保留 header 顺序、大小写、重复 header。
- [ ] 实现语义化 request/response 视图。
- [ ] 实现 `HttpAdapter` transaction 循环。
- [ ] 实现 request head/body 读取。
- [ ] 实现 response head/body 读取。
- [ ] 支持 `Content-Length` body。
- [ ] 支持 `Transfer-Encoding: chunked` 基础解析与序列化。
- [ ] 实现 HTTP/1.1 keep-alive。
- [ ] 明确并实现 HTTP/1.1 pipelining 首版策略。
- [ ] 处理 HTTP/1.0、`Connection: close`、1xx、204、304、HEAD 无 body。
- [ ] 添加 GET、POST、keep-alive、chunked 集成测试。

## 阶段 5：Patch、Validation 与 Manual Intercept

目标：实现请求和响应的修改、拦截、恢复、丢弃和 mock response。

- [ ] 实现 `PatchSet` 应用逻辑。
- [ ] 实现 request patch：method、uri、headers、body、redirect target。
- [ ] 实现 response patch：status、headers、body。
- [ ] 实现 `RequestValidationHandler`。
- [ ] 实现 `ResponseValidationHandler`。
- [ ] 实现 hop-by-hop header 删除与重建。
- [ ] 实现 `Content-Length` 与 `Transfer-Encoding` 重算。
- [ ] 实现 `InterceptTicket`。
- [ ] 实现 `ManualInterceptHandler`。
- [ ] 实现 `ResumeDecision` 一次性消费与过期处理。
- [ ] 实现拦截超时策略。
- [ ] 实现 `MockResponse` 并设置 `response_source = Mock`。
- [ ] 添加 request pause、patch、resume 测试。
- [ ] 添加 response pause、patch、resume 测试。
- [ ] 添加 mock response 跳过 upstream 测试。
- [ ] 添加 Drop scope 行为测试。

## 阶段 6：HTTP Body 状态机与存储

目标：实现 body buffer、streaming、spool、压缩处理和敏感数据存储约束。

- [ ] 定义 `BodyState`。
- [ ] 实现 `Buffered` body。
- [ ] 实现 `Streaming` body。
- [ ] 实现 `SpoolBacked` body。
- [ ] 实现 body preview 与 hash。
- [ ] 实现 body buffer limit 与 spool limit。
- [ ] 实现 gzip 解压、编辑、重压缩。
- [ ] 实现 deflate 解压、编辑、重压缩。
- [ ] 对 br 和多重编码默认禁止语义编辑。
- [ ] 实现敏感 header 默认脱敏。
- [ ] 实现 body spool 目录权限、保留期限、最大磁盘占用。
- [ ] 区分 metrics、tracing、audit、storage 可记录字段。
- [ ] 添加 body limit、streaming、ReplaceBody 合法性测试。
- [ ] 添加 gzip/deflate 修改与 framing 校验测试。

## 阶段 7：TLS MITM 与证书管理

目标：实现 HTTPS MITM、ClientHello 所有权、根 CA、站点证书和 TLS bypass 策略。

- [ ] 实现完整 ClientHello 解析，并保存 raw bytes 与 `ClientHelloInfo`。
- [ ] 实现 ClientHello 最大长度和读取超时。
- [ ] 实现根 CA 加载与生成。
- [ ] 实现根 CA metadata。
- [ ] 禁止通过控制面导出 CA 私钥。
- [ ] 实现站点证书生成，支持 DNS SAN 与 IP SAN。
- [ ] 实现站点证书内存缓存。
- [ ] 实现 CA 轮换后站点证书缓存失效。
- [ ] 实现 rustls server acceptor。
- [ ] 实现 upstream TLS connector。
- [ ] 强制首版客户端 ALPN 为 `http/1.1`。
- [ ] 强制首版 upstream ALPN 为 `http/1.1`。
- [ ] 实现 ALPN 降级审计。
- [ ] 实现 SNI 缺失时证书和 upstream 校验规则。
- [ ] 实现 MITM fail-close 默认策略。
- [ ] 实现显式 TLS bypass 规则。
- [ ] 实现 bypass reason 标签和审计事件。
- [ ] 添加 TLS MITM HTTPS 捕获测试。
- [ ] 添加 TLS bypass ClientHello 回放测试。
- [ ] 添加证书生成失败默认 drop 测试。

## 阶段 8：Lua hook 与脚本沙箱

目标：实现受限 Lua hook 运行时、动作转换、错误隔离和安全边界。

- [ ] 选择并接入 `mlua` 运行时。
- [ ] 实现 hook registry。
- [ ] 实现 `on_connect`。
- [ ] 实现 `on_tls_client_hello`。
- [ ] 实现 `on_request`。
- [ ] 实现 `on_request_after_intercept`。
- [ ] 实现 `on_response`。
- [ ] 实现 `on_response_after_intercept`。
- [ ] 实现 Lua 返回值到 `Decision` 的转换。
- [ ] 实现 hook 阶段允许动作校验。
- [ ] 禁用 `io`、`os.execute`、`package.loadlib`、`debug`、FFI、任意网络和任意文件访问。
- [ ] 实现 wall-clock timeout。
- [ ] 实现 instruction budget。
- [ ] 实现 memory limit。
- [ ] 实现脚本错误计数与熔断。
- [ ] 实现 scripting fail action，默认 `Pass`。
- [ ] 添加 Lua hook 成功路径测试。
- [ ] 添加 Lua timeout、非法动作、内存限制测试。

## 阶段 9：公开 API、事件与控制面边界

目标：让平台模块、CLI 或 UI 能通过稳定 API 启动 core、订阅事件、恢复拦截、导出证书和关闭服务。

- [ ] 定义 `CoreConfig`。
- [ ] 定义 `CoreHandle`。
- [ ] 实现 `start(config)`。
- [ ] 定义 `EventStream`。
- [ ] 定义 `ControlHandle`。
- [ ] 实现 `resume_intercept(ticket_id, decision)`。
- [ ] 实现 `export_root_ca()`，只导出公钥证书。
- [ ] 实现 `ca_metadata()`。
- [ ] 实现 `shutdown()`。
- [ ] 实现 control plane ticket 授权、过期与重复提交拒绝。
- [ ] 添加事件订阅测试。
- [ ] 添加拦截恢复 API 测试。
- [ ] 添加 shutdown 资源释放测试。

## 阶段 10：错误映射、观测与验收

目标：补齐错误到客户端行为映射、指标、日志、安全审计和阶段验收。

- [ ] 定义 `CoreError` 全量枚举。
- [ ] 实现 SOCKS5 auth/connect 错误映射。
- [ ] 实现 upstream connect fail 映射。
- [ ] 实现 upstream TLS fail 映射。
- [ ] 实现 ClientHello parse fail 映射。
- [ ] 实现 HTTP framing error 映射。
- [ ] 实现 body limit exceeded 映射。
- [ ] 实现 Lua timeout 映射。
- [ ] 实现 Intercept timeout 映射。
- [ ] 实现 metrics。
- [ ] 实现 tracing 字段白名单。
- [ ] 实现 audit event。
- [ ] 整理集成测试脚本。
- [ ] 完成 `cargo fmt --all`。
- [ ] 完成 `cargo test --workspace`。

## 参考文档

- `docs/PROPOSAL.md`：core 架构、协议边界、handler 契约、TLS/Lua 安全和实施阶段。
- `AGENTS.md`：开发前后必须执行的协作规范、命令和状态同步规则。
- `core/README.md`：core crate 说明，当前为空，后续阶段补充。
- `README.md`：仓库说明，当前为空，后续阶段补充。
