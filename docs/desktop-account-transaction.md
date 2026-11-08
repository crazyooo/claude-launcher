# Desktop 完整账号事务设计

2026-10-17，对应[完整交付矩阵](complete-delivery-plan.md) A2。此设计尚未实现，不能把现有 Code 身份归档说成 Desktop 账号切换。当前只读审查代码及官方应用包，未访问真实账号目录、浏览器资料或钥匙串。

## 与现有 Code 保险库的关系

保留 `AccountVault` 的 v1/v2 格式和有限 JSON 字段语义，新增独立 Desktop 格式及事务实现。现有 8 MiB/4096 文件限制不能通过简单增大来承载整套 IndexedDB/LevelDB；采用有上限的流式分块加密。复用 AES-GCM、精确绑定、描述符相对 I/O 和先备份再写入的原则。

## 版本布局与加密上下文

每个受支持客户端版本需明确布局契约，涵盖账号/session 子树、需保留的 MCP/插件/全局配置，以及经验证可重新生成的锁与缓存。未知路径不能默认为缓存或直接覆盖。没有充分布局证据时拒绝真实恢复。

待核验的存储类别包括 Cookies/Network、SQLite 的 WAL/SHM、Local Storage、Session Storage、IndexedDB/WebStorage、Service Worker 持久数据和相关 Local State。这是调查范围，不是对当前客户端路径全集的断言。

Safe Storage 是当前 macOS 用户/应用共享的加密上下文，不是可随 Claude 账号切换的 OAuth 字段。档案绑定 UID、来源根目录、客户端签名/版本布局、精确 Keychain 条目与上下文证明；归档/恢复时显式核验，不在 UI 轮询读取密码。不得覆盖共享加密根、复制整个 login.keychain 或重建原条目 ACL。跨用户、密钥轮换、条目缺失及签名/上下文变化应拒绝密文直接恢复，转入经过支持的重新登录流程。

## 文件树与数据库

- `absent / directory / regularFile` 都是档案中的真实状态；包含空目录，支持新增与缺失文件。
- 文件块、manifest、journal 均加密，AAD 绑定版本、范围、用户/根目录、档案/事务 ID、路径、块编号和长度。任何错块、换路径、超限和损坏都失败，不截断。
- Cookies 等 SQLite 一致性组保留原始主库/WAL/SHM 的加密备份。仅在私有离线副本使用 SQLite backup/checkpoint 生成规范化主库；不对真实原库执行 checkpoint/VACUUM。
- 恢复规范化主库时，不混入旧账号的 WAL/SHM。LevelDB/IndexedDB按契约整子树处理，不能只复制若干 `.ldb` 文件。
- 明文临时工作区需 0700/0600、明确生命周期和可恢复清理；不得把它称为加密备份。遵循安全删除规则，不调用 `rm`。

## 事务协议

1. 获取保险库排他锁及受管理启动互斥租约，验证客户端已退出。
2. 校验布局、加密上下文、整个目标 manifest 和所有内容块。
3. 两次读取源树并验证一致，构造保留当前全局配置的 before/after。
4. 完整加密备份和 journal 先持久化，fsync 后才能开始修改。
5. 目录创建浅到深；文件逐项期望值比对、原子 rename/fsync；多余成员深到浅移入可恢复保存位置。类型变更和中间目录状态写入 journal。
6. 每步检查占用和冲突；最终全树等于 after、数据库校验通过、加密上下文不变且客户端仍退出，才写持久 commit。
7. commit 成功后，UI 刷新失败不触发回滚。

恢复先全量检查，包括未修改成员及意外新增后代。只有当前状态属于该事务允许的 before/after/已记录中间状态才执行反向恢复。任何第三状态导致零自动回滚写入，保留记录供处理。旧备份必须先验证适用性再创建活动 journal，避免不适用备份造成恢复锁。

`flock` 只能协调本工具，进程扫描也不能阻止 Finder 另开 Claude。因此需要明确接入后续启动隔离/互斥能力；在其完成前只能声称冲突检测，不能声称任意外部并发下原子切换。

## UI 与测试

账号页保留 Code 功能，Desktop 使用真实 `connect/capture/restore/backups/restoreBackup/recover` 接口。被动刷新不读真实凭据。显示布局未验证、客户端占用、恢复待处理、第三状态冲突、加密上下文变化等实际状态。操作不启动客户端。

必须覆盖：SQLite未合并WAL、文件/目录存在状态变化、完整LevelDB树、每个持久化/修改/commit边界中断、第三状态零回滚、错钥/换块/路径越界/符号链接/硬链接/特殊文件、保留MCP插件配置、旧备份不适用、UI确实调用事务。先用隔离 fixture；真实登录恢复由本人验收。

## 静态调查入口

已只读确认 `/Applications/Claude.app/Contents/Resources/app.asar` 的 package 版本为 `2.26454.2`，入口 `.vite/build/index.pre.js`。包内存在 Safe Storage、userData、持久 session partition 和 Cookies 使用点；后续应以实际调用链核验布局。代码中出现某个字符串不能证明它属于主账号存储，也不能证明已覆盖所有服务端或系统凭据。
