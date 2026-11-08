# 产品边界

macOS 菜单栏环境检测 + 既有代理 + 可选 Claude 防直连 + 可选 Desktop 多账号切换。检测 Desktop、CLI、诊断代理的证据分开；网页结果仅来自 Net.Coffee 与 IPSuper 可见页面，不逆向接口、不覆盖本机结论，不跳过 TLS 验证。

侧栏：环境检测 / 检查详情 / 账号 / 防直连 / 其他工具 / 问题与日志。

1. **环境检测**：代理声明、本机入口、Desktop/CLI/诊断路径结论  
2. **检查详情**：逐步证据与自查清单  
3. **Desktop 账号切换（可选）**：A–D 最多四套本地身份，整份换卷 `~/Library/Application Support/Claude`；切换前退出 Desktop；默认不代启，可选手动打开；可刷新订阅/额度（不要求 Pro）  
4. **防直连（可选）**：只处理物理网卡到 Anthropic 网段的直连  

账号切换不是检测通过，也不代表防直连已开启。v1 不做 CLI 多账号联动、`--user-data-dir` 多开、加密导出、历史合并。

防直连不接管整机路由/TUN，不自动停止用户代理客户端。规则开启不等于实际防护验证通过。不能伪造 accepted、routing_verified、protection_verified。

v0.16.16 的更改操作使用 macOS 管理员授权；状态查询精确免密。特权代码与完整依赖放在 root 所有目录，原生入口在运行 Python 前检查固定 CLT 运行时。旧授权必须按快速开始迁移。当前不承诺 Touch ID。

完整开关 GUI 和实际网络差分仍待验证。安装与配置见 [快速开始](for-others-quickstart.md)，验证范围见 [验收记录](detect-acceptance.md)。账号边界见 [claude-account-switch.md](claude-account-switch.md)。
