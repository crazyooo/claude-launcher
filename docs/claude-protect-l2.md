# L2：钉代理到既有链式入口

默认本地 HTTP 入口示例：`http://127.0.0.1:1082`（客户端不限）。若你的端口不同，先改模板再安装。

## Claude Desktop

1. 打开 `tools/l2/claude-desktop-egress-proxy.mobileconfig`（或先编辑其中的 `egressProxyUrl`）。
2. 系统设置 → 通用 → 设备管理 / 描述文件，确认安装。
3. 需要 Desktop 版本支持 `egressProxyUrl`（官方托管配置）。钉死后，代理不可达应失败而不是静默直连。

本工具不代你点击安装；安装后其它 App 不受影响。

## Claude Code（CLI）

将 `tools/l2/claude-code-proxy-env.snippet.json` 里的 `env` 字段合并进 `~/.claude/settings.json`。

若使用第三方 `ANTHROPIC_BASE_URL` 中转，把该中转域名加入 `NO_PROXY`。

## 与 L3/L4 的关系

- L2：应用层钉代理  
- L3：物理口拦 Anthropic 直连（`claude_protect_pf.py`）  
- L4：代理挂了停 Claude（`claude_protect_guard.py`）  

三层独立；L2  alone 不能替代内核拦截。
