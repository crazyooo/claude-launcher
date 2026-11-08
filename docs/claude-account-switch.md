# Desktop 账号切换（A–D）· v1

可选功能：在本机最多四套 Claude Desktop 本地身份之间切换。  
不是检测结论，也不代表防直连已开启。

应用内入口：侧栏 **账号**。

## 行为

1. 优雅退出 Claude Desktop；超时未退出则**拒绝**切换（默认不强杀）。
2. 把当前 `~/Library/Application Support/Claude` 归档到 `~/.claude-launcher/accounts/<当前>/`。
3. 把目标槽位还原为活目录；空槽位得到空目录（首次登录）。
4. 写入 `~/.claude-launcher/current`。
5. 默认**不**打开 Claude；应用内可开启「切换后打开 Claude Desktop」。

首次从「未建档」切到另一槽位时，会先把现有活目录收编为 A。槽位为 A / B / C / D。

## 应用内步骤

1. 把当前登录存成 A（或先点空位开始新登录）  
2. 空位「登录新账号」→ 打开 Claude 登录另一套  
3. 之后在 A–D 卡片之间切换  
4. 「刷新额度」查看订阅；Free 也可刷新

## 命令

```sh
/usr/bin/python3 -I -B tools/claude_account_switch.py status
/usr/bin/python3 -I -B tools/claude_account_switch.py adopt --as A --i-confirm-adopt
/usr/bin/python3 -I -B tools/claude_account_switch.py switch --to B --i-confirm-switch
/usr/bin/python3 -I -B tools/claude_account_switch.py switch --to C --i-confirm-switch
/usr/bin/python3 -I -B tools/claude_account_switch.py switch --to A --i-confirm-switch --open
/usr/bin/python3 -I -B tools/claude_account_switch.py refresh-usage --slot B --i-confirm-refresh-usage
```

测试可用环境变量：`CLAUDE_ACCOUNT_HOME` / `CLAUDE_ACCOUNT_BASE` / `CLAUDE_ACCOUNT_DATA`。

## 订阅 / 额度

应用内「刷新额度」会优先读 Desktop `oauth:tokenCache*`；新版 Desktop 若未写入该缓存，则回退到 Cookies 会话（`sessionKey`）查询 claude.ai。  
Free 账号也可刷新，通常只有订阅名、没有会话/周用量进度条。默认个人组织名（如 `email's Organization`）不展示。不落盘令牌。

## v1 边界

- 只动 Desktop；不动 Claude Code CLI / `CLAUDE_CONFIG_DIR`
- 不做 `--user-data-dir` 多开、加密导出、Keep 列表、历史合并
- 中断产生的 `.new` / `.previous` / `.replaced` 会阻断后续覆盖，需人工检查

## 验证

```sh
PYTHONPATH=tools /usr/bin/python3 -B -m unittest claude_account_switch_tests
DEVELOPER_DIR=/Applications/Xcode-16.4.app/Contents/Developer swift test --disable-sandbox --filter ClaudeAccountModelTests
```
