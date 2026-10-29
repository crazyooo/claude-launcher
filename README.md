# Claude 环境检测 · Public Beta · v0.16

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

macOS 菜单栏应用：看清本机代理与 Claude 网络；可选在链式代理异常时防 Claude 静默直连 Anthropic。  
其它 App 继续听系统 / 你自己的代理客户端。本工具**不代启 Claude、不接管整机分流**。

**状态：Public Beta。** 源码按 [MIT](LICENSE) 公开；自动回归已通过的部分见 [验收记录](docs/detect-acceptance.md)。真实防直连差分、部分 GUI、以及签名二进制发布仍未完成——**不要把本仓库当成已验收成品或官方安装包来源**。

## 欢迎体验与反馈

这是 [crazyooo](https://github.com/crazyooo) 的公开实验项目。如果你也在用 Claude Desktop / CLI + 自有代理，欢迎从源码构建试用，并把体验开到 [Issues](https://github.com/crazyooo/claude-launcher/issues)：

- 检测结论是否好懂、有没有误导
- 菜单栏 / 第一屏哪里卡住或不清
- 可选「防直连」的安装、授权、开关是否符合预期
- macOS / Xcode 版本，以及是否安装了特权 helper

反馈请尽量脱敏（不要贴真实出口 IP、账号、代理订阅）。安全类问题请走 [SECURITY.md](SECURITY.md)，不要公开贴可利用细节。

给别人用的最短说明：[docs/for-others-quickstart.md](docs/for-others-quickstart.md)  
产品边界：[docs/product-detect-guard.md](docs/product-detect-guard.md)  
贡献：[CONTRIBUTING.md](CONTRIBUTING.md)

**权限警告：** 可选「防直连」会安装 root 所有的特权入口（`local.crazyooo.claude-protect`），并可能改动 PF。安装前请自行审阅源码与安装器摘要。免密码授权仅限精确的 `status`；开关防护走 macOS 管理员授权，当前不承诺 Touch ID。

**标识：** Bundle / LaunchAgent / helper 使用 **`local.crazyooo.*`**（与 GitHub 用户名一致）。若本机仍残留旧的 `local.crazymax.*` 入口，请先按快速开始迁移/退役后再装新版，不要两套并行。

**v0.16.16 / 61：** 特权代码改为系统目录内的 root 所有快照；单独升级 App 不会撤销旧 sudoers，须按快速开始迁移。

## 打开后主路径

1. **已开代理**开关（本机记忆，不改系统代理）
2. **一键检测**：本机后台检测，结果回填第一屏（浏览器页可选）
3. **防直连**（可选）：禁止 Anthropic 物理口直连；代理异常时可停 Claude
4. **其他工具**：Claude 相关开源项目目录
5. **问题与日志**：脱敏诊断记录

侧栏只有上述主路径五项；旧分流 / 当前走线 / 附属工具 UI 已删除。遗留 `RoutingCore` 仅作兼容依赖，不在本版本功能验收内。

## 安装

需要 macOS 13+，以及 Xcode 16.4（或兼容工具链）。

```sh
git clone https://github.com/crazyooo/claude-launcher.git
cd claude-launcher
/usr/bin/python3 -I -B tools/fetch_router_core.py
DEVELOPER_DIR=/Applications/Xcode-16.4.app/Contents/Developer bash tools/build.sh
/usr/bin/python3 -I -B tools/install.py install
open ~/Applications/Claude\ Launcher.app
```

默认装检测版：不写启动包装、不启动连接器。应用在 `~/Applications/Claude Launcher.app`。

若本机曾装旧版隔离组件，可先预览再退役（可选）：

```sh
/usr/bin/python3 -I -B tools/retire_legacy.py plan --scope user
# 核对后再执行输出里的 apply_command
```

## 防护命令（可选，须你确认）

应用内「防直连」页提供检查、开启、关闭与独立刷新；首次使用或从旧版升级请先完成[授权迁移](docs/for-others-quickstart.md)。常用只读检查：

```sh
/usr/bin/python3 -B tools/claude_protect_pf.py generate
/usr/bin/python3 -B tools/claude_protect_guard.py status
/usr/bin/python3 -B tools/claude_protect_guard.py check --dry-run
```

L3 `apply` / `unload` 与 root hook 须双确认；L4 真杀进程须去掉 `--dry-run`。  
L2 模板见 [docs/claude-protect-l2.md](docs/claude-protect-l2.md)。

完成新版授权安装后，状态查询无需密码：

```sh
sudo -n /Library/PrivilegedHelperTools/local.crazyooo.claude-protect/claude-protect status
```

## 检测源（仅两个）

- [IPSuper Claude](https://ipsuper.com/claude/)
- [Net.Coffee Claude](https://ip.net.coffee/claude/)

首页「读取两页结果」通过临时 WebKit 页面读取网站可见结果，标注来源和时间，不覆盖本机 Desktop/CLI 结论。IPSuper 当前 Claude 页只提供环境风控结果，不补造 IP 或连通性。

首次使用请在检测设置中填入**自己的**固定出口与代理入口。文档与测试中的 `203.0.113.0/24` 仅为示例，不能当作网络证据。

## 开发验证

```sh
DEVELOPER_DIR=/Applications/Xcode-16.4.app/Contents/Developer swift test --disable-sandbox --filter LauncherCoreTests
PYTHONPATH=tools:tools/l4 /usr/bin/python3 -B -m unittest claude_protect_pf_tests claude_protect_guard_tests router_pf_root_hook_tests detector_installer_tests install_guard_daemon_tests install_sudoers_nopasswd_tests
```

默认 Swift 范围跳过真实网站读取。显式设置 `CLAUDE_LAUNCHER_LIVE_WEBSITES=1` 并筛选 `WebsiteResultsLiveTests` 可验证两站读回。  
**不要直接运行未筛选的全量测试：** 冻结的 RoutingCore Live 测试可能实际改动本机网络、PF 或核心进程。

本快照曾独立复跑：LauncherCoreTests 309 通过 / 1 Live 跳过；Python 六模块 57/57。

## 许可与第三方

- 本项目源码：[MIT](LICENSE)
- 第三方说明：[docs/third-party-notices.md](docs/third-party-notices.md)
- **本公开仓库默认不附带 Mihomo 等代理二进制。** 若你自行捆绑 GPL 组件再分发，须自行满足对应许可证义务。

## 尚未完成（方案 C 剩余）

- App 内管理员取消 / 开关流程与真实代理故障、直连差分的人工验收
- 检测体验的产品级收尾（结论可读、减少误导）
- Developer ID 签名 / 公证的官方二进制 Release（当前无安装包发布）
