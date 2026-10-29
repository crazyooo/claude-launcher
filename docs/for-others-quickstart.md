# 给别人用 · 快速开始

适合：本机已有可用的链式代理（常见本地入口如 `127.0.0.1:1082`，客户端不限），想检查 Claude Desktop / CLI 网络，并可选开启「防 Claude 直连」。

**v0.16.16 / 61：先迁移旧授权。** 旧免密码入口执行用户可写脚本的问题已在新版代码中修正；仅安装 App 不会撤销本机旧授权。下列迁移须使用管理员授权，保留现有 PF 规则和 hook 日志，不重启代理或停止 Claude。GUI 与实际防护效果尚未全部验收。

公开版标识为 `local.crazyooo.*`。若本机还有旧的 `local.crazymax.*` helper / LaunchAgent，请先退役或完成授权迁移后再装，避免两套并行。体验问题欢迎到仓库 [Issues](https://github.com/crazyooo/claude-launcher/issues) 反馈（请脱敏）。

## 安装（从源码）

需要 macOS 13+，以及 Xcode 16.4（或兼容工具链）。

```sh
cd /path/to/claude-launcher
DEVELOPER_DIR=/Applications/Xcode-16.4.app/Contents/Developer bash tools/build.sh
/usr/bin/python3 -I -B tools/install.py install
open ~/Applications/Claude\ Launcher.app
```

默认安装**检测版**：不写启动包装、不启动连接器、不自动改 PF。

菜单栏会出现「Claude 环境检测」；点开控制台即进第一屏。

## 菜单栏与后台设置（v0.16.14 起）

点击菜单栏图标 → **设置… → 菜单栏与后台**，也可从主窗口右上角设置按钮或 ⌘, 打开。

- 图标可选网络、脉冲、检测镜；可选择在图标旁显示检测状态。
- 后台自动检测默认每 30 秒一次，可改为 1、2、5 分钟，也可从菜单直接暂停。暂停后当前一轮会完成，手动检测仍可用，旧结果照常过期；网络变化/唤醒时，开启自动检测才会重新采样。
- **登录 Mac 时启动**按需开启；需要系统批准时会显示等待允许，可点「打开系统登录项…」。安装与打开设置不会自动替你启用。
- 关闭主窗口后仍驻留菜单栏；菜单底部可退出检测器。退出检测器不会关闭独立运行的防直连防护。
- 菜单栏与后台选项立即保存；固定出口、诊断代理、异常通知在 **检测** 标签中修改后「保存并检测」。

## 打开后先做什么

1. 确认代理是否已开 → 拨动 **已开代理**（只记你的声明，不改系统代理）；本页会核对本地入口是否真的在听。
2. 点 **一键检测**：在应用内后台核对代理入口与本机 Desktop / CLI / 诊断路径，把出口 IP、逐站结果回填第一屏「后台检测数据」与结论（可用 / 异常 / 声明不一致 / 未测全）。默认不弹浏览器。
3. 首页 **网站检测结果 → 读取两页结果**：直接显示 Net.Coffee 的出口 IP、地区、Claude 连通性与评分，以及 IPSuper 的环境风控结果，最长等待 45 秒。IPSuper 当前 Claude 页不提供 IP/连通性。来源和时间分开展示，未取得/过期会标明；网页使用系统网络路径，可能与 Claude 或外部浏览器不同。需要对照时再「打开原网页」。**检查详情**仍是 [Claude Code 稳定使用指南](https://ip.net.coffee/claude/claudecode.html) 自查清单，本机探针在该页下部。
4. 可选：完成下方授权安装后，侧栏 **防直连** 提供「禁止直连」与「代理异常时关掉 Claude」。开关防护通过 macOS 管理员授权，当前可能需要密码；不再以 App 内 Touch ID 弹窗代替系统权限验证。刷新无需密码、操作期间可用，错误提示保留；超时不当成成功、不自动重试。
5. **其他工具**：别人的 Claude 相关开源项目外链。  
6. **问题与日志**：脱敏记录，可导出。

侧栏只有这几项；旧分流控制台已删除。

## 不要指望它做什么

- 不代你启动 Claude
- 不接管整机分流 / TUN
- 不自动停你的代理客户端或其它 App
- 浏览器站点评分 ≠ 本机 Desktop/CLI 结论

规则全文：[product-detect-guard.md](product-detect-guard.md)。

## 防护授权安装 / 旧版迁移（v0.16.16）

在已核对的源码目录中执行，`--user` 指当前普通登录用户：

```sh
/usr/bin/python3 -I -S -B tools/l4/install_sudoers_nopasswd.py plan --user "$(id -un)"
sudo /usr/bin/python3 -I -S -B tools/l4/install_sudoers_nopasswd.py install --user "$(id -un)" --i-confirm-install --expected-source-sha256 "PASTE_REVIEWED_SOURCE_MANIFEST_SHA256"
sudo /usr/bin/python3 -I -S -B tools/l4/install_sudoers_nopasswd.py verify --user "$(id -un)"
```

先核对 `plan` 的各文件摘要，再将其 `source_manifest_sha256` 原样填入上方占位值；不匹配则在更改授权前拒绝。安装器把已核对源码缓存到内存、写入 root 暂存目录，并从暂存副本编译 C 入口。此绑定防止审查后的源码漂移，不替代对安装器本身及工具链的信任。

脚本文件名为兼容旧流程保留，但仅授予精确的 `status` 免密码查询。它先撤销旧授权，再退役旧 wrapper，并把四个特权 Python 文件快照安装到 `/Library/PrivilegedHelperTools/local.crazyooo.claude-protect/`。所有代码、依赖、清单及祖先目录须 root 所有、非组/其他用户可写、无符号链接或额外 ACL；运行时再次检查并核对摘要。原生 C 入口在 Python 启动前检查固定 CLT Python framework 及标准库的权限/ACL，拒绝越界符号链接；不走 xcode-select 转发壳。Python 禁用环境与 site 注入，特权端只接受限定参数。安装需要 Apple Command Line Tools，缺失或不可信则拒绝。

若旧 wrapper 的祖先目录不可信，新版只记录警告、跳过读取/改写；该路径的旧 sudoers 授权已先撤销，可继续安装新入口。迁移失败时，已撤销的旧免密授权保持撤销，可排查后重跑；不会自动恢复不安全的旧授权。备份留在系统目录的 `archive-*` 下，不能直接恢复旧 sudoers。`uninstall --i-confirm-uninstall` 只撤销本工具授权并退役入口，保留代码备份和现有 PF 防护；它不等于关闭防直连。旧 `/usr/local/sbin/claude-protect-*` 命令退役，请改用新版 App。

安装前必须信任源码与构建工具链；`plan` 输出待安装代码的 SHA-256 供对照。root 快照的摘要用于发现安装后篡改，不能证明安装前的源码可信。本地开发版有未提交工作，应在正式分发前与审核后的提交或签名发布包核对。
