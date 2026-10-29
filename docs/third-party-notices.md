# 第三方来源与许可

CCBaga参考源码：<https://github.com/liseami/CCBaga>，提交 `30a171f5191fbb65dc24e4b1a0392d998f7c5719`。本工具独立编写Swift账号管理与控制界面，参考其账号字段边界和浏览器启动约定。

浏览器安装器下载官方发布资产：<https://github.com/liseami/CCBaga/releases/tag/v0.2.48>。仅提取保留原签名的CCBaga-B包，不修改Chromium二进制、不运行上游安装脚本。浏览器包自带的Chromium及其他第三方许可继续随包保留；CCBaga仓库MIT许可不能代替这些组件各自的许可。

以下为CCBaga仓库原始许可：

```text
MIT License

Copyright (c) 2026 CCBaga contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Mihomo v1.19.32

本机运行包携带 MetaCubeX/Mihomo 官方 darwin-arm64 可执行文件，保持上游字节及签名。许可证为 GPL-3.0，完整文本随包提供为 `mihomo-GPL-3.0.txt`，仓库中见 `docs/licenses/mihomo-GPL-3.0.txt`。

- 项目与对应源码：<https://github.com/MetaCubeX/mihomo/tree/v1.19.32>
- 固定发行版：<https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.32>
- 压缩包 SHA256：`3312a6780652c622890fd4357c6a853bbf865464fd047ac7b7f52dab8de18652`
- 可执行文件 SHA256：`94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66`

公开仓库默认**不附带** Mihomo 可执行文件；上述哈希仅记录历史本机运行包曾使用的精确版本。若你自行获取并随分发方案捆绑该二进制，须同时提供该精确版本的完整对应源码及 GPL-3.0 要求的材料，不能仅用上述链接替代分发义务。
