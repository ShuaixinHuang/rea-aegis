# REAegis

**减少发布产物暴露的信息，验证保留的内容。**

REAegis 是面向软件作者的本地发布保护 CLI，采用“审计 → 明确选择移除项 → 生成独立副本 → 验证”的流程，帮助减少向 REA 等逆向工具直接暴露的源码、配置和调试信息。项目与 REA 维护者没有隶属关系。

它不能保证阻止逆向。运行时 JavaScript 仍然可读，客户端长期秘密仍可能被提取；关键授权与秘密应尽可能放在服务端。当前没有混淆、反调试、二进制改写或内存保护能力。

## 安装与使用

需要 Python 3.11+，运行时没有第三方依赖。首版通过 GitHub 发布，尚未发布到 PyPI。

```bash
python -m pip install "git+https://github.com/ShuaixinHuang/rea-aegis.git@v0.1.0"
rea-aegis audit ./dist
rea-aegis audit ./app.asar --format json
rea-aegis audit ./app.zip --format sarif > report.sarif
rea-aegis harden ./dist ./protected --remove-source-maps --omit .env
rea-aegis verify ./protected --receipt-sha256 从可信外部位置记录的摘要
```

加固仅支持目录副本，输出目录必须不存在且与输入互不包含。不会改写输入，也不会自动删除源码文件、执行应用或访问网络。`--omit` 是准确的相对文件路径，不是通配符；移除 source map 同样需要显式选择，无法解释或超过读取限制的 `.map` 会拒绝自动删除。

保留的文件字节不变，空目录会保留。回执记录文件清单与 SHA-256，但不是数字签名；如果攻击者能替换产物和回执，就能同时重新计算二者，因此需要把回执摘要保存在可信外部位置。验证结果不等于应用运行行为证明。所有者、ACL、扩展属性、硬链接关系、时间戳及特殊权限位不保留，目录使用新建权限；发布前仍需运行自己的应用与安装测试。

## 能力与边界

- 审计目录、单个文件、经典单磁盘 ZIP、Electron ASAR。
- 发现 v3 source map、嵌入源码、映射引用、私钥标记、凭据候选、环境配置、源码附件与调试旁文件。
- 重复 ZIP 文件名保留不同序号身份，不用后一个覆盖前一个。
- 预算不足、无法读取、加密、外部 ASAR 成员、链接、嵌套归档等保持“部分覆盖”，不会静默算通过。
- 只输出敏感命中的规则与字节位置，不输出匹配值；文件名和选定路径仍会出现在报告中。
- 不支持 ZIP64、多卷 ZIP、ZIP/ASAR 改写或递归解包；原生二进制只做有限字节标记检查，不解码其语义。

默认限制：10,000 项、每成员 2 MiB、累计内容 64 MiB、ZIP 载体 32 MiB、归档头 4 MiB。内容预算可用 `--max-file-bytes` 和 `--max-total-bytes` 明确提高。

退出码：`0` 为配置检查完成且未达到失败阈值，`1` 为达到阈值，`2` 为部分覆盖或错误。默认失败阈值为 `high`；不应把退出 `0` 理解为完全安全。

完整用法、演示与支持矩阵见 [英文 README](../README.md)，实际验证范围见 [验证记录](verification.md)。
