# REAegis

**保护可执行逻辑，分离密钥，验证发布产物。**

REAegis 提供认证加密代码保护、服务端逻辑隔离与发布验证。发布流程采用“审计 → 明确选择移除项 → 生成独立副本 → 验证”的流程，帮助减少向 REA 等逆向工具直接暴露的源码、配置和调试信息。项目与 REA 维护者没有隶属关系。

下文列出当前版本的保护能力与操作方法，完整部署边界见 [安全模型](../SECURITY.md)，测试条件见 [验证记录](verification.md)。

## 安装与使用

需要 Python 3.11+，运行时没有第三方依赖。首版通过 GitHub 发布，尚未发布到 PyPI。

```bash
python -m pip install "git+https://github.com/ShuaixinHuang/rea-aegis.git@v0.1.1"
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

## 三条代码保护链路

- **JS/TS 与 Electron 主进程**：现有构建生成 CommonJS，使用外置密钥进行 AES-256-GCM 加密，认证后加载 `.cjs`，保留模块导出。
- **Linux 原生程序**：加密 ELF，由外置密钥认证解密后从匿名内存文件启动，并转发程序参数。
- **服务端关键逻辑**：私有处理函数与根密钥保留在服务端，客户端通过短时能力令牌调用；网关拒绝重放，并按调用者限速。

```bash
rea-aegis keygen ../operator/master.key
mkdir protected
rea-aegis protect-js ./dist/core.cjs ./protected/core.cjs --key-file ../operator/master.key
REA_AEGIS_KEY_FILE=../operator/master.key node ./protected/core.cjs
rea-aegis protect-native ./dist/app ./protected/app.aegis --key-file ../operator/master.key
rea-aegis run-native ./protected/app.aegis --key-file ../operator/master.key -- argument
```

加密链路使用 Node.js 20+ 内置密码学；Linux 内存加载使用 `memfd`。服务端网关使用 Python 标准库。完整密钥交付、Electron 接入、原生运行上下文和网关部署说明见 [保护部署指南](protection.md)。
