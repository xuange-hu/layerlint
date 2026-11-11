# layerlint · 中文说明

[English README](README.md) · 建模 `stage → layer` 的 Dockerfile 审计器。

**一句话**：`RUN rm -rf /root/.cache` 删不掉**前一层**里的缓存。只看指令清单的工具
会以为删掉了，layerlint 不会。

## 目录

- [为什么存在](#为什么存在)
- [三步跑通](#三步跑通)
- [差异化](#差异化)
- [命令](#命令)
- [已知边界](#已知边界)

## 为什么存在

[hadolint](https://github.com/hadolint/hadolint)（约 12.5k★）逐条检查 Dockerfile
指令：有没有 `--no-cache`、有没有固定版本、有没有用 `latest`。这些都对，但都不回答
一个更贵的问题：**最终镜像里到底留下了什么**。

Docker 的每一条指令生成一层，层是追加的、不可变的。敏感文件只要曾经出现在任意一层，
`RUN rm` 之后依然能从镜像历史里取出来。跨阶段的 `COPY --from`、构建参数里被 bake 进去的
密钥、多阶段构建里 stage 之间的泄漏，都需要先把 Dockerfile 变成一张层图才能判断。
零依赖 Python 且真正建模层的工具，赛道是空的。

## 三步跑通

```bash
# 1) 安装（核心零运行时依赖）
pip install git+https://github.com/xuange-hu/layerlint

# 2) 看层图 / 跑自带演示（不需要 Docker、不联网）
layerlint layers Dockerfile
layerlint demo            # 写出一份故意写坏的 Dockerfile 并审计，实测 rc=0

# 3) 扫整个目录并卡 CI
layerlint scan . --fail-on high --sarif layerlint.sarif
```

`layerlint demo` 已在干净目录实测：写出 `layerlint-demo/Dockerfile` 并输出 202 行报告。

## 差异化

| 能力 | 说明 |
|---|---|
| **层图建模** | stage → layer 两层结构，能判断「删了但没删掉」 |
| **32 规则** | 安全 + 构建质量，分级 critical / high / medium / low / info |
| **证据式输出** | 结论带行号与命中的原始指令，可复核 |
| **MCP 4 工具** | `uvx --from "layerlint[mcp]" layerlint-mcp` |
| **CI 一等公民** | `--fail-on` 退出码 + SARIF 2.1.0 |

## 命令

| 命令 | 作用 |
|---|---|
| `layerlint scan PATH` | 审一个 Dockerfile 或一整个目录 |
| `layerlint layers FILE` | 打印该 Dockerfile 的层图（理解风险的第一手视图） |
| `layerlint rules` | 列出每条规则及其级别 |
| `layerlint explain RULE` | 一条规则为什么存在、怎么修 |
| `layerlint demo` | 生成故意写坏的 Dockerfile 并审计 |

## 已知边界

- 静态分析：不构建镜像，因此看不到基础镜像内部已有的层内容；
- 不解析 `RUN` 里的任意 shell 脚本语义，只看可静态判定的文件操作；
- BuildKit 的新语法（如 `RUN --mount=type=secret`）按保守规则处理，不做推测。

贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。MIT。
