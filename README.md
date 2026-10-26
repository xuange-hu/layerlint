# layerlint

[![CI](https://github.com/xuange-hu/layerlint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/layerlint/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-126%20passing-brightgreen.svg)](tests/)
[![rules](https://img.shields.io/badge/rules-32-red.svg)](#rule-map)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![mcp](https://img.shields.io/badge/MCP-4%20tools-blueviolet)](https://modelcontextprotocol.io)

**Dockerfile 审计器 v0.1.0 — 唯一看得懂「层」的那个。**

32 条确定性规则 · 零依赖 · 每条结论带 `Dockerfile:行号` · SARIF 直连 GitHub Code Scanning · MCP server

```
layerlint demo && layerlint scan ./demo
```

> **The one thing it does that nothing else does.** 其他 linter 把 Dockerfile 当成
> 一份指令清单；layerlint 把它建模成 **stage → layer**。`RUN rm -rf` 只能删自己那
> 一层写的东西，写在前面层里的字节**一直在镜像里**：
>
> ```dockerfile
> COPY ./secrets /app/secrets     # L14：进了镜像
> RUN  rm -rf /app/secrets        # L15：只写一个 whiteout，一个字节都没少
> ```
>
> `docker save` / `docker history` / 任何一次 pull，都能把 L14 拿出来。这条规则
> (LYR502) 会同时报出两个行号。**没有层模型，这类问题只能靠人肉发现。**

---

## 三步跑通

```bash
pip install layerlint

layerlint demo              # 写一个"故意写坏"的 Dockerfile 并审计它
layerlint scan .            # 审计自己的项目（自动找 ./Dockerfile）
layerlint scan . --fail-on high   # CI 闸门：命中就 exit 1
```

不装也能跑（零依赖，stdlib 实现）：

```bash
python -m layerlint scan ./Dockerfile
```

## 输出长什么样

```
  layerlint  ./Dockerfile
  2 stage(s) · 20 layer(s) · 15 finding(s) · risk 100/100 → CRITICAL RISK
  critical 5  high 10  medium 14  low 19
  runs as root · ports 22,8080 · 9 package(s) · 1 deletion(s) that cannot shrink the image

  findings
    HIGH     LYR502  ./Dockerfile:32
      rm removes files written by an earlier layer
      '/app/cache' was written by layer L14 (line 27) and deleted here — the bytes remain in L14
      > RUN rm -rf /app/cache
    CRITICAL LYR401  ./Dockerfile:11
      Secret-looking name in ENV or ARG
      'BUILD_TOKEN' holds credential material by its name.
      > ARG BUILD_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

每条结论都带 `文件:行号` 和原始指令 —— **先看那一行，再决定信不信**。

## 层视图（这是别家没有的）

```bash
layerlint layers Dockerfile
```

```
    stage layer  line  instruction detail
    1     L14    27    COPY        . /app  [adds: /app]
    1     L18    32    RUN         rm -rf /app/cache  ** still in an earlier layer: /app/cache

  ** = 字节还在镜像里：后面的删除只写一个 whiteout
```

## 命令

| 命令 | 用途 |
|---|---|
| `layerlint scan [PATH]` | 审计 Dockerfile 或目录；`--fail-on`、`--json`、`--sarif`、`--min-severity`、`--ignore-rule` |
| `layerlint layers [PATH]` | 打印层地图：每层加了什么、删了什么、装了什么包 |
| `layerlint rules [--group G]` | 列出全部规则与严重级别 |
| `layerlint explain LYR502` | 这条规则为什么存在、最小改法是什么 |
| `layerlint demo [DIR]` | 生成故意写坏的 Dockerfile 并审计它（一键看到全部价值） |

退出码：`0` 通过 · `1` 命中 `--fail-on` 阈值 · `2` 用法/文件错误。

## 和已有工具的区别

| | hadolint | dockerfile-roast | **layerlint** |
|---|---|---|---|
| 语言 / 运行时 | Haskell 二进制 | Rust 二进制 | **纯 Python，零依赖** |
| 层建模 | ✗ | ✗ | **✓ stage/layer DAG + 跨层删除检测** |
| 扩展方式 | 重新编译 | 重新编译 | **Python 规则字典，改一行就是一条规则** |
| CI 集成 | shell 管道 | shell 管道 | **原生 SARIF + 退出码** |
| Agent 集成 | ✗ | ✗ | **MCP server（4 tools）** |
| 离线、确定性 | ✓ | ✓ | ✓ |

不是替代品，是补位：hadolint 查 shell 写法，layerlint 查**镜像里到底留下了什么**。

## MCP server

```bash
uvx --from "layerlint[mcp]" layerlint-mcp
```

```json
{ "mcpServers": { "layerlint": { "command": "uvx",
  "args": ["--from", "layerlint[mcp]", "layerlint-mcp"] } } }
```

4 个工具：`layerlint_scan` · `layerlint_layers` · `layerlint_explain` · `layerlint_rules`。
Claude Code / Cursor / Cline 里直接问「这个 Dockerfile 有什么问题」。

## CI

```yaml
- name: Dockerfile audit
  run: |
    pip install layerlint
    layerlint scan . --fail-on high --sarif layerlint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: layerlint.sarif
```

> ⚠️ SARIF 上传需要 `permissions: { security-events: write }`，否则 CodeQL action
> 会报 *Resource not accessible by integration*。

<a id="rule-map"></a>
## 规则地图

`layerlint rules` 列出全部；`layerlint explain <ID>` 看完整理由与改法。

| 组 | 规则 |
|---|---|
| base | LYR101 浮动 tag · LYR102 未命名 stage · LYR103 运行阶段未降权 · LYR104 显式切回 root · LYR105 sudo/su · LYR106 无 HEALTHCHECK |
| packages | LYR201 update/install 分层 · LYR202 拉入 recommends · LYR203 包管理器缓存残留 · LYR204 未锁版本 · LYR205 npm install · LYR206 关闭校验 |
| network | LYR301 管道进 shell · LYR302 下载即执行 · LYR303 ADD 远程 URL · LYR304 ADD 本地归档 · LYR305 明文 http 拉取 |
| secrets | LYR401 凭据名 · LYR402 凭据形值 · LYR403 复制密钥文件 · LYR404 RUN 写出凭据 · LYR405 无 .dockerignore 全量拷贝 |
| filesystem | LYR501 全局可写 · **LYR502 跨层删除** · LYR503 相对 WORKDIR |
| layers | LYR504 依赖安装晚于全量拷贝 · LYR606 单层过多 |
| runtime | LYR601 shell 形式 CMD/ENTRYPOINT · LYR602 重复 CMD/ENTRYPOINT · LYR603 特权端口 · LYR604 静默失败 · LYR605 无元数据标签 |

## 设计原则

1. **证据优先**：每条结论必须给出 `Dockerfile:行号` + 原始指令。
2. **零依赖**：核心模块只 import 标准库（`tests/test_packaging.py` 静态断言这件事）。
3. **不猜**：不确定的一律不报；解析不了的指令忽略而不是编造。
4. **解释优先于判定**：每条规则自带 `why` 与 `fix`，`explain` 直接可读。

## 已知边界

- 不支持 heredoc（`RUN <<EOF`）与 `# escape=` 解析指令：会被当成普通指令，结果是"看不懂"而不是误报。
- 不构建、不联网、不调用守护进程：全部结论来自静态解析，因此**永远不会误执行你的 Dockerfile**。

## License

MIT © xuange-hu
