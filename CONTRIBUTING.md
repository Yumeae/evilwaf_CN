# 贡献指南

感谢您改进 EvilWAF。

## 提交 PR 前

- 保持更改聚焦且小（每个 PR 只处理一个关注点）。
- 描述风险/影响，特别是涉及网络、TLS、代理和扫描器逻辑的部分。
- 优先选择增量式更改，而非大范围重构。

## 本地验证

推送前请运行以下命令：

```bash
python -m pip install -r requirements.txt
python -m py_compile evilwaf.py core/*.py chemistry/*.py
python evilwaf.py -h
```

如果您修改了运行时行为，请在 PR 描述中包含简短的可复现测试或命令输出。

## 提交信息规范

- 使用简洁的祈使语气提交信息。
- 有助于理解时包含作用域，例如：`core: ...`、`chemistry: ...`、`docs: ...`、`ci: ...`。
- 避免将无关的清理工作与行为变更混合。

## Pull Request 检查清单

- 变更了什么以及为什么。
- 任何面向用户的行为变更。
- 安全影响及缓解措施（如适用）。
- 手动验证步骤。
- 关联的 issue（如有）。

## 安全报告

请勿在公开 issue 中披露漏洞。请使用仓库 Security 标签页和私有公告流程。
