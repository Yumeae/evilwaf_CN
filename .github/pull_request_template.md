## 变更摘要

- 改了什么？
- 为什么需要这个更改？

## 风险 / 影响

- 网络/TLS/代理影响：
- 向后兼容性考量：

## 验证

- [ ] 本地语法/编译检查
- [ ] CLI 冒烟测试
- [ ] 其他手动检查（如适用）

使用的命令：

```bash
python -m py_compile evilwaf.py core/*.py chemistry/*.py
python evilwaf.py -h
```

## 关联

- Issue(s)：
- 安全注意事项：
