# pairwise-iam-policy

云账号数量一多，IAM 最小权限就只剩口号：策略里 `Action: "*"` 和 `Resource: "*"` 一起给；条件块可以被 `NotAction` 绕过；跨账号信任没有外部 ID 和来源限制；角色链能连续 AssumeRole 到生产账号；策略变量由用户输入拼接，能注入资源 ARN；deny 语句被后面的 allow 覆盖；长期 AccessKey 不轮换；未使用权限从不回收；CI 任务的 OIDC 信任策略允许任意仓库；权限边界只按账号不看环境。security/iam_policy.py 是核心，tests/test_iam_policy.py 15个红。要修的是：禁止全通配；NotAction 审查；跨账号信任限制；角色链深度；变量转义；deny 优先；密钥轮换；权限回收；OIDC subject 限定；环境隔离。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
