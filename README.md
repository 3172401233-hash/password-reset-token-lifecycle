# password-reset-token-lifecycle

Python 密码重置令牌生命周期库，处理绑定、一次性消费、撤销和并发兑换。

## 威胁模型与设计目标

针对以下真实事故场景设计：

- 重置邮件中的链接被点击两次、或两个浏览器标签页同时提交，必须只有一次兑换成功。
- 用户修改邮箱后，针对旧邮箱签发的重置 token 不能再用于重置该账号。
- 重复点击“发送重置邮件”会产生多个 token，任意一个被成功兑换后其余 token 立即失效。
- 数据库内容泄露时，攻击者无法直接从落库数据还原出可用 token。

## Token 格式

明文 token 只通过邮件等带外通道交付给用户，形态为：

```
prt_<base64url 负载>.<base64url HMAC-SHA256 签名>
```

- **前缀**：所有 token 均以 `prt_`（password reset token）开头，便于日志扫描、密钥管理和邮件网关识别。
- **负载**：JSON 经 base64url（无填充）编码，绑定五项声明：
  - `user_id`：用户账号标识；
  - `email`：发起重置时的邮箱地址；
  - `purpose`：用途，固定为 `password_reset`，防止跨场景混用；
  - `nonce`：每次签发生成的 16 字节随机数（十六进制 32 字符），保证重复签发的 token 互不相同；
  - `iat`：签发时间，Unix 毫秒时间戳。
- **签名**：使用服务端密钥对负载做 HMAC-SHA256，验签使用 `hmac.compare_digest` 做恒定时间比较，防止时序攻击。篡改负载或签名都会在验签阶段被拒绝。

## 数据库只存不可逆摘要

数据库 `reset_tokens` 表**不保存明文 token**，只保存：

- `token_digest`：明文 token 的 SHA-256 摘要（十六进制），作为主键；
- 绑定声明（`user_id` / `email` / `purpose` / `nonce` / `iat`）、到期时间和状态（`unused` / `consumed` / `revoked`）。

兑换时由服务端对请求带来的明文 token 现场计算 SHA-256，再按摘要查库。即使数据库被拖库，攻击者也无法凭摘要反推出可点击的重置链接（SHA-256 不可逆，且 nonce 具备 128 位熵，不可行暴力枚举）。

## 有效期

- 默认有效期 **15 分钟**（`TokenIssuer(secret, ttl_ms=15*60*1000)`，可按业务调整）。
- 到期判定为左闭右开：`now - iat < ttl` 有效，`now - iat >= ttl` 立即过期；签发层和数据库 `expires_at_ms` 双重校验，防止时钟偏差绕过。
- 可调用 `service.prune_expired()` 定时把过期的未使用 token 标记为 `revoked`。

## 原子兑换与级联撤销

`ResetTokenService.redeem()` 在单个 SQLite `BEGIN IMMEDIATE` 事务内完成全部操作：

1. 验签并校验 `user_id` / `email` / `purpose` 绑定与过期时间；
2. 按摘要锁定该行，检查状态；
3. 标记当前 token 为 `consumed`；
4. 把该用户名下**其他所有未使用 token** 标记为 `revoked`（重复发送的链接立即失效）；
5. 撤销该用户的**全部活跃会话**（强制重新登录）。

事务保证双击、并发标签页、多线程请求下恰好一次成功，其余请求得到 `TokenConsumedError`。数据库写操作遇到 `database is locked` 等瞬时错误时按线性退避自动重试（默认 3 次），重试耗尽抛出 `StoreUnavailableError`，且不会破坏单次消费语义。

邮箱变更时调用 `service.on_email_changed(user_id, old_email, new_email)`，会按“用户 + 旧邮箱”维度撤销所有未使用 token，阻断“旧邮箱链接重置新账号”的路径。

## 错误类型

| 异常 | 触发场景 |
| --- | --- |
| `TokenInvalidError` | 前缀/格式错误、签名不匹配、库中无此摘要 |
| `TokenExpiredError` | 超过 TTL |
| `TokenConsumedError` | token 已被兑换过 |
| `TokenRevokedError` | token 已被撤销（邮箱变更、被其他兑换级联失效、过期清理） |
| `TokenBindingError` | 用户、邮箱或用途与 token 绑定不一致 |
| `StoreUnavailableError` | 数据库重试耗尽 |

## 日志安全

有效 token 永远不会进入日志：所有日志只记录摘要的前 12 个字符（`digest_ref`），异常消息也不含 token 内容；可用 `reset_tokens.service.redact_token()` 对外部传入值脱敏后再记录。测试中对日志输出、异常文本和数据库落库内容都做了明文 token 断言。

## 快速上手

```python
from reset_tokens import SQLiteTokenStore, TokenIssuer, ResetTokenService

issuer = TokenIssuer(secret="从密钥管理系统读取的高熵密钥", ttl_ms=15 * 60 * 1000)
store = SQLiteTokenStore("/var/lib/app/reset_tokens.db")
service = ResetTokenService(issuer, store)

raw_token = service.request_reset(user_id="user-1", email="alice@example.com")
# 把 raw_token 放进重置邮件，数据库里只有它的 SHA-256 摘要

result = service.redeem(
    raw_token,
    expected_user_id="user-1",
    expected_email="alice@example.com",
)
print(result.revoked_sessions, result.revoked_tokens)

service.on_email_changed("user-1", "alice@example.com", "alice@new.example")
```

## Token 或密钥泄露后的处置

按影响范围从窄到宽处理：

1. **单个 token 泄露**：该 token 天然一次性、15 分钟过期；可立即用新的重置流程兑换一次（成功后同账号其他 token 与会话全部撤销），或直接在管理后台删除/撤销对应摘要行。
2. **疑似批量泄露**：轮换 HMAC 密钥——旧 token 签名立即全部验签失败；同时数据库中的摘要无法还原明文，可按需把相关用户的未使用 token 批量置为 `revoked`。
3. **数据库泄露**：摘要不可逆且 nonce 不可枚举，不存在可直接使用的 token；仍应轮换 HMAC 密钥、撤销受影响用户的全部会话，并复核 `state` 记录确认没有非预期的 `consumed` 行。
4. **日志疑似泄露**：日志只含 12 字符摘要前缀，无法据此构造 token；排查输出链路，确认没有其他系统打印过完整请求参数或邮件正文。
5. **轮换密钥后的兼容**：建议直接作废所有未使用 token 并让用户重新发起重置，而不是长期保留多把验签密钥，缩小旧密钥的暴露窗口。

## 测试

```bash
python -m unittest
```

测试覆盖：并发兑换（多线程下恰好一次成功）、邮箱变更撤销、重复发送与级联失效、TTL 过期边界、错误账号/邮箱/用途绑定、数据库瞬时故障重试与重试耗尽、日志与落库内容不含明文 token，共 32 个用例。
