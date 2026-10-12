---
metadata:
  node_type: memory
name: "sn-1 lab-scanning-non-standard-data-structures mechanism probe"
description: "sn-1 未解出:cookie=username:token 的三态机制与双槽无注入面已证,派单 302→提权面板假设否证"
last_updated: 2026-10-12T14:48:23+08:00
created: 2026-10-12T14:48:23+08:00
---

## 2026-10-12 sn-1 lab-scanning-non-standard-data-structures 攻坚(未解出)

题面:lab-scanning-non-standard-data-structures(essential-skills / using-burp-scanner-during-manual-testing),目标删除 carlos。实例 0a880015040964b880be53ed001c00f5(lab_id AA337200EF03F4ADB1C669E54C672A13150D20A25CEE6622930F71C424F0AFFC)。

### 已证机制(session cookie 承载面)
- 匿名:`session=%3a<32位base62 token>`(username 空);登录 wiener:peter 后 `session=wiener%3a<32位随机 token>`。token 每次新会话都变(两次新鲜匿名会话 token 不同)⇒ 随机、不可预测、不可伪造。
- 解析序(三种响应态,已用 ~90 个 payload 证):
  1. token 查不到 ⇒ 302 → /login,并 Set-Cookie 换成新的匿名 session(如 `wiener:XYZ`);
  2. token 查到(属主=wiener)但 cookie username ≠ 属主 ⇒ 500 固定 2480 字节页,正文 `<p class=is-warning>Integrity violation detected</p>`,不换 cookie;该检查**全局生效**(/admin 同 500);
  3. 两半匹配 ⇒ 200。
- 关键判定:`administrator%3a<未知token>` → 302,但 `administrator%3a<wiener有效token>` → 500 ⇒ 先按 token 查会话、后比 username;**username 半不参与任何查询**。
- token 槽无可注入性:`' OR '1'='1`、`'-- `、`'#`、`UNION SELECT NULL|'administrator'|* FROM users|sessions|user|accounts`、`;SELECT`、pg_sleep(5)/sleep(5) 计时腿 ⇒ 全部 302(不区分「无行」与「错误」),即查表是参数化/内存 Map。
- username 槽无可注入性:单引号/双引号/反引号/`)`/`/*`/`#x`/`-- -`(规避 cookie 尾空格被裁的可能)/`OR '1'='1'`/`UNION`/`ORDER BY`/`AND sleep` ⇒ 全部 500 同一 2480 字节页(即 app 自查,不是 SQL 报错)。
- 结构绕过全失败:双重百分号编码冒号、JSON 形(`{"username":..,"token":..}`)、三段 `wiener:token:x`、NUL/空格/换行/制表填充、`administrator%253a…` ⇒ 302/500/200 三态内无新态。
- 旁路:登录 administrator:peter ⇒ Invalid username or password;登录 `administrator'-- ` ⇒ 无效;/post?postId= 非数字 ⇒ 400、未知 id ⇒ 404(无 SQLi);/?… 与 /my-account?id= 均不注入;url_fuzz 25 路径仅 /admin(401)。

### 结论
派单前鉴的第 3 条(「令牌槽注入回 302 非对称,指向提权面板」)已展开并**否证**:302 恒为 /login。session cookie 是完整的完整性绑定结构,两个槽都无注入面,不可伪造,故「非标准数据结构」不在 cookie 上(或需 Burp「Scan selected insertion point」才能命中的第三处插入点,本会话未定位)。终态 banner is-notsolved。

### 环境坑
- 本实例 host 间歇性 transport 失败(range_launch /api/widgets 超时、http_dump 超时、targeted_scan "no response within 8000ms"、os error 11),重试即过;range_launch 首次失败后重试拿到实例。
- 匿名/登录后 token 会在服务端被替换,所以逐请求显式带 Cookie 头才能稳定复现。
- page_read of the lab page 给 widget-lab-id=AA3372…;lab URL 路径是 /web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures。

