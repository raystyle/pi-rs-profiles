---
title: 逻辑与访问控制族:解析分歧与对象引用
---

# 逻辑与访问控制族:解析分歧与对象引用

> 单层真源:方法正本单层存于 seed 的 business-logic-family 注;本注不维护方法副本,仅住项目层实录链与题代差异(防双层 drift)。

同一类型漏洞:业务规则实现与意图错位,或对象级鉴权缺位。共性是「两个组件
对同一值解析不一致」或「可达而校验缺位」。

## 子型判型矩阵

| 子型 | 判型特征 | 手法方向 | 实录 |
|---|---|---|---|
| 邮箱解析分歧 | 注册/登录/改址各自解析 email;校验器常是多道闸门 | 用解析差使账号落不同主体(判闸门看 response 长度、不看文案) | [[lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies]] |
| IDOR / 参数污染 | 对象标识可控、参数可污染 | 改 id / 污染参数读他人对象 | [[independent-idor]] |
| 购买流程无限刷钱 | shop + 优惠券 + 可兑换礼品卡;余额不足买不起高价商品 | 券作用于礼品卡、卡按面值兑换 → 每轮净赚折扣 | [[lab-logic-flaws-infinite-money]] |

## 共性

1. 先对账正常流程,找同一值在不同端点被**不同解析**(编码/截断/大小写)。
2. 邮箱类题:**闸门用 response 长度区分,不要只 grep 文案**。同一 200 下可能并存
   `Invalid email`(语法)/`blocked for security reasons`(过滤器)/`Only emails with the <域> domain are allowed`(域不符);
   把「域不符」误当接受会让整条分析跑偏(批42 实测教训)。校验器还可能**先解码 RFC-2047 encoded-word 再校验**(解码后仍须是 atext)。
   真正的缺口在**投递侧那个 parser**——判它只能用收件箱当唯一 ground truth。
2. IDOR:对象标识可枚举或可预测;先经正常路径取回真实值再改。
3. 参数污染(HTTP parameter pollution)可让一处校验、一处取值看到不同值。

## 判定与收尾要点

- 判定锚点:实际读到他人数据/以他人身份动作;请求被放行不算解。
- **购买型 lab 的翻牌时机**(批 29 实测):只 `POST /cart/checkout` 拿到 303 **不会**把 lab 标 solved,
  必须紧接着 `GET /cart/order-confirmation?order-confirmed=true`(同一 session)才触发判定。
- 刷钱循环用件 `money_loop`(见 [[lab-logic-flaws-infinite-money]])。
- 与 seed 的 access-control-family / business-logic-family 同域(跨库不按名连,仅引用其名)。

## 相关族

- 越权与 Host/头信任见 [[host-header-family]]、[[ssrf-family]];方法论:web-vuln-methods(seed 层,按名引用)。
