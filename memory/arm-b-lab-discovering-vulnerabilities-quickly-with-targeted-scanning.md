---
metadata:
  node_type: memory
name: "arm-B lab-discovering-vulnerabilities-quickly-with-targeted-scanning 未解阻塞"
description: "臂 B 未解出:目标实例表面(/, /product, /product/stock, /image, /analytics)全部实测无文件读向量;含 10 分钟计时与 /try-again 复位机制、raw_matrix 不写 Content-Length 的缺陷"
last_updated: 2026-10-11T18:01:00+08:00
created: 2026-10-11T18:01:00+08:00
---

日期 2026-10-11,pi 臂 B,端口实例 0ae4002e04ef1680802499c100ee0081.web-security-academy.net。

结果:未解出。目标=10 分钟计时题,读 /etc/passwd。

表面枚举(全部在活实例上做实,非猜测):
- / 首页(20 商品,仅 Home/View details 链接,无搜索无 cart 无 login,无隐藏表单/脚本)
- /product?productId=N:N 严格 ^[0-9]+$ 校验;1-20 有效,0/21+ →404,非数字 →400 "Invalid product ID"
- /product/stock:仅接受 form-urlencoded(application/xml、text/xml、JSON 体内一律 400 "No such product or store",已用 target_scan 重算 CL 的受控模板验证);productId 同款严格数字校验;storeId 任意字符串 → 确定性伪随机数(如 (1,1)=277, (1,"1|cat /etc/passwd")=917, storeId=/proc/sys/kernel/pid_max → 88),证明是哈希存根,无文件读、无 shell、无 SQL;未知参数被忽略
- /image/<path>:静态图,JPG 200;../ 原样字节(raw)、%2e%2e%2f、双编码、NUL+扩展名、%5c、overlong %c0%af 全部 app 级 JSON 404(非代理层)
- /analytics:恒 200 空体无 Content-Type,参数/头全被忽略
- 约 250 个路径名(api/v1、source/config、actuator、graphql、backup、.env、product/1 等)全 404;~100 个参数名在 /product 与 /product/stock 上做隐藏参数发现,响应与基线同 digest
- Host 头只认实例名,其他值一律前端 403;X-Forwarded-*/X-Original-URL/Referer/UA 注入无效;PUT/OPTIONS/TRACE →405

机制记录(重要):该题实例带 10 分钟计时,超时后所有页面变成 "Time's up! / Click here to restart"(/try-again 302→/)。计时由实验台在 *部署* 时启动,不随我的 launch 重置,所以多次长扫描是自己把窗口跑死的:中途矩阵里 digest 突变(5323→3100)即超时信号,不是漏洞。长矩阵务必先核对当前页是否 "Time's up" 再采信。

工具缺陷(宜修):raw_matrix 的 send() 从不写 Content-Length,凡带 body 的变体后端读到 0 字节 → 全部伪 400(POST 矩阵结果不可信);POST 类矩阵改用 targeted_scan 或 burp_interp。

