# labkit - 做题产生的项目级 rs 件集

实践解题分支(practice/independent-solve)的项目级件档(`.pi-rs/rust-scripts/`,
catalog 以 `project` 源并入 rs_search / rs_execute,信任门与项目脚本同规,按名可跑)。
浏览器臂共用 pi 隔离 profile(`~/.pi-rs/agent/chrome/engine-profile`),cdp 依赖
运行时注入(ADR-0011 vendored)。

层级口径:本目录 = 做题/任务产生的任务级件 + 已验证通用的框架件;插件内置件在
`packages/rs-agent/src/extensions/rust_script/scripts/`(text_* 手术刀、browse、
cookies、lab_alert、page_snapshot、page_interact、reqseq 等已升内置)。任务件被实战
验证"通用、引导后续解题"后,经自省策展升入内置层,不自动灌入。

| 件 | 职责 | 溯源 |
| --- | --- | --- |
| `lab_http.rs` | (已晋 bundled,本地副本退役)cookie-jar HTTP 客户端:get/post/submitform/手工重定向 | IDOR 轮(pi 自写) |
| `chrome_cookies.rs` | Chrome Linux cookie 库离线解密(v10/v11,peanuts 派生键),导出 jar | IDOR 轮(Python 助手 rs 化,监督审查改进项) |
| `lab_launch.rs` | 靶场实例发射整链封装(widget 渲染 + Auth0 OIDC 回放) | IDOR 轮 |
| `objref_scan.rs` | 对象引用枚举(FUZZ 区间/清单探,非 404 命中与长度簇报告) | IDOR 轮 |
| `solved_check.rs` | 实例横幅判读(is-solved + congratulation 行) | IDOR 轮 |
| `gql_alias_brute.rs` | (已晋 bundled,本地副本退役)GraphQL 登录别名爆破:单请求并置 N 个别名的 login mutation 绕限速 | hunter chest 批预置,graphql 批 brute 题首战 |
| `lab_page.rs` | (已晋 bundled,本地副本退役)题面抓取并剥离 solution 折叠块后读,回 widget-lab-id/标题/题面 | GraphQL 批(规则更正后) |
| `html_text.rs` | HTML 手术刀:按标签取文本或属性(`--tag`/`--attr`/`--contains`/`--tokens`,`--out` 落行文件),补 text_* 不做 HTML 结构的空白 | 工具纪律更正后 |
| `json_pick.rs` | JSON 手术刀:对 JSON 文件跑 jaq 过滤取字段,补 text_* 不做 JSON 的空白 | 工具纪律轮 |
| `labkit_sync.rs` |  把项目级件集镜像进可运行全局脚本目录,只拷新增/变更件,幂等 | 工具纪律轮 |
| `header_scan.rs` | 请求头按 FUZZ 数值范围遍历,回命中/基线/长度簇(Host 头 SSRF、vhost 探测) | Host header 批 |
| `raw_http.rs` | 字节级原始请求行(absolute-form/畸形 Host)+ `--ids` FUZZ 遍历 + 自带 TLS,补 ureq 表达不了的解析差 | Host header 批 |
| `conn_reuse.rs` | 单连接字节级重放:同 socket 发 N 个原始请求(random 或 pipelined),内置 CL.TE/TE.CL/混淆 TE 帧构造(`--cl-te`/`--te-cl`/`--te-line`),读回并按 `HTTP/1.` 切分每个响应(状态/首字节时延);raw_http 的反面(逐连接复用) | 请求走私批 |
| `h2_req.rs` | 手写 HTTP/2 客户端(TLS+ALPN h2、自组帧、`hpack` 编解码):pseudo/普通头名值均为调用方可控**字节**(允许 CR/LF 注入),可选 DATA/多流,回读按 stream 归并状态与体;`h2` crate 的 HeaderName/Value 校验发不出此类帧 | 请求走私批(H2 进阶) |
| `jwt.rs` | JWT 手术刀:`decode`;JWKS->SPKI PEM(`pubkey`);两令牌反推模数(`rsa-from-tokens`);HS256 伪造(`forge`/`sign --pem`) | JWT 批 |
| `b64.rs` | base64 手术刀:data-URI/文件解码落盘、文件编码(配合 read 读验证码图) | LLM 批 |
| `ws_chat.rs` | wss 聊天一刀:带 jar 会话连 wss,发 `READY`+`{"message":…}`,读回执(LLM 聊天靶场) | LLM 批 |
| `blind_oracle.rs` | 布尔预言机抽取器:模板含 `{I}`/`{C}`,按位并发试字符、以响应标记判真假(`--place cookie|header|body|query`),盲 SQLi/盲 SSRF 判读 | 盲注入批 |
| `race_send.rs` | 并发赛跑件:预热连接+Barrier 齐发,支持两组 body 变体(`--body/--body2`、`--n` 对、`--a/--b` 计数),单端点竞态 | 竞态批 |
| `race_email.rs` | 邮件改绑竞态驱动:循环齐发 A/B 改邮箱,读收件箱抽确认 token,逐个试 `/confirm-email` 直到被接受 | 竞态批 |
| `http_dump.rs` | 单请求全响应头转储(状态、所有头含 X-Cache/Age、Location、体长度/预览),补 lab_http 看不到的头面;缓存规则探测 | WCD 批 |
| `url_fuzz.rs` | URL 的 FUZZ 矩阵探(FUZZ 换值/字符集),逐值回状态/长度/X-Cache/标记命中;分隔符/路径探测 | WCD 批 |
| `header_fuzz.rs` | 逐请求头带 marker 枚举(Param-Miner 风味),回头部反射/长度/状态差异 + X-Cache/Vary;缓存投毒的未键控头探查 | 缓存投毒批 |
| `sha_brute.rs` | 令牌派生式暴力:按模板(整数秒/毫秒/微秒/uniqid/日期 × user/email/pw 前缀)在区间内匹配 SHA1/SHA256;时间敏感令牌逆向 | 竞态批 |
| `poison_loop.rs` | 定时重复发一条投毒请求(URL+头),保持短 max-age 缓存持久中毒直到访客命中 | 缓存投毒批 |
| `fatget_poison.rs` | 带 body 的 GET 循环续投:body 供 origin 解析、不进缓存键(fat-GET 靶场) | 缓存投毒实现缺陷批 |
| `raw_poison.rs` | 字节级原始请求行循环续投:发 ureq 会重编码的原始 `<`/`>`/`%XX`,配合解码归一化的缓存 | 缓存投毒实现缺陷批 |
| `phpser.rs` | PHP 序列化手术刀:模板中 `%00` 展开为 NUL 字节(私有/保护属性名),输出 serialized/base64/可作 session cookie 的 URL-encoded base64 | 反序列化批 |
| `bin_get.rs` | 二进制下载 + ascii run 抽取:拉取 polyglot/图片等二进制文件到盘,并列出其中可打印 ASCII 串(读 PHAR 内嵌序列化载荷) | 反序列化批 |
| `upload.rs` | multipart/form-data 上传:二进制安全地传文件 + 普通表单字段 + jar cookie(头像/PHAR polyglot/任意文件上传靶场) | 反序列化批 |
| `mut_oracle.rs` | 竞态半构造变异 oracle:模板({I}/{M} 占位)Barrier 齐发 N 对 + 串行基线,报串线 marker/差分簇/谓词命中,判半构造行读面可见性 | 件先行专场(kimi Swarm 铸) |
| `duphost_probe.rs` | 双 Host 表达探针:单连接发两个可配置头,五类判定(rejected-400/first-wins/second-wins/both-reflected/other),--repeat 测稳定性 | 件先行专场(kimi Swarm 铸) |
| `burp_interp.rs` | 拦截代理语义(客户端侧重放,非 TLS 终止):--req 原请求 + set/drop/replace/set-body 改写规则 + jar,--follow 给整链 | 件先行专场(kimi Swarm 铸) |

检索:语义面走 zg(zvec-grep,fts+vector 混合);已升内置的浏览器件
(lab_alert/page_snapshot/page_interact/reqseq+browse/cookies)在产品 catalog。


## 自全局归并件(2026-10-05 清理)

| 件 | 职责 | 溯源 |
| --- | --- | --- |
| `sh_run.rs` | sh -c 执行命令,回退出码/stdout/stderr 信封 | 早期全局件 |
| `cdp_probe.rs` / `jc_probe.rs` | vendored cdp / jc_parse 编译链探针 | vendor 轮/改名轮验收 |
| `diag_env.rs` / `diag_search.rs` / `diag_tools.rs` | 环境与检索诊断三件套 | 扩展验收轮 |
| `collatz.rs` / `digits_demo.rs` / `slowloop.rs` | catalog 冒烟与超时纪律测试件 | rust_script 验收轮 |
| `disk_space.rs` / `find_files.rs` | 磁盘/文件查件 | 早期全局件 |

(旧全局镜像 16 件已清,项目件集为唯一正本;labkit_sync 的镜像使命终结,保留为历史件)
