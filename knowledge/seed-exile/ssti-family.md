---
title: SSTI 族:引擎判型与受限环境的利用原语
---

# SSTI 族:引擎判型与受限环境的利用原语

同一类型漏洞:用户输入进了**服务端模板源码**(不是 HTML 上下文),于是模板语法即代码。
与 CSTI/Angular 的区别:执行发生在服务端进程,拿到的是服务器能力(文件/命令)。

## 子型判型矩阵

| 子型 | 判型特征 | 手法方向 | 实录 |
|---|---|---|---|
| PHP Twig(受限环境) | 错误页泄露 `Twig_Error_*` + 版本路径;`filter`/`reduce` 可能被裁 | 破标签 `1}}<tag>{{-1` 后试受限环境里仍存在的回调原语 | [[lab-server-side-template-injection-with-a-custom-exploit]] |
| AngularJS(CSTI) | `<body ng-app>` + `{{ }}` 由浏览器求值 | 见 [[client-side-template-injection-family]] | — |

## 共性

1. **先判引擎**:发一个必然报错的载荷(`{{7*7}}` 是否求值、`{{#…}}`/`{%…%}` 是否语法错),
   错误页常直接给引擎与版本(`Twig_Error_Syntax` + `/usr/local/envs/php-twig-2.4.6/` ✓,还顺带泄露 app 路径)。
2. **判射点形态**:值是被插进 *表达式*(`{{ 值 }}`)还是 *模板源码*——前者不能直接用标签,要先 `}}` 破出去再 `{{` 回来
   (实证:`1}}{{7*7}}{{-1` → 页面显示 `1491` ✓)。
3. **判“被裁掉的原语”**:逐个试经典回调过滤器,错误信息会点名 `Unknown "filter"/"reduce" filter`,即环境裁剪面;
   保留的原语才可继续(sort 在 Twig 2.x 里 arrow 语义是属性名,不是 PHP callable)。同为判型点:受限环境用
   `Twig_Loader_Array`(模板名 `index`)⇒ `source()`/`include()` 读文件不可用 ⇒ 经典 Twig RCE 路断,必须用应用自带对象当 gadget。
4. **文件写入口**(若题目给了上传):留意落点与校验方式:`/tmp/<原始文件名>`,mime 校验读**客户端声明类型**,
   于是“polyglot 图片头 + 模板代码”还不够,必须能控制 multipart 部件的 `Content-Type`(需自造件/raw_http)。
5. **用类型错误读实现**(受限 Twig 里没有 `source()`/`dump()` 时的主要手法):给方法传**错类型**会触发 PHP warning/exception,
   直接点名**文件:行号与所调函数**。实测 `{{user.setAvatar([],'image/png')}}` →
   `symlink() expects parameter 1 to be a valid path … in /home/carlos/User.php on line 35` /
   `Uncaught Exception: Failed to write symlink Array -> users/wiener/avatar … :36`
   ⇒ `setAvatar($file,$mime)` 被确认是 **symlink 原语**(可把 `users/<user>/avatar` 指向任意文件)。
6. **方法枚举用 `user.X is defined`**:对方法名有效(实测只有 `setAvatar` 为 true),比逐个调用(error/副作用)安全。
   另:`user|json_encode` 导出全部 **public** 字段(`user_dir`/`avatarLink`),setAvatar 不碰它们 ⇒ 它只做文件系统动作。

## 判定与收尾要点

- 判定锚点:目标副作用真的发生(目标文件被删)+ `solved_check`;仅“表达式被求值”不算解。
- **symlink 型 gadget 的收尾难点(未收口)**:要“删掉”目标需一个**按解析后路径删除**的动作;
  实测 头像上传分支 / `/avatar` 非图片分支 / `delete()` 都不按解析路径删。
- 题面若警告“乱调方法会把实例弄坏”,每次尝试只跑**定向**命令,别用通配/递归删除。

## 相关族

- 客户端模板注入见 [[client-side-template-injection-family]];反射上下文见 [[xss-context-family]]。
- 工具:内置 `lab_http`/`upload`/`raw_http`(手工 multipart 用)、`solved_check`。
