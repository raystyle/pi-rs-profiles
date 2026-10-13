---
title: twig-sandbox-delete-primitive
---

# twig-sandbox-delete-primitive

受限 Twig 环境里"删除任意文件"的原语组合(实测于 `lab-server-side-template-injection-with-a-custom-exploit`)。

- **属性访问即调用方法**:表达式 `user.X`(无同名属性时)在 Twig 里按方法调用解析,等价 `user.X()` ⇒ 既可用作行为探测,也可直接触发方法。 - **删原语 = symlink 建立 + `readlink`/`unlink` 组合**: 1. `user.setAvatar('/目标/文件','image/png')` —— 应用把该值 `symlink()` 成 `users/<user>/avatar`(只校验 mime 前缀 `image/`)。 2. `user.gdprDelete()` → `rm()` 先 `readlink(users/<user>/avatar)` 取**目标真实路径**,再 `unlink()` ⇒ 删掉的是 symlink 的**目标**,不是链接本身。 - 拿方法名的最快路径:对未建 symlink 的实例调用删除方法会 500,栈里直接写 `User.php(48): User->rm(false)` / `Core.php(1601): User->gdprDelete()`。 - 通用判型:`setAvatar` + `gdprDelete`(命名可变)成对出现是这类题的标准 gadget;`user|json_encode` 只看 public 字段,不足以枚举行为。 - 触发时机:表达式在**渲染**时才求值,所以"投递表达式"与"请求页面触发"是两步;每步都要各请求一次承载页。

## 相关族

- evidences: [[ssti-family]] - records: [[records/lab-server-side-template-injection-with-a-custom-exploit]]

# twig-sandbox-delete-primitive

受限 Twig 环境里"删除任意文件"的原语组合(实测于 `lab-server-side-template-injection-with-a-custom-exploit`)。

- **属性访问即调用方法**:表达式 `user.X`(无同名属性时)在 Twig 里按方法调用解析,等价 `user.X()` ⇒ 既可用作行为探测,也可直接触发方法。 - **删原语 = symlink 建立 + `readlink`/`unlink` 组合**: 1. `user.setAvatar('/目标/文件','image/png')` —— 应用把该值 `symlink()` 成 `users/<user>/avatar`(只校验 mime 前缀 `image/`)。 2. `user.gdprDelete()` → `rm()` 先 `readlink(users/<user>/avatar)` 取**目标真实路径**,再 `unlink()` ⇒ 删掉的是 symlink 的**目标**,不是链接本身。 - 拿方法名的最快路径:对未建 symlink 的实例调用删除方法会 500,栈里直接写 `User.php(48): User->rm(false)` / `Core.php(1601): User->gdprDelete()`。 - 通用判型:`setAvatar` + `gdprDelete`(命名可变)成对出现是这类题的标准 gadget;`user|json_encode` 只看 public 字段,不足以枚举行为。 - 触发时机:表达式在**渲染**时才求值,所以"投递表达式"与"请求页面触发"是两步;每步都要各请求一次承载页。

## 相关族

- evidences: [[ssti-family]] - records: [[records/lab-server-side-template-injection-with-a-custom-exploit]]
