# Web 安全 - 信息泄露

> 来源: WooYun 漏洞库 | 拆自 web-file-infra.md

## 三、信息泄露

### 3.1 漏洞本质

```
信息泄露本质: 攻击面暴露 -> 信任链断裂 -> 纵深渗透
规律: 一个泄露点可导致整条信任链崩溃
      源码 -> 配置 -> 数据库 -> 内网 -> 全部沦陷
```

### 3.2 敏感文件路径字典

版本控制泄露:

```bash
# Git泄露 (检测优先级最高)
/.git/config          # 含远程仓库地址
/.git/HEAD            # 当前分支
/.git/index           # 暂存区索引
/.git/logs/HEAD       # 操作日志

# SVN泄露
/.svn/entries         # SVN 1.6及以下
/.svn/wc.db           # SVN 1.7+ SQLite数据库

# 利用工具: dvcs-ripper, GitHack, svn-extractor
```

备份文件泄露:

```bash
# 压缩包备份 (530例命中)
/wwwroot.rar | /www.zip | /web.rar | /backup.zip | /site.tar.gz
/{domain}.zip | /{domain}.rar

# SQL备份 (136例命中)
/backup.sql | /database.sql | /db.sql | /dump.sql

# 配置备份 (101例命中)
/config.php.bak | /web.config.bak | /.env.bak
/config_global.php.bak
```

配置文件泄露:

```bash
# 通用
/.env | /.env.local | /.env.production
/config.yml | /config.json | /appsettings.json

# PHP
/config.php | /include/config.php | /data/config.php

# Java/Spring
/WEB-INF/web.xml | /WEB-INF/classes/application.properties
/WEB-INF/classes/jdbc.properties

# .NET
/web.config | /connectionStrings.config
```

探针/调试/日志文件:

```bash
# 探针文件
/phpinfo.php | /info.php | /test.php | /probe.php

# 日志文件
/ctp.log | /logs/ctp.log | /debug.log | /storage/logs/

# 管理界面
/phpmyadmin/ | /pma/ | /adminer.php
/swagger-ui.html | /api-docs
/actuator/env                    # Spring Boot
```

### 3.3 探测方法论

```
Phase 1 被动收集: 响应头(Server/X-Powered-By) -> 错误页面 -> robots.txt -> 源码注释/JS
Phase 2 定向探测: 版本控制(.git/.svn) -> 备份文件(域名/日期) -> 敏感路径
Phase 3 搜索引擎: Google Hacking语法
```

Google Hacking速查:

```
site:target.com filetype:sql | filetype:bak | filetype:zip
site:target.com filetype:env | filetype:log
site:target.com inurl:.git | inurl:.svn
site:target.com inurl:phpinfo | intitle:phpinfo
site:target.com "db_password" | "mysql_connect"
```

### 3.4 信息利用链

```
源码泄露   -> 配置文件 -> 数据库凭证 -> 数据库接管 -> 服务器提权
版本控制   -> 源码审计 -> SQL注入等  -> 管理权限   -> 文件上传getshell
配置泄露   -> DB连接串 -> 数据库    -> 用户数据   -> 业务接管
日志泄露   -> Session  -> 身份劫持  -> 业务数据   -> 横向移动
API接口    -> 凭证/密码 -> 解密     -> 批量控制   -> 全面渗透
第三方凭证 -> 短信/OSS -> 验证码    -> 账户接管   -> 数据泄露
```

### 3.5 防御措施

Nginx安全配置:

```nginx
location ~ /\.(git|svn|env|htaccess|htpasswd) { deny all; return 404; }
location ~ \.(bak|sql|log|config|ini|yml)$ { deny all; return 404; }
location ~* /(backup|bak|old|temp|test|dev)/ { deny all; return 404; }
autoindex off;
server_tokens off;
```

Apache安全配置:

```apache
<FilesMatch "\.(git|svn|env|bak|sql|log|config)">
    Order Allow,Deny
    Deny from all
</FilesMatch>
Options -Indexes
ServerSignature Off
```

CI/CD集成: 部署前扫描敏感文件 -> 禁止.git/.svn部署 -> 配置文件加密

---

