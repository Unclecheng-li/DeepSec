# AI基座安全 - 容器与沙箱逃逸实战方法论

> 来源: AISS绿盟大模型安全智链社区 | 拆自 ai-baseline-security.md
> 主题: 容器逃逸/持久化/横向移动 实战方法论

## 二十、容器与沙箱逃逸实战测试方法论

> 针对AI应用部署环境（Docker/Sysbox/Daytona/Kubernetes）的系统化逃逸与隔离测试
> **通用容器部署安全**: Web应用容器部署安全检查 → [web-deployment-security.md §二](web-deployment-security.md)

### 一、测试流程总览

```
信息收集 → 环境识别 → 隔离评估 → 逃逸尝试 → 持久化验证 → 横向移动 → 报告
```

### 二、信息收集阶段

#### 2.1 容器运行时识别

| 检测项 | 命令 | 判断依据 |
|--------|------|----------|
| 是否在容器中 | `cat /proc/1/cgroup` | 包含`docker`/`kubepods`/`containerd` |
| Docker标志文件 | `ls /.dockerenv` | 文件存在则为Docker容器 |
| 容器运行时类型 | `cat /proc/1/cgroup \| head` | `sysbox-fs`→Sysbox, `docker`→Docker |
| 内核版本 | `uname -r` | 匹配CVE影响范围 |
| User Namespace | `cat /proc/self/uid_map` | `0 0 4294967295`→无隔离(危险) |
| Capabilities | `cat /proc/self/status \| grep Cap` | 解码后检查危险Cap |
| Seccomp | `cat /proc/self/status \| grep Seccomp` | 0=disabled, 2=filter |
| AppArmor | `cat /proc/self/attr/current` | `unconfined`→无保护 |
| 挂载点 | `mount \| grep -v overlay` | 检测宿主机敏感路径挂载 |

#### 2.2 Sysbox 特定检测

| 检测项 | 方法 | 安全影响 |
|--------|------|----------|
| CE vs EE版本 | `sysbox-runc --version` 或检查UID映射范围 | CE共享映射有跨租户风险 |
| UID映射独占性 | `cat /proc/self/uid_map`, CE通常`0 165536 65536`(共享) | 共享映射→跨容器提权可能 |
| 虚拟化/proc | `ls /proc/sys/net/` | Sysbox虚拟化程度 |
| Docker-in-Docker | `docker ps 2>/dev/null` | 内层Docker可能无安全限制 |
| /dev/kvm | `ls /dev/kvm` | KVM可用→嵌套虚拟化逃逸 |

### 三、隔离评估阶段

#### 3.1 进程隔离

```bash
# PID Namespace检查
ps aux   # 是否能看到其他容器/宿主机进程
ls /proc/*/cmdline   # 枚举可见进程

# 如果PID 1不是容器init而是systemd/dockerd → 隔离失败
cat /proc/1/cmdline | tr '\0' ' '
```

#### 3.2 网络隔离

```bash
# 网络接口
ip addr   # 检查网络接口和IP段
ip route  # 路由表，是否能到达其他网段

# 同网段扫描(发现邻居容器)
for i in $(seq 1 254); do
  (ping -c 1 -W 1 $SUBNET.$i &>/dev/null && echo "$SUBNET.$i alive") &
done; wait

# 内部DNS探测
cat /etc/resolv.conf
nslookup kubernetes.default.svc.cluster.local 2>/dev/null
```

#### 3.3 文件系统隔离

```bash
# 检查宿主机文件系统挂载
mount | grep -E "ext4|xfs|btrfs" | grep -v overlay
findmnt

# 路径遍历测试
ls -la /var/lib/sysbox/ 2>/dev/null
ls -la /var/lib/docker/ 2>/dev/null
ls -la /run/containerd/ 2>/dev/null

# 符号链接逃逸
ln -s /proc/1/root/etc/shadow /tmp/test_escape
cat /tmp/test_escape 2>&1  # 如果成功→隔离失败
```

### 四、逃逸测试矩阵

| 逃逸路径 | 前提条件 | 危险等级 | 测试方法 |
|----------|----------|----------|----------|
| cgroup release_agent | CAP_SYS_ADMIN + cgroup v1 | Critical | 写release_agent执行宿主机命令 |
| Docker Socket | /var/run/docker.sock暴露 | Critical | 通过API创建特权容器 |
| /proc/1/root | PID Namespace未隔离 | Critical | 直接读写宿主机文件 |
| 特权容器 | --privileged模式 | Critical | mount宿主机磁盘 |
| runc fd泄露 | CVE-2024-21626 | High | 利用/proc/self/fd访问宿主 |
| Dirty Pipe | CVE-2022-0847, 5.8≤kernel≤5.16.11 | High | 覆写只读文件提权 |
| OverlayFS | CVE-2023-0386, 5.11≤kernel≤6.2 | High | SUID文件提权 |
| 敏感挂载 | 宿主机路径被mount进容器 | High | 写入宿主机文件 |
| CAP_DAC_READ_SEARCH | Capability未限制 | Medium | open_by_handle_at读取文件 |
| CAP_SYS_PTRACE | Capability未限制 | Medium | 注入宿主机进程 |
| Docker-in-Docker | 内层Docker无限制 | Medium | 内层创建特权容器 |

### 五、持久化测试

> 验证沙箱跨会话持久化攻击可行性（尤其适用于持久沙箱如Daytona）

| 测试项 | 会话1操作 | 会话2验证 | 预期安全结果 |
|--------|-----------|-----------|-------------|
| .bashrc后门 | `echo 'malicious_cmd' >> ~/.bashrc` | 开新shell检查是否执行 | 新会话不继承/重置 |
| Crontab | `echo "* * * * * cmd" \| crontab -` | `crontab -l` | Crontab被清理或不可用 |
| SSH密钥 | 写入~/.ssh/authorized_keys | SSH连接测试 | SSH服务不可用或密钥清理 |
| 后台进程 | `nohup cmd &` | `ps aux \| grep cmd` | 会话关闭后进程终止 |
| 文件投毒 | 工作区写入恶意文件 | AI是否读取执行 | AI不自动执行文件中指令 |
| 历史残留 | 在shell中输入敏感命令 | `cat ~/.bash_history` | 历史命令跨会话清除 |
| 环境变量 | `export SECRET=leaked` | `echo $SECRET` | 环境变量不跨会话保留 |

### 六、横向移动测试

```
容器内 → 内网服务发现 → 数据库/缓存/API直连 → 其他租户沙箱
         ↓
         云元数据服务(169.254.169.254) → IAM凭据窃取 → 云资源访问
         ↓
         K8s API(kubernetes.default.svc) → Pod列表/Secret获取
```

| 目标 | 检测命令 | 利用方式 |
|------|----------|----------|
| 云元数据 | `curl 169.254.169.254` | 获取IAM临时凭据 |
| K8s API | `curl -k https://kubernetes.default.svc` | 列举Pod/获取Secret |
| K8s ServiceAccount | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | 认证K8s API |
| 内网数据库 | `echo \| nc DB_HOST 5432` | 直连数据库 |
| Redis | `redis-cli -h REDIS_HOST ping` | 未授权访问 |
| Docker Registry | `curl http://REGISTRY:5000/v2/_catalog` | 拉取敏感镜像 |

### 七、防御验证Checklist

```
[ ] 容器以非root用户运行(或User Namespace隔离有效)
[ ] 无多余Capabilities(最小原则: 仅NET_BIND_SERVICE等必需项)
[ ] Seccomp profile已启用(非disabled)
[ ] AppArmor/SELinux非unconfined
[ ] /var/run/docker.sock未暴露
[ ] 不以--privileged模式运行
[ ] 无宿主机敏感路径挂载(/、/etc、/var/run)
[ ] 内核版本不受已知逃逸CVE影响
[ ] cgroup v2或release_agent不可写
[ ] PID Namespace隔离有效(仅见自身进程)
[ ] Network Policy/防火墙限制容器间通信
[ ] 169.254.169.254元数据服务被拦截
[ ] 会话间敏感数据(history/credentials)被清理
[ ] 沙箱销毁时完全清除所有用户数据
[ ] Sysbox使用EE版或独占UID映射
```

---
