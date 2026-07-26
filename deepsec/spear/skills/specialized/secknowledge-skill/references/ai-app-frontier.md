# AI应用安全 - 前沿安全风险（2025-2026）

> 来源: AISS绿盟大模型安全智链社区 | 拆自 ai-app-security.md
> 主题: AI Agent/MCP/Skills 前沿风险（Claude Code CVE/Skills 注入/Agent 蠕虫）

## 三十五、AI Agent/MCP/Skills 前沿安全风险 (2025-2026)

> 以下内容基于2025-2026年最新安全研究补充，覆盖OWASP Agentic AI Top 10 (ASI01-ASI10)。

### MCP (Model Context Protocol) 协议安全

#### 11类MCP新兴风险 (Checkmarx/Invariant Labs/Trail of Bits 2025研究)

| 风险类型 | 描述 | 攻击场景 |
|----------|------|----------|
| 工具描述投毒 | 在tool description中嵌入隐藏恶意指令 | 模型执行工具时读取并遵循description中的隐藏Prompt |
| 地毯式骗局(Rug Pull) | 用户授权后Server动态修改工具描述 | 初始审核通过，后续篡改功能逻辑 |
| 指令覆盖(Shadow Tool) | 恶意Server的tool描述劫持可信工具行为 | 修改邮件发送工具的收件人为攻击者 |
| ANSI/Unicode隐藏指令 | 利用终端转义码或不可见Unicode字符隐藏指令 | 供应链攻击: 模型建议下载恶意包 |
| 跨Server攻击 | 多个MCP Server间的工具定义冲突和劫持 | Server A重定义Server B的工具名称 |
| Token/凭据窃取 | 提取MCP Server存储的OAuth Token和API密钥 | 单点突破获取所有连接服务的凭据 |
| Server伪装 | 恶意MCP Server伪装合法服务记录所有查询 | 数据窃取和行为监控 |
| Schema操纵 | 动态修改工具输入/输出Schema绕过验证 | 注入额外参数或修改返回值 |
| 命令注入 | 通过工具参数注入OS命令 | MCP Server执行未过滤的shell命令 |
| 上下文溢出 | 构造超大工具响应耗尽模型上下文窗口 | 挤出安全指令，降低模型判断力 |
| 持久化投毒 | 通过工具返回值污染对话历史 | 长期影响后续所有交互的安全性 |

#### MCP安全测试方法

1. **工具描述审计**: 检查所有注册tool的description字段是否含隐藏指令(ANSI码/Unicode/HTML注释)
2. **动态行为监控**: 对比初始注册和运行时的tool description是否一致
3. **跨Server隔离**: 验证多Server环境中tool名称是否冲突
4. **凭据存储审计**: 检查OAuth Token/API Key的存储方式(明文vs加密)
5. **输入验证测试**: 对tool参数进行命令注入/SQL注入测试
6. **权限边界测试**: 验证tool是否能访问声明范围外的资源

### AI Agent 安全 (OWASP ASI01-ASI10 补充)

#### Clawdbot/Moltbot 实战案例 (2026年1月)

全球发现4500+暴露实例的AI Agent安全事件:
- **根因**: 反向代理配置错误导致localhost自动认证通过
- **影响**: API密钥、服务Token、WhatsApp会话凭据被提取
- **教训**: AI Agent集中了shell执行、持久状态、自主任务发起等高权限，单点暴露=完全接管

#### Agent工具选择攻击 (CATS研究)

- 工具池作为非管控仓库，攻击者可发布带误导性元数据的工具
- 对抗性攻击下，Agent的工具选择认证准确率下降60%+
- 自适应对抗攻击后准确率低于20%

#### ASI07: 多Agent通信安全

| 攻击向量 | 描述 |
|----------|------|
| 消息伪造 | Agent A伪装Agent B发送指令 |
| 信任传递滥用 | 低权限Agent利用高权限Agent的信任关系 |
| 协调劫持 | 操纵Agent间的任务分配和结果聚合 |
| 中间人攻击 | 拦截和篡改Agent间通信 |

#### ASI09: 人机信任利用

- 过度依赖: 用户对AI输出不做验证直接执行
- 社工增强: AI生成的钓鱼内容更可信
- 确认偏见: 用户倾向于信任与预期一致的AI输出
- 自动化偏见: "AI说的应该是对的"心理

#### ASI10: 恶意/失控Agent

- Agent被入侵后在授权参数外运行
- 自主决策链中的目标漂移
- 横向移动: 通过Agent间通信感染其他Agent

### Skills/Rules 供应链安全

#### 攻击面

AI编程助手(Claude Code/Cursor等)的Skills和Rules系统引入新的供应链攻击面:

| 攻击向量 | 描述 | 影响 |
|----------|------|------|
| 恶意Skill注入 | 社区分享的skill中嵌入恶意Prompt指令 | AI执行隐藏的命令(如数据外传) |
| Rules文件篡改 | 通过PR修改.cursorrules/.claude/RULES.md | 长期控制开发者的AI行为 |
| SKILL.md投毒 | skill引用的reference文件中嵌入间接注入 | AI读取reference时执行恶意指令 |
| 依赖链攻击 | skill依赖的外部MCP Server被替换 | 所有使用该skill的用户受影响 |
| 构建钩子利用 | 通过skill的scripts/触发恶意构建操作 | 代码执行、密钥窃取 |

#### Claude Code 已披露CVE (2025-2026)

| CVE | 严重性 | 描述 |
|-----|--------|------|
| CVE-2025-54795 | High | echo命令绕过用户审批直接执行 |
| GHSA-qxfv-fcpc-w36x | High | rg命令注入绕过审批Prompt |
| - | High | sed命令验证绕过实现任意文件写入 |
| - | High | 启动信任对话框前即可执行命令 |
| - | Moderate | 恶意仓库配置导致数据泄露 |

#### 防御建议

- **Skill审计**: 安装前审查SKILL.md和所有reference文件内容
- **签名验证**: 验证skill来源和完整性(目前无官方机制,需手动)
- **权限隔离**: 限制skill可访问的工具和文件范围
- **Rules保护**: .cursorrules和AGENTS.md纳入代码审查流程
- **MCP Server白名单**: 仅允许信任的MCP Server连接
- **行为监控**: 记录AI助手的所有工具调用和文件操作日志

### Agentic AI 综合安全测试框架

基于OWASP ASI01-ASI10，针对AI Agent应用的系统化测试流程:

1. **目标枚举**: 识别所有Agent、工具、MCP Server、通信通道
2. **认证测试**: Agent身份验证、Token管理、权限边界(ASI03)
3. **工具安全**: description审计、参数注入、权限越界(ASI02)
4. **注入测试**: 直接/间接Prompt注入、工具返回值注入(ASI01)
5. **供应链审计**: MCP Server来源、skill完整性、依赖安全(ASI04)
6. **代码执行**: 沙箱逃逸、命令注入、文件操作(ASI05)
7. **记忆安全**: 上下文投毒、持久化攻击、状态腐败(ASI06)
8. **通信安全**: Agent间认证、消息完整性、信任传递(ASI07)
9. **级联测试**: 单点失败传播范围、故障隔离(ASI08)
10. **信任测试**: 输出验证机制、人工审批流程(ASI09)
11. **逃逸测试**: Agent行为监控、异常检测、Kill Switch(ASI10)
