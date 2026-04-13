

<p align="center">
  <a href="https://github.com/matrixleons/evilwaf/stargazers">
    <img src="https://img.shields.io/github/stars/matrixleons/evilwaf?style=flat-square" alt="Stars">
  </a>
  <a href="https://github.com/matrixleons/evilwaf/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

---

**EvilWAF** 是一款先进的透明 MITM 防火墙绕过代理与深度 WAF 漏洞扫描器，专为授权安全测试而设计。它工作在传输层——不会修改来自您工具的载荷、Cookie 或请求头。可与任何支持 `--proxy` 参数的工具配合使用（如 `ffuf`、`sqlmap`、`nuclei` 等）。

---

## 功能特性

### 代理与绕过
- **透明 MITM 代理** — 适用于所有支持 `--proxy` 的工具，工具侧无需额外配置。
- **TCP 指纹轮换** — 每次请求轮换 TCP 协议栈选项，规避行为检测。
- **TLS 指纹轮换** — 每次请求轮换 TLS 指纹（JA3/JA4 风格），与 TCP 配置文件配对使用。
- **HTTP/2 指纹轮换** — 逐请求轮换 H2 SETTINGS 帧与 HEADERS 帧配置文件，循环使用 Chrome、Firefox、Safari、Edge 浏览器配置，防止 WAF 行为指纹识别。
- **源端口操控** — 每次请求轮换源端口，破坏依赖源端口一致性的 WAF 会话追踪与限速计数器。
- **Cloudflare 头注入** — 注入 Cloudflare 专属内部请求头（`CF-Connecting-IP`、`CF-Ray`、`True-Client-IP`），通过精心构造的值测试 WAF 对上游头的信任并尝试 IP 白名单绕过。
- **Tor IP 轮换** — 通过 Tor 路由流量，每次请求自动轮换出口 IP。
- **代理池 IP 轮换** — 通过外部代理池每次请求轮换 IP。
- **源站 IP 探测** — 使用 10 个并行扫描器发现 WAF 后面的真实服务器 IP：
  - DNS 历史、SSL 证书分析、子域名枚举
  - DNS 错误配置、云泄露检测、GitHub 泄露搜索
  - HTTP 头泄露、favicon 哈希、ASN 范围扫描、Censys
- **自动 WAF 检测** — 在绕过开始前自动检测 WAF 厂商。
- **直接源站绕过** — 一旦找到真实 IP，所有流量直接路由到服务器，完全跳过 WAF。
- **全量 HTTPS MITM** — 通过动态逐主机证书生成，拦截并检查 HTTPS 流量。
- **HTTP/2 & HTTP/1.1 支持** — 自动协商 ALPN，透明处理两种协议。
- **响应顾问** — 遇到 WAF 拦截（403、429、503）时，自动以不同技术重试。

### WAF 漏洞扫描器
- **深度多层 WAF 扫描器** — 将防火墙本身作为目标，跨 10 个独立扫描层同步分析所有 WAF 防御层：
  - `第 1 层  网络` — 虚拟主机绕过、敏感路径探测、Host 头操控
  - `第 2 层  规则引擎` — 基于载荷的规则缺口检测：SQLi、XSS、RCE、LFI
  - `第 3 层  限速` — 突发与持续限速策略测试
  - `第 4 层  逃逸` — 编码与规范化绕过，每个载荷 10 种编码变体
  - `第 5 层  行为` — 时序分析：限速陷阱、JS 挑战延迟、退避检测
  - `第 6 层  请求头` — HTTP 头注入与 IP 欺骗绕过
  - `第 7 层  TLS` — TLS 版本探测、SNI 绕过、证书指纹识别
  - `第 8 层  HTTP 方法` — HTTP 方法/动词绕过，包含 WebDAV 方法
  - `第 9 层  会话` — Cookie 操控、认证绕过、会话固定探测
  - `第 10 层 错误配置` — WAF 错误配置与信息泄露检测
- **持久化会话** — 每次扫描与历史 JSON 数据合并。置信度随时间增长——扫描时间越长，结果越准确。
- **统计置信度引擎** — 使用均值、标准差和稳定性分析计算每层置信度分数。经 15 次验证后置信度达 86% 的发现是真实漏洞，而非噪音。
- **误报验证** — 每项发现在上报前均与干净基线重放比对，无法复现的发现自动排除。
- **C 扩展** (`_fast_scanner.c`) — 高性能 Python C 扩展，用于分类、熵分析、时序异常检测和统计热路径。

### 界面
- **TUI 仪表盘** — 实时终端 UI，展示实时流量、当前技术、Tor IP、源端口、代理池及各层扫描发现。
- **无头模式** — `--no-tui` 标志用于脚本和 CI/CD 流水线。
- **仅扫描模式** — `--scan-only` 单独运行 WAF 漏洞扫描器，不启动代理。

---

<details>
<summary><strong>关于 Cloudflare 与研究背景</strong></summary>

<br>

### 为何选择 Cloudflare？

Cloudflare 被广泛认为是当今世界上最复杂的 Web 应用防火墙。它不仅仅是一组规则——而是一套多层防御体系，通过多种技术协同工作来保护 Web 应用。

在网络层面，Cloudflare 在全球数百个数据中心运营，每个请求都经过具备数百万网站流量模式可见性的基础设施。这种全球可见性是其最强大的优势之一——它能在全球任何地方检测到正在出现的攻击模式，并在数秒内在所有受保护资产上部署缓解措施。

在检测层面，Cloudflare 同时从多个维度分析请求：TCP/IP 指纹、TLS 指纹、HTTP/2 帧结构、头部顺序、请求时序、跨会话行为模式以及载荷内容。任何单一信号都不足以拦截请求，但 Cloudflare 会将所有信号综合关联，为每个请求构建风险评分。

机器学习组件是 Cloudflare 与传统 WAF 本质不同之处。基于规则的 WAF 寻找已知的恶意模式，而 Cloudflare 的 ML 模型则在 PB 级真实攻击流量上训练。它们学习传输层合法浏览器流量的特征——TCP 选项的精确序列、TLS ClientHello 的精确结构、HTTP/2 SETTINGS 帧的顺序——并标记任何偏离基线的行为，即使载荷本身看起来是干净的。这就是为什么仅对载荷编码或轮换请求头不足以绕过 Cloudflare 的原因。绕过必须发生在传输层，而非应用层。

### 为何 Cloudflare 难以绕过？

大多数 WAF 绕过技术针对规则引擎——混淆载荷、使用编码变体、将攻击字符串分散到多个参数。这些技术对基于签名的 WAF 有效，因为这类 WAF 只检查载荷内容。

Cloudflare 的防御在载荷被检查之前就已生效。来自 Python HTTP 库的请求，即使发送完全无害的载荷，也可能因为 TLS 指纹与任何已知浏览器不匹配而被挑战或拦截。这意味着发出请求的工具在内容被分析之前就已被识别。Cloudflare 称之为行为指纹，这也是标准渗透测试工具在面对 Cloudflare 时失效的主要原因，即使底层载荷是正确的。

Cloudflare 的限速同样智能——它不仅仅是每 IP 每秒请求数的计数器。它跟踪跨会话的请求模式，关联同一 ASN 下不同 IP 的行为，并采用渐进式挑战而非硬性拦截，使得通过自动化测试难以检测到阈值。

### 开发者的研究方法

EvilWAF 的开发者将 Cloudflare 视为研究对象，而非攻击目标。研究方法论系统化：观察 Cloudflare 对不同传输层身份的响应，测量哪些信号触发挑战、拦截或静默放行，并从实时数据构建其行为的统计模型。

这与阅读文档或研究 CVE 有本质区别。Cloudflare 的行为无法从外部资源完全理解，因为它在持续变化——模型被重新训练，阈值被调整，新信号被添加。唯一可靠的理解方式是通过实时、受控、授权的实验和对收集数据的仔细分析。

这项研究的目标是产出工具和知识，帮助安全研究社区理解 2026 年 WAF 绕过在技术层面的真实面貌——不是为了造成危害，而是确保防御者了解他们所依赖技术的真实能力与局限性。理解 Cloudflare 如何检测和拦截请求的安全研究员，能更好地测试其背后的应用是否真正得到了保护。

EvilWAF 的扫描器架构——持久化会话、统计置信度、多层分析、时序异常检测——之所以存在，是因为这类研究需要长期观察和严格的数据收集，而非快速扫描。真正的 WAF 研究需要时间，工具应当反映这一点。

</details>

---









## 免责声明

**重要：使用 EvilWAF 前请阅读此内容**
- 本工具仅用于**授权安全测试**
- 您必须获得**明确许可**方可测试目标系统
- 仅供**教育目的**、**安全研究**及**授权渗透测试**使用
- **不得用于恶意或非法活动**

### 法律合规
- 用户对本工具的使用方式承担全部责任
- 开发者对任何滥用或造成的损害**不承担任何责任**
- 请确保遵守当地、省级及国家法律法规

---

## 支持

本人不提供非法用途的支持，但将帮助您在授权测试中实现目标。

[LinkedIn](https://www.linkedin.com/in/matrix-leons-77793a340)

**EvilWAF** 由 Matrix Leons 创建。

---

## 支持本项目

如果 EvilWAF 对您有所帮助，欢迎支持其开发。您的贡献有助于保持本项目的维护与成长。

<p align="center">
  <a href="https://store.pesapal.com/supportmywork">
    <img src="https://img.shields.io/badge/Donate-Support%20the%20Project-brightgreen?style=for-the-badge" alt="Donate">
  </a>
</p>

**[捐赠](https://store.pesapal.com/supportmywork)**

感谢您的支持，非常感谢。

---

## CA 证书配置（HTTPS 必需）

```bash
# EvilWAF 启动时自动生成本地 CA 以拦截 HTTPS 流量，需信任一次。

# 先运行 EvilWAF——CA 在启动时自动生成
# 然后查找证书：
ls /tmp/evilwaf_ca_*/evilwaf-ca.pem

# Linux——系统级信任
sudo cp /tmp/evilwaf_ca_*/evilwaf-ca.pem /usr/local/share/ca-certificates/evilwaf-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  /tmp/evilwaf_ca_*/evilwaf-ca.pem

# 对于 sqlmap 等工具，请传入 --ignore-proxy=False 或您工具的等效参数。
```

---

## 安装

```bash
# 1. 创建虚拟环境
python3 -m venv myenv

# 2. 激活虚拟环境
source myenv/bin/activate

# 3. 克隆并安装
git clone https://github.com/matrixleons/evilwaf.git
cd evilwaf
pip3 install -r requirements.txt

# 4. 编译 C 扩展（可选，提升扫描器性能）
python setup_fast_scanner.py build_ext --inplace

python3 evilwaf.py -h
```

### Docker 安装

```bash
docker build -t evilwaf .
docker run -it evilwaf -t https://example.com
```

---

## 使用方法

```bash
# 基础用法——标准代理模式
python3 evilwaf.py -t https://target.com

# 自动探测 WAF 后方源站 IP
python3 evilwaf.py -t https://target.com --auto-hunt

# EvilWAF 并行运行 10 个扫描器，按置信度排序候选项，然后询问：
#   [?] 是否使用 1.2.3.4 作为源站 IP 进行绕过？[y/n]:
# 确认后，所有流量直接发往真实服务器，完全绕过 WAF。

# 手动指定源站 IP（已知时）
python3 evilwaf.py -t https://target.com --server-ip 1.2.3.4

# 启用 Tor IP 轮换
python3 evilwaf.py -t https://target.com --enable-tor

# 无头模式（不显示 TUI）
python3 evilwaf.py -t https://target.com --no-tui

# WAF 漏洞扫描器——与代理同时运行
python3 evilwaf.py -t https://target.com --scan-vulns

# WAF 漏洞扫描器——独立运行，不启动代理
python3 evilwaf.py -t https://target.com --scan-only

# WAF 漏洞扫描器——自定义速率与输出
python3 evilwaf.py -t https://target.com --scan-only --scan-rps 5.0 --scan-output ./results

# 上游代理
python3 evilwaf.py -t https://target.com --upstream-proxy socks5://127.0.0.1:1080
python3 evilwaf.py -t https://target.com --upstream-proxy http://user:pass@proxy.com:8080
python3 evilwaf.py -t https://target.com --proxy-file proxies.txt

# 自定义监听地址与端口
python3 evilwaf.py -t https://target.com --listen-host 0.0.0.0 --listen-port 9090
```

### 连接您的工具

EvilWAF 运行后，通过代理将任意工具指向它：

```bash
# sqlmap
sqlmap -u "https://target.com/page?id=1" --proxy=http://127.0.0.1:8080 --ignore-proxy=False

# ffuf
ffuf -u https://target.com/FUZZ -x http://127.0.0.1:8080

# nuclei
nuclei -u https://target.com -proxy http://127.0.0.1:8080

# curl（用于测试）
curl -x http://127.0.0.1:8080 https://target.com
```

### API 密钥（可选）

```bash
export SHODAN_API_KEY="your_key"
export SECURITYTRAILS_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
```

未配置 API 密钥时，EvilWAF 仍可使用免费来源运行（DNS 历史、SSL 证书、HTTP 头、favicon 哈希、子域名枚举）。

---

## 贡献

欢迎贡献代码。EvilWAF 持续成长，有许多值得改进的领域。

```bash
# Fork 并克隆
git clone https://github.com/matrixleons/evilwaf/fork
git checkout -b my-new-feature
git commit -am 'Add some feature'
git push origin my-new-feature
# 提交 Pull Request
```

### 贡献指南
- 保持代码整洁，与现有风格一致
- 提交 PR 前测试您的更改
- 不要创建修改被代理请求的 body、headers、payloads 或 cookies 的技术
- 对于大型更改，请先开 issue 进行讨论

---

## 许可证

基于 Apache License 2.0 授权
