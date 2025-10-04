# make-mihomo-envs
Mihomo 一键搭建配置脚本（macOS arm64）可用做网关代理

![Watchers](https://img.shields.io/github/watchers/469138946ba5fa/make-mihomo-envs) ![Stars](https://img.shields.io/github/stars/469138946ba5fa/make-mihomo-envs) ![Forks](https://img.shields.io/github/forks/469138946ba5fa/make-mihomo-envs) ![Vistors](https://visitor-badge.laobi.icu/badge?page_id=469138946ba5fa.make-mihomo-envs) ![LICENSE](https://img.shields.io/badge/license-CC%20BY--SA%204.0-green.svg)
<a href="https://star-history.com/#469138946ba5fa/make-mihomo-envs&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=469138946ba5fa/make-mihomo-envs&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=469138946ba5fa/make-mihomo-envs&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=469138946ba5fa/make-mihomo-envs&type=Date" />
  </picture>
</a>

本脚本用于在 **macOS** 系统上自动化完成以下任务：

* 注意本脚本不会自动安装 python 环境，每个人的系统都很复杂，请自行安装挑选 python 环境
* 安装依赖工具（如 `brew`, `ggrep`, `unar` 等）
* 下载并配置 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核
* 在线订阅转换并生成 Clash 兼容的配置文件
* 配置本地 UI、Geo 数据文件
* 自动生成并启动本地代理服务
* 提供可执行启动脚本 `mihomo-start.sh`

---

## ⚠️ 注意事项
* 需要提前设置好有线网卡 en0 为固定的 ip gateway dns 比如我的路由器 ip 是 192.168.255.254 内网环境是 192.168.255.0/24 macmini 设备 en0 的 ip 192.168.255.253 gateway 和 dns 一样配置为路由器 ip 192.168.255.254 这样保证本机可以访问内网
* 😑关于先有鸡还是先有蛋的问题，说来可笑想搭建代理环境，必须要有代理环境，哎，太可笑了，太可悲了，哎
  * 本脚本会安装 brew ggrep 和 unar 工具，这需要代理环境，请配置临时代理环境执行本脚本直到结束，哎
* 本脚本依赖 python 环境请自行好提前准备好，本脚本会生成 python 脚本，用于解决在线转换的yaml节点无法解析的问题
  * 问题分析
    * 比如 FATA[date] Parse config error: yaml: line num: did not find expected node content 原因如下
    * 那是由于在线订阅转换链接转换的节点有时候用了 YAML 行内简写结构 {}，其中嵌套的 ws-opts 再次使用 {}，造成了 YAML 无法准确解析结构层次的问题
    * YAML 对 {} 的嵌套解析非常敏感，嵌套中 headers 没有适当引号包裹的值（如 Host），path: 字段值中含有 /@xxx 这类特殊字符没加引号
    * 需要用 Python 或 YAML 专用工具转换将每个行内简写结构 {} 展开为 YAML 格式，就可以被正常解析了
* 如需**全局路由**，请将路由器 DHCP 下发的 Gateway 和 DNS 强制为本机 IP，不要将 DNS 设置为 fake-ip 地址
* 如需**旁路由**，请将路由器或设备 Gateway 和 DNS 强制为本机 IP，不要将 DNS 设置为 fake-ip 地址
* 如需**端口代理**，请将联网代理设置为本机 IP:7890
* 若出现网络策略未生效，请检查系统是否允许 `utun` 接口访问网络
* 为启用系统级转发，会尝试设置 `net.inet.ip.forwarding=1`，需要管理员权限
* 本脚本会自己检测桌面是否包含 $HOME/Desktop/mihomos 目录，如果存在则会自动拼接 uuid 作为新目录在桌面创建
  * 例如 $HOME/Desktop/mihomos-19AF2BFC-8B73-4678-992C-01BE6045C635

## 💻 支持平台

* 支持 **macOS**
* 额支持 ARM 架构

---

## 🚀 使用方法(假设默认创建的是 $HOME/Desktop/mihomos 目录)

1. 打开终端下载脚本，例如：

   ```bash
   cd $HOME/Desktop
   curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o 'make-mihomo-env.sh' 'https://github.com/469138946ba5fa/make-mihomo-envs/raw/refs/heads/master/make-mihomo-env.sh'
   ```

2. 给脚本授权并执行：

   ```bash
   chmod +x ./make-mihomo-env.sh
   ./make-mihomo-env.sh
   ```

3. 根据提示输入以下内容（可回车使用默认值）：

   * 订阅链接（可自定义或使用默认）
   * 规则策略模板链接
   * 在线订阅转换 API 链接

4. 安装完成后，将生成配置文件与可执行二进制：

   ```
   $HOME/Desktop/mihomos
   ├── base_config.yaml
   ├── config.yaml
   ├── mihomo
   ├── mihomo_config
   │   ├── cache.db
   │   ├── geoip.metadb
   │   ├── geosite-cn.mrs
   │   ├── ui
   │   └── ui.zip
   ├── mihomo-darwin-arm64.gz
   ├── mihomo-start.sh
   ├── out_config.yaml
   ├── subs-fix.py
   └── temp_config.yaml
   ```

5. 按照脚本提示启动 Mihomo tun 代理：

   ```bash
   # 订阅链接下载处理等会固化在 mihomo-start.sh 脚本中，此后想用就直接执行这个脚本即可
   $HOME/Desktop/mihomos/mihomo-start.sh
   ```

---

## 📦 自动安装依赖

本脚本将检查并自动安装以下依赖：

* `Homebrew`（若未安装则自动安装）
* `ggrep`（替代系统 grep，支持增强语法）
* `unar`（用于解压 `.gz`, `.zip` 文件）

---

## 🧩 配置说明

* 默认配置启用了 **TUN 模式** 和 **Fake-IP DNS 模拟**，适用于全局代理、旁路由和端口代理
* 配置文件路径：`$HOME/Desktop/mihomos/config.yaml`
* Web UI 端口：`http://localhost:9999/ui/`
* 默认监听端口：
  * external-controller: 9999
  * http/socks5 代理：7890
  * dns：53

---

## 🔧 自定义订阅转换

本脚本支持通过在线 API 将原始订阅链接转换为 Clash 格式。

默认 API 为：

```
https://sub.d1.mk/sub
```

可自行替换为其他 Clash 订阅转换服务，只需支持如下参数结构：

```
?target=clash&insert=true&url=<订阅链接>&config=<规则模板链接>
```


---

## ❓ 常见问题

**Q: 为什么 brew 安装失败？**  
A: 说来有些可笑，你可能需要为了搭建代理环境而不得不临时使用代理完成这个流程，属实是有些`先有鸡还是先有蛋`了，如果你有能力确实可以修改优化这个脚本，比如将全部链接换成国内网路支持的版本，这样就能完成整套流程了。


**Q: 为什么 curl 命令在脚本中不生效？**  
A: 可能是 `$SUB_URL` 未被正确 URL 编码，脚本已内置编码函数 `urlencode()`。若有问题请手动检查 `${TMP_FILE}` 是否为空。


**Q: 为什么通过7890端口能访问的网站，而通过路由器强制下发DHCP却报错ssl_cert相关的问题？**  
A: 这涉及到一个非常经典的问题，我的配置文件用的 `fake-ip` 作为 `DNS` 解析策略，TUN + fake-ip + MITM 是直接接管 TCP 流量并劫持 TLS，所以需要伪造证书与客户端完成握手。  
如果证书未被信任、缺失、SAN 不匹配，就会触发 ssl_cert 或 certificate_verify_failed 报错。  
7890 走的是 HTTP 代理协议（即使访问的是 HTTPS），浏览器先发一个 CONNECT 请求到代理，代理只是转发 TLS 流量，不解密，所以不需要伪造证书。  

---
注意，以下步骤不用尝试了，这是个美丽的幻想，mihomo内核是不支持内置mitm，所以要么选择外挂mitm工具，要么选择sing-box，而sing-box更新的又太激进了，维护起来何其费力，难道就没有两全其美的方案？  
确实没有 -> <a href="https://github.com/MetaCubeX/mihomo/issues/2143#issuecomment-3018382470" target="_blank">MetaCubeX/mihomo#2143 (comment)</a>

---

* 在 MITM 工具（如 mihomo、mitmproxy）中，你自己生成的 `ca.crt` 就是根证书，它用来签发伪造的“中间证书”或“网站证书”，让客户端误以为是合法的。
* 原理是在代理节点，一方面与服务端建立正常的 TLS 连接（代理扮演客户端）；另一方面伪造服务器证书，与客户端建立新的 TLS 连接（代理扮演服务器）
```plaintext
Client <---TLS--->[中间人代理]<---TLS--->Server
```
* 证书链是啥？简单来说就是证书链是从网站证书一路向上追溯到根证书的过程。比如：
```plaintext
[你访问的网站证书] ← [中间证书] ← [根证书]
```
* 关于 mihomo 解密https流量，达到7890端口访问的明文效果，也就是 ，你可以尝试以下操作。  
* 注意，这个步骤我不会写到脚本里，证书链永远都是个危险的尝试，永远不要尝试自己不理解的知识，会坠入深渊。  
* 不到万不得已，不推荐你搞，懂吧？自己对自己负责吧。  
  - 1. 安全性：伪造证书认证可能会导致敏感数据泄露或系统被攻击。确保此操作仅用于测试环境，不要在生产环境中使用，不能用于窃取他人数据。  
  - 2. 合法性：解密 HTTPS 流量可能涉及隐私和法律问题，请确保你的操作符合相关法律法规。  
  - 3. 证书管理：生成的证书需要妥善管理，避免泄露或被滥用，千万不要泄露 `ca.key` 否则别人可以伪造你的证书，冒充任何网站。  
  - 4. 某些启用 HPKP / 证书透明（CT）的站点会拒绝被 MITM。
* 我该说的也说完了，那就开始吧。

---

* **1. 生成并信任 CA 根证书**
  * **注意 `$HOME/Desktop/mihomos/mihomo_config/certs/openssl.cnf` 文件中的部分内容请自行修改**
    * **IP.2 = 192.168.255.253 是你的内网 IP（`ifconfig` 查）**
    * **DNS.2 = 469138946ba5fa-Mac-mini.local 是你的内网主机名（`hostname` 查）**
* 

```bash
# 创建存放目录
mkdir -p "$HOME/Desktop/mihomos/mihomo_config/certs"
chmod 700 "$HOME/Desktop/mihomos/mihomo_config/certs"

# 新建文件 openssl.cnf，内容如下（注意修改 [alt_names] 里可添加更多你想信任的域名/IP）
# 其中 IP.2 = 192.168.255.253 是我主机局域网ip
cat << '469138946ba5fa' | tee $HOME/Desktop/mihomos/mihomo_config/certs/openssl.cnf
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C = CN
ST = Test
L = Test
O = Test
OU = Test
CN = Mihomo CA

[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = localhost
DNS.2 = 469138946ba5fa-Mac-mini.local
IP.1 = 127.0.0.1
IP.2 = 192.168.255.253
IP.3 =  ::1
469138946ba5fa

# 生成 100 年有效期的 Mihomo CA 证书根证书（私钥 + 公钥）
openssl req -x509 -newkey rsa:2048 -sha256 -days 36500 -nodes \
  -keyout $HOME/Desktop/mihomos/mihomo_config/certs/ca.key \
  -out $HOME/Desktop/mihomos/mihomo_config/certs/ca.crt \
  -config $HOME/Desktop/mihomos/mihomo_config/certs/openssl.cnf \
  -extensions v3_ca

chmod 600 "$HOME/Desktop/mihomos/mihomo_config/certs/ca.key"

# 导入并信任 Mihomo CA 证书到 macOS 系统
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "$HOME/Desktop/mihomos/mihomo_config/certs/ca.crt"
```

  * **可验证 `Mihomo CA` 证书是否添加：**

```bash
security find-certificate -c "Mihomo CA" /Library/Keychains/System.keychain
# 有输出则已添加
```

---

* **2. 尝试关闭跳过证书认证，并尝试添加伪造证书文件配置中，位置自己找并修改，如果有重复的参数请自行检查原始对应参数替换**
  * **如果没执行过脚本 `make-mihomo-env.sh` 且 `$HOME/Desktop/mihomos` 目录已经不存在，你可以尝试直接编辑 `$HOME/Desktop/make-mihomo-env.sh` 文件，修改追加以下部分内容**
  * **如果执行过了脚本 `make-mihomo-env.sh` 且 `$HOME/Desktop/mihomos` 目录已经生成，你可以尝试直接编辑 `$HOME/Desktop/mihomos/base_config.yaml` 文件，修改追加以下部分内容**

```yaml
external-controller-tls: :9443 # 开启 tls 管理端口
# 其他参数默认不变，这里是追加内容，用作提示，别直接覆盖，万一其他参数用得上呢？
tls:
  enable: true
  skip-cert-verify: false             # 必须为 false 才会验证并解密
  certificate: ./certs/ca.crt
  private-key: ./certs/ca.key
  sniff: true
# 这里是 tls 其他所省略的配置，用作提醒
```

---

* **3. 完成以上操作，启动脚本测试代理是否使用了 `Mihomo CA` 证书文件**
  * **如果脚本 `make-mihomo-env.sh` 还未执行 `$HOME/Desktop/mihomos` 目录还不存在，则执行脚本 `$HOME/Desktop/make-mihomo-env.sh` 并按照脚本提示启动 Mihomo tun 代理脚本 `$HOME/Desktop/mihomos/mihomo-start.sh`**
  * **如果脚本 `make-mihomo-env.sh` 执行过 `$HOME/Desktop/mihomos` 目录存在，则执行脚本 `$HOME/Desktop/mihomos/mihomo-start.sh` 即可**
  * **测试检查证书已经调用，端口9443也开启**
```bash
echo | openssl s_client -connect 127.0.0.1:9443 -servername localhost -showcerts
sudo lsof -i :9443
```
  * **回显信息如下，可以看到 `C=CN, ST=Test, L=Test, O=Test, OU=Test, CN=Mihomo CA` 信息，说明证书已经被使用**
```plaintext
Connecting to ::1
CONNECTED(00000005)
Can't use SSL_get_servername
depth=0 C=CN, ST=Test, L=Test, O=Test, OU=Test, CN=Mihomo CA
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=CN, ST=Test, L=Test, O=Test, OU=Test, CN=Mihomo CA
verify return:1
---
Certificate chain
 0 s:C=CN, ST=Test, L=Test, O=Test, OU=Test, CN=Mihomo CA
   i:C=CN, ST=Test, L=Test, O=Test, OU=Test, CN=Mihomo CA
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Aug  9 05:44:34 2025 GMT; NotAfter: Jul 16 05:44:34 2125 GMT
...
mihomo  4519 root    5u  IPv6 0xe933761124346a07      0t0  TCP *:tungsten-https (LISTEN)
```

* **4.0 卸载 / 移除证书**

  * **如果以后不想再用 MITM，必须移除 `Mihomo CA` 根证书并清理文件：**

```bash
# 删除系统信任的 CA
sudo security delete-certificate -c "Mihomo CA" /Library/Keychains/System.keychain

# 删除本地证书文件
rm -rf $HOME/Desktop/mihomos/mihomo_config/certs
```

  * **可验证 `Mihomo CA` 根证书是否删除：**

```bash
security find-certificate -c "Mihomo CA" /Library/Keychains/System.keychain
# 无输出则已删除
```

* **4.1 卸载 / 移除多个 `Mihomo CA` 证书**
  * **例外情况，如果你执行了多次生成导入证书的命令，那么你需要根据 `SHA-1` 精确删除对应的系统信任证书：**
```bash
# 查询系统信任的 Mihomo CA 证书 SHA-1 列表，确认无误
security find-certificate -a -Z -c "Mihomo CA" /Library/Keychains/System.keychain | grep -Ei 'SHA-1|="Mihomo CA'
# 删除所有 Mihomo CA 相关证书
for hash in $(security find-certificate -a -Z -c "Mihomo CA" /Library/Keychains/System.keychain | awk '/SHA-1/ {print $3}'); do
  echo "Deleting cert $hash ..."
  sudo security delete-certificate -Z "$hash" /Library/Keychains/System.keychain
done

# 删除本地文件
rm -rf "$HOME/Desktop/mihomos/mihomo_config/certs"
```

  * **可验证 `Mihomo CA` 根证书是否删除：**

```bash
security find-certificate -c "Mihomo CA" /Library/Keychains/System.keychain
# 无输出则已删除
```

---

* **5. 常见问题排查**
  * **全局路由下 `ssl_cert` 报错**
    → 证书未被客户端信任（Firefox 需单独导入，Java/Node 需导入 keystore）
  * **fake-ip 解析后某些网站打不开**
    → 该站点启用证书透明或 HPKP，不允许中间人伪造证书
  * **TUN 不生效**
    → 检查 `net.inet.ip.forwarding` 是否为 `1`，且 `sudo` 启动 mihomo

**Q: 配置文件为空或不完整？**  
A: 检查你输入的订阅链接和规则模板链接是否能通过浏览器访问。

**Q: 你的测试节点哪里来的？这个问题就不要在私信我了哦。**  
A: 动动你的小手，打开浏览器，打开搜索框输入关键词有且不限于以下信息，按回车，你大概率能搜索到  
  `site: baidu.com 2025 clash base64 免费节点`,   
  `site: google.com 2025 clash base64 免费节点`,   
  `site: bing.com 2025 clash base64 免费节点`,   
  `site: duckduckgo.com 2025 clash base64 免费节点`,   
  `site: yahoo.com 2025 clash base64 免费节点`,  
  `site: yandex.com 2025 clash base64 免费节点`,...   

---

## 🧼 卸载（可选）

若要清理所有文件：

```bash
# 1.0 从 /etc/sysctl.conf 移除 net.inet.ip.forwarding=1 行
if grep -q '^net.inet.ip.forwarding=1' /etc/sysctl.conf 2>/dev/null; then
  echo "移除 /etc/sysctl.conf 中的 IPv4 转发配置..."
  sudo sed -i '' '/^net\.inet\.ip\.forwarding=1$/d' /etc/sysctl.conf
fi

# 1.1 从 /etc/sysctl.conf 移除 net.inet6.ip6.forwarding=1
if grep -q '^net.inet6.ip6.forwarding=1' /etc/sysctl.conf 2>/dev/null; then
  echo "移除 /etc/sysctl.conf 中的 IPv6 转发配置..."
  sudo sed -i '' '/^net\.inet6\.ip6\.forwarding=1$/d' /etc/sysctl.conf
fi

# 1.2 从 /etc/pf.conf 移除 "# inserted-by-nat-script" 标记行
# 删除旧规则（带标记的）
sudo sed -i '' "/# inserted-by-nat-script/d" /etc/pf.conf
sudo rm -fv /etc/pf.anchors/mihomo
# 重新加载 PF
sudo pfctl -d
sudo pfctl -f /etc/pf.conf
sudo pfctl -e

# 2. 实时禁用 IP 转发
echo "禁用 IP 转发..."
# IPv4 关闭
sudo sysctl -w net.inet.ip.forwarding=0
# IPv6 关闭
sudo sysctl -w net.inet6.ip6.forwarding=0

# 3. 终止 mihomo 进程
echo "终止 Mihomo 进程（如有）..."
sudo pkill -f 'mihomo -f' || echo "未找到 Mihomo 进程，跳过。"

# 4. 删除整个代理目录
rm -rf $HOME/Desktop/mihomos*
```
## 许可证
本项目采用 [MIT License](LICENSE) 许可。

## 联系与反馈
遇到问题或有改进建议，请在 [issues](https://github.com/469138946ba5fa/make-mihomo-envs/issues) 中提出，或直接联系项目维护者。

## 参考
[github/Homebrew install](https://github.com/Homebrew/install)  
[github/juewuy ShellCrash](https://github.com/juewuy/ShellCrash)  
[在线订阅转换 sub.d1.mk](https://sub.d1.mk/sub)  
[github/MetaCubeX mihomo](https://github.com/MetaCubeX/mihomo)  
[github/Zephyruso zashboard](https://github.com/Zephyruso/zashboard)  
[github/MetaCubeX meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)  
[github/MetaCubeX meta-rules-dat/tree/meta](https://github.com/MetaCubeX/meta-rules-dat/tree/meta)  
[www.panlongid.com freenodeshare](https://www.panlongid.com/category/freenodeshare)  

# 声明
本项目仅作学习交流使用，用于解决生理需求，学习各种姿势，不做任何违法行为。仅供交流学习使用，出现违法问题我负责不了，我也没能力负责，我没工作，也没收入，年纪也大了，你就算灭了我也没用，我也没能力负责。
