# make-mihomo-envs
Mihomo 一键搭建配置脚本（macOS arm64）

![Watchers](https://img.shields.io/github/watchers/469138946ba5fa/make-mihomo-envs) ![Stars](https://img.shields.io/github/stars/469138946ba5fa/make-mihomo-envs) ![Forks](https://img.shields.io/github/forks/469138946ba5fa/make-mihomo-envs) ![Vistors](https://visitor-badge.laobi.icu/badge?page_id=469138946ba5fa.make-mihomo-envs) ![LICENSE](https://img.shields.io/badge/license-CC%20BY--SA%204.0-green.svg)
<a href="https://star-history.com/#469138946ba5fa/make-mihomo-envs&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=469138946ba5fa/make-mihomo-envs&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=469138946ba5fa/make-mihomo-envs&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=469138946ba5fa/make-mihomo-envs&type=Date" />
  </picture>
</a>

本脚本用于在 **macOS** 系统上自动化完成以下任务：

* 安装依赖工具（如 `brew`, `ggrep`, `unar` 等）
* 下载并配置 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核
* 在线订阅转换并生成 Clash 兼容的配置文件
* 配置本地 UI、Geo 数据文件
* 自动生成并启动本地代理服务
* 提供可执行启动脚本 `mihomo-start.sh`

---

## 💻 支持平台

* 支持 **macOS**
* 额支持 ARM 架构

---

## 🚀 使用方法

1. 打开终端下载脚本，例如：

   ```bash
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
   ~/Desktop/mihomos
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
   └── temp_config.yaml
   ```

5. 启动 Mihomo tun 代理：

   ```bash
   ./mihomo-start.sh
   ```

---

## 📦 自动安装依赖

本脚本将检查并自动安装以下依赖：

* `Homebrew`（若未安装则自动安装）
* `ggrep`（替代系统 grep，支持增强语法）
* `unar`（用于解压 `.gz`, `.zip` 文件）

---

## 🧩 配置说明

* 默认配置启用了 **TUN 模式** 和 **Fake-IP DNS 模拟**，适用于全局代理和旁路由
* 配置文件路径：`~/Desktop/mihomos/config.yaml`
* Web UI 端口：`http://localhost:9999/ui/`
* 默认监听端口：

  * HTTP 代理：7890
  * Redir：7892
  * TProxy：7893
  * DNS：1053

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

## ⚠️ 注意事项

* 如需**旁路由**，请将路由器或设备网关设置为本机 IP（同时设置 DNS）
* 若出现网络策略未生效，请检查系统是否允许 `tun` 接口访问网络
* 为启用系统级转发，会尝试设置 `net.inet.ip.forwarding=1`，需要管理员权限

---

## 📚 示例命令

运行脚本并使用默认配置：

```bash
./make-mihomo-env.sh
```

运行完成后，执行启动脚本：

```bash
./mihomo-start.sh
```

---

## ❓ 常见问题

**Q: 为什么 curl 命令在脚本中不生效？**
A: 可能是 `$SUB_URL` 未被正确 URL 编码，脚本已内置编码函数 `urlencode()`。若有问题请手动检查 `${TMP_FILE}` 是否为空。

**Q: 配置文件为空或不完整？**
A: 检查你输入的订阅链接和规则模板链接是否能通过浏览器访问。

---

## 🧼 卸载（可选）

若要清理所有文件：

```bash
rm -rf ~/Desktop/mihomos*
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

## 声明
本项目仅作学习交流使用，学习各种姿势，不做任何违法行为。仅供交流学习使用，出现违法问题我负责不了，我也没能力负责，我没工作，也没收入，年纪也大了，就算灭了我也没用，我也没能力负责。
