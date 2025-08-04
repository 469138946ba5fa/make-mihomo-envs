#!/bin/bash
IFS_BAK=$IFS
IFS=$'\n'
set -e

echo "检查操作系统..."

if [[ "$(uname)" != "Darwin" ]]; then
  echo "本脚本仅支持 macOS。"
  exit 1
fi

echo "操作系统是 macOS"

# 检查 brew 是否已安装
if ! command -v brew >/dev/null 2>&1; then
  echo "未检测到 Homebrew，正在安装..."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

  # 配置环境变量（适配 arm64）
  echo '正在设置环境变量...'
  arch_name="$(uname -m)"

  if [[ "$SHELL" == */zsh ]]; then
    echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
    eval "$(/opt/homebrew/bin/brew shellenv)"
  else
    echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.bash_profile
    eval "$(/usr/local/bin/brew shellenv)"
  fi
else
  echo "已安装 Homebrew"
fi

# 强制更新 Homebrew 本体和软件包信息
echo "正在更新 brew..."
brew update

# 安装 grep (GNU 版本)
echo "安装/升级 grep (GNU)..."
brew install grep || brew upgrade grep

# 安装 unar（解压 .rar/.zip）
echo "安装/升级 unar..."
brew install unar || brew upgrade unar

# 将 ggrep 设置为默认 grep（添加到 shell 配置）
if ! grep -q 'alias grep=' ~/.zshrc 2>/dev/null; then
  echo "alias grep='ggrep'" >> ~/.zshrc
  echo "添加 alias grep='ggrep' 到 ~/.zshrc"
fi

echo "所有工具安装完成，请重新打开终端或执行 'source ~/.zshrc'"

alias grep='ggrep'
command -v grep

USER_HOME="$HOME"
MIHOMO_DIR_PATH="${USER_HOME}/Desktop/mihomos"
if [[ ! -d ${MIHOMO_DIR_PATH} && ! -f ${MIHOMO_DIR_PATH} ]]; then
  MIHOMO_DIR=${MIHOMO_DIR_PATH}'/mihomo_config'
else
  MIHOMO_DIR_PATH=${MIHOMO_DIR_PATH}-$(uuidgen)
  MIHOMO_DIR=${MIHOMO_DIR_PATH}'/mihomo_config'
fi

# 订阅链接
echo "请输入你的订阅链接SUBS，回车使用默认但不保证节点有效:"
echo "默认 'http://clashshare.cczzuu.top/node/20250802-clash.yaml' "
read -r -s SUBS
SUBS=${SUBS:-'http://clashshare.cczzuu.top/node/20250802-clash.yaml'}
urlencode() {
  local LANG=C
  local length="${#1}"
  for (( i = 0; i < length; i++ )); do
    local c="${1:i:1}"
    case $c in
      [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
}
SUBS=$(urlencode ${SUBS})
# 规则策略模版
echo "请输入你的规则策略模版链接RULES，回车使用默认但不保证模版有效:"
echo "默认 'https://github.com/juewuy/ShellCrash/raw/master/rules/ShellClash_Full_Block.ini' "
read -r RULES
RULES=${RULES:-'https://github.com/juewuy/ShellCrash/raw/master/rules/ShellClash_Full_Block.ini'}
# 在线订阅转换API接口
echo "请输入你的在线订阅转换API链接SUBS_API，回车使用默认但不保证转换有效:"
echo "默认 'https://sub.d1.mk/sub' "
read -r SUBS_API
SUBS_API=${SUBS_API:-'https://sub.d1.mk/sub'}
SUB_URL=${SUBS_API}'?target=clash&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url='${SUBS}'&config='${RULES}
MIHOMO_BIN_FILE_GZ="${MIHOMO_DIR_PATH}/mihomo-darwin-arm64.gz"
MIHOMO_BIN_FILE="$(echo ${MIHOMO_BIN_FILE_GZ} | sed 's;.gz;;g')"
MIHOMO_BIN_FILE_RENAME="${MIHOMO_DIR_PATH}/mihomo"
MIHOMO_COMMIT=$(curl -SL --connect-timeout 30 -m 60 --speed-time 30 --speed-limit 1 --retry 2 -H "Connection: keep-alive" -k 'https://github.com/MetaCubeX/mihomo/releases' | grep -Eo 'commit/[a-f0-9]{40}' | head -n 1 | cut -d '/' -f2 | cut -c1-7)
MIHOMO_PATH=$(curl -SL --connect-timeout 30 -m 60 --speed-time 30 --speed-limit 1 --retry 2 -H "Connection: keep-alive" -k 'https://github.com/MetaCubeX/mihomo/releases' | sed 's;";\n;g;s;tag;download;g' | grep '/download/' | head -n 1)
VERSION=$(basename $(echo ${MIHOMO_PATH} | sed 's;-;/;g') | tr 'A-Z' 'a-z')-${MIHOMO_COMMIT}
echo "https://github.com${MIHOMO_PATH}/mihomo-darwin-arm64-${VERSION}.gz"
MIHOMO_BIN_FILE_URL="https://github.com${MIHOMO_PATH}/mihomo-darwin-arm64-${VERSION}.gz"
UI_URL='https://github.com/Zephyruso/zashboard/releases/download/v1.100.0/dist.zip'
UI_FILE=${MIHOMO_DIR}'/ui.zip'
GEOIP_URL='https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb'
GEOIP_FILE=${MIHOMO_DIR}'/geoip.metadb'
GEOSITE_URL='https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/cn.mrs'
GEOSITE_FILE=${MIHOMO_DIR}'/geosite-cn.mrs'
TMP_FILE=${MIHOMO_DIR_PATH}'/temp_config.yaml'
OUT_FILE=${MIHOMO_DIR_PATH}'/out_config.yaml'
BASE_FILE=${MIHOMO_DIR_PATH}'/base_config.yaml'
# 固定自定义配置，启用tun模式，到时候转发的时候可以带动全局网络嗨翻天
BASE_MIHOMO_CONFIG=$(cat <<'469138946ba5fa'
mixed-port: 7890
redir-port: 7892
tproxy-port: 7893
routing-mark: 7894
authentication: [""]
allow-lan: true
mode: Rule
log-level: info
ipv6: true
external-controller: :9999
external-ui: ui
secret: 

# 开启tun绑定网卡en0
tun:
  enable: true
  stack: mixed
  device: utun
  auto-route: true
  auto-detect-interface: true
  include-interface:
    - en0

dns:
  enable: true
  listen: :1053
  use-hosts: true
  ipv6: true
  default-nameserver:
    - 223.5.5.5
    - 114.114.114.114
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.localdomain'
    - '*.example'
    - '*.invalid'
    - '*.localhost'
    - '*.test'
    - '*.local'
    - '*.home.arpa'
    - '*.direct'
    - 'time.*.com'
    - 'time.*.gov'
    - 'time.*.edu.cn'
    - 'time.*.apple.com'
    - 'time-ios.apple.com'
    - 'time1.*.com'
    - 'time2.*.com'
    - 'time3.*.com'
    - 'time4.*.com'
    - 'time5.*.com'
    - 'time6.*.com'
    - 'time7.*.com'
    - 'ntp.*.com'
    - 'ntp1.*.com'
    - 'ntp2.*.com'
    - 'ntp3.*.com'
    - 'ntp4.*.com'
    - 'ntp5.*.com'
    - 'ntp6.*.com'
    - 'ntp7.*.com'
    - '*.time.edu.cn'
    - '*.ntp.org.cn'
    - '+.pool.ntp.org'
    - 'time1.cloud.tencent.com'
    - 'music.163.com'
    - '*.music.163.com'
    - '*.126.net'
    - 'musicapi.taihe.com'
    - 'music.taihe.com'
    - 'songsearch.kugou.com'
    - 'trackercdn.kugou.com'
    - '*.kuwo.cn'
    - 'api-jooxtt.sanook.com'
    - 'api.joox.com'
    - 'joox.com'
    - 'y.qq.com'
    - '*.y.qq.com'
    - 'streamoc.music.tc.qq.com'
    - 'mobileoc.music.tc.qq.com'
    - 'isure.stream.qqmusic.qq.com'
    - 'dl.stream.qqmusic.qq.com'
    - 'aqqmusic.tc.qq.com'
    - 'amobile.music.tc.qq.com'
    - '*.xiami.com'
    - '*.music.migu.cn'
    - 'music.migu.cn'
    - '+.msftconnecttest.com'
    - '+.msftncsi.com'
    - 'localhost.ptlogin2.qq.com'
    - 'localhost.sec.qq.com'
    - 'localhost.*.weixin.qq.com'
    - '+.steamcontent.com'
    - '+.srv.nintendo.net'
    - '*.n.n.srv.nintendo.net'
    - '+.cdn.nintendo.net'
    - '+.stun.playstation.net'
    - 'xbox.*.*.microsoft.com'
    - '*.*.xboxlive.com'
    - 'xbox.*.microsoft.com'
    - 'xnotify.xboxlive.com'
    - '+.battle.net'
    - '+.battlenet.com.cn'
    - '+.wotgame.cn'
    - '+.wggames.cn'
    - '+.wowsgame.cn'
    - '+.wargaming.net'
    - 'proxy.golang.org'
    - 'stun.*.*'
    - 'stun.*.*.*'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - '+.stun.*.*.*.*'
    - '+.stun.*.*.*.*.*'
    - 'heartbeat.belkin.com'
    - '*.linksys.com'
    - '*.linksyssmartwifi.com'
    - '*.router.asus.com'
    - 'mesu.apple.com'
    - 'swscan.apple.com'
    - 'swquery.apple.com'
    - 'swdownload.apple.com'
    - 'swcdn.apple.com'
    - 'swdist.apple.com'
    - 'lens.l.google.com'
    - 'stun.l.google.com'
    - 'na.b.g-tun.com'
    - '+.nflxvideo.net'
    - '*.square-enix.com'
    - '*.finalfantasyxiv.com'
    - '*.ffxiv.com'
    - '*.ff14.sdo.com'
    - 'ff.dorado.sdo.com'
    - '*.mcdn.bilivideo.cn'
    - '+.media.dssott.com'
    - 'shark007.net'
    - 'Mijia Cloud'
    - '+.market.xiaomi.com'
    - '+.cmbchina.com'
    - '+.cmbimg.com'
    - 'adguardteam.github.io'
    - 'adrules.top'
    - 'anti-ad.net'
    - 'local.adguard.org'
    - 'static.adtidy.org'
    - '+.sandai.net'
    - '+.n0808.com'
    - '+.3gppnetwork.org'
    - '+.uu.163.com'
    - 'ps.res.netease.com'
    - '+.oray.com'
    - '+.orayimg.com'
    - '+.gcloudcs.com'
    - '+.gcloudsdk.com'
    - "rule-set:geosite-cn"
  nameserver-policy: 
    "+.googleapis.cn": [https://223.5.5.5/dns-query, https://doh.pub/dns-query, tls://dns.rubyfish.cn:853]
  nameserver: [https://223.5.5.5/dns-query, https://doh.pub/dns-query, tls://dns.rubyfish.cn:853]
  fallback: [https://223.5.5.5/dns-query, https://doh.pub/dns-query, tls://dns.rubyfish.cn:853]
  fallback-filter:
    geoip: true
    domain:
      - '+.bing.com'
      - '+.linkedin.com'

rule-providers:
  geosite-cn:
    type: file
    behavior: domain
    format: mrs
    path: geosite-cn.mrs
469138946ba5fa
)
MIHOMO_FILE=${MIHOMO_DIR_PATH}'/config.yaml'

BASE_MIHOMO_CONFIG_FIXSCRIPT=$(cat <<'469138946ba5fa'
# 由于在线订阅转换链接转换的节点有时候用了 YAML 行内简写结构 {}，其中嵌套的 ws-opts 再次使用 {}，造成了 YAML 无法准确解析结构层次的问题
# YAML 对 {} 的嵌套解析非常敏感，嵌套中 headers 没有适当引号包裹的值（如 Host），path: 字段值中含有 /@xxx 这类特殊字符没加引号
# 需要用 Python 或 YAML 专用工具转换将每个行内简写结构 {} 展开为 YAML 格式，就可以被正常解析了
#command -v python
#python -m pip install ruamel.yaml
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import DoubleQuotedScalarString
import sys

yaml = YAML()
yaml.preserve_quotes = True

def quote_all_scalars(obj):
    """递归地为所有字符串值加双引号"""
    if isinstance(obj, dict):
        return {k: quote_all_scalars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [quote_all_scalars(i) for i in obj]
    elif isinstance(obj, str):
        return DoubleQuotedScalarString(obj)
    else:
        return obj

input_path = sys.argv[1]
output_path = sys.argv[2]

with open(input_path, 'r', encoding='utf-8') as f:
    data = yaml.load(f)

# 遍历 proxy 节点
if isinstance(data, dict):
    for section in ['proxies', 'proxy-providers']:
        if section in data and isinstance(data[section], list):
            data[section] = [quote_all_scalars(proxy) for proxy in data[section]]

with open(output_path, 'w', encoding='utf-8') as f:
    yaml.dump(data, f)

print(f"✅ 修复完成：{output_path}")
469138946ba5fa
)
BASE_CONFIG_FIXSCRIPT_FILE=${MIHOMO_DIR_PATH}'/subs-fix.py'
MIHOMO_START=${MIHOMO_DIR_PATH}'/mihomo-start.sh'

mkdir -pv ${MIHOMO_DIR}

curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o ${MIHOMO_BIN_FILE_GZ} ${MIHOMO_BIN_FILE_URL}
curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o ${UI_FILE} ${UI_URL}
curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o ${GEOIP_FILE} ${GEOIP_URL}
curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o ${GEOSITE_FILE} ${GEOSITE_URL}

unar -f ${MIHOMO_BIN_FILE_GZ} -o ${MIHOMO_DIR_PATH}
mv -fv ${MIHOMO_BIN_FILE} ${MIHOMO_BIN_FILE_RENAME}
chmod -v a+x ${MIHOMO_BIN_FILE_RENAME}
if [[ -d ${MIHOMO_DIR}/ui ]]; then
  rm -frv ${MIHOMO_DIR}/ui
fi
unzip -o ${MIHOMO_DIR}'/ui.zip' -d ${MIHOMO_DIR}
mv -fv ${MIHOMO_DIR}/dist ${MIHOMO_DIR}/ui

# 合并自定义头部 + 提取部分
echo "${BASE_MIHOMO_CONFIG}" > "${BASE_FILE}"
echo "${BASE_MIHOMO_CONFIG_FIXSCRIPT}" > "${BASE_CONFIG_FIXSCRIPT_FILE}"

chmod -Rv a+x ${MIHOMO_DIR_PATH}
chown -Rv $USER ${MIHOMO_DIR_PATH}

cat << 469138946ba5fa | tee ${MIHOMO_START}
#!/bin/bash
IFS_BAK=\$IFS
IFS=\$'\n'
set -e

echo "start mihomo..."
if [ -f '${TMP_FILE}' ]; then
  rm -fv '${TMP_FILE}'
fi

if curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o '${TMP_FILE}' '${SUB_URL}'; then
    # curl 成功，继续检查文件内容
    if [ ! -s '${TMP_FILE}' ]; then # -s 检查文件是否存在且大小不为0
        echo "Error: ${TMP_FILE} is empty or not created after curl. Exiting."
        exit 1
    fi
    echo "Temporary config downloaded to ${TMP_FILE}"
else
    # curl 失败
    echo "Error: curl download failed. Exiting."
    exit 2
fi

#  提取 proxies: proxy-groups: 和 rules:
awk '
BEGIN { keep = 0 }
/^proxies:/     { keep=1 }
keep && /^[^[:space:]]/ && \$1 != "proxies:" && \$1 != "proxy-groups:" && \$1 != "rules:" { keep=0 }
keep { print }
' '${TMP_FILE}' > '${OUT_FILE}'

cat '${BASE_FILE}' '${OUT_FILE}' > '${MIHOMO_FILE}'

# 修复 mihomo config.yaml 中自动选择策略的 url-test 设置
if [ -f '${MIHOMO_FILE}' ]; then
    echo "正在增强自动选择策略组配置..."

    # 替换测试 URL 为更稳定的 Cloudflare
    sed -i '' 's|http://www.gstatic.com/generate_204|http://cp.cloudflare.com/generate_204|g' '${MIHOMO_FILE}'

    awk '
    /^[ \t]*tolerance:/ { sub(/:[ ]*[0-9]+/, ": 300") }
    /^[ \t]*interval:/  { sub(/:[ ]*[0-9]+/, ": 180") }
    { print }
    ' '$MIHOMO_FILE' > '${MIHOMO_FILE}.tmp' && mv '${MIHOMO_FILE}.tmp' '$MIHOMO_FILE'
else
  echo "Error: ${MIHOMO_FILE} is not exist. Exiting."
  exit 3
fi

cp -fv '${MIHOMO_FILE}' '${MIHOMO_FILE}.bak'

# 每个人的系统环境如此的不同
# 假如你原本就有python环境，而我如果写了一个脚本安装python环境，那一定会破坏你原本的python环境
# 所以python环境这块，你自己搭建好吗？这行命令用于安装yaml处理相关的第三方库

python -m pip install ruamel.yaml
python '${BASE_CONFIG_FIXSCRIPT_FILE}' '${MIHOMO_FILE}.bak' '${MIHOMO_FILE}'

echo "配置已生成: ${MIHOMO_FILE}"

# 避免反复写入
if ! grep -q 'net.inet.ip.forwarding=1' /etc/sysctl.conf 2>/dev/null; then
  echo 'net.inet.ip.forwarding=1' | sudo tee -a /etc/sysctl.conf
fi
# 关闭则 sudo sysctl -w net.inet.ip.forwarding=0
sudo sysctl -w net.inet.ip.forwarding=1
sudo pkill -f 'mihomo -f' || true
sudo '${MIHOMO_BIN_FILE_RENAME}' -f '${MIHOMO_FILE}' -d '${MIHOMO_DIR}'
IFS=\$IFS_BAK
469138946ba5fa

chmod -v a+x ${MIHOMO_START}
echo "已生成启动脚本: ${MIHOMO_START}"

echo "如果想要全局路由你需要配置路由器 DHCP 下发的 NetGateway 强制为本机 IP 同时将下发 DNS 强制修改为 198.18.0.1 后执行脚本"
echo "如果想要旁路由，你需要为单个联网设备配置 NetGateway 强制为本机 IP 同时将下发 DNS 强制修改为 198.18.0.1 后执行脚本"
echo "如果想要本机，那就什么都没什么可说的了"
echo "执行脚本 ${MIHOMO_START} 启动测试看看吧"

IFS=$IFS_BAK
