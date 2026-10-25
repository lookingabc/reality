#!/usr/bin/env bash
# =============================================================
# Reality 一键脚本 v2 (Debian 11/12/13) —— Xray VLESS + REALITY
# 传输: TCP+Vision(默认) 或 XHTTP;可选后量子增强
#
#   bash reality.sh install      安装并生成节点(首次运行)
#   reality list                 检测全部候选域名
#   reality switch [N|域名]      切换 dest 域名(默认自动换下一个可用的)
#   reality add 域名             添加候选域名
#   reality mode vision|xhttp    切换传输方式
#   reality enc on|off           VLESS Encryption(ML-KEM-768),仅 XHTTP 模式
#   reality mldsa on|off         REALITY ML-DSA-65 后量子证书签名
#   reality pqcheck [域名]       检查域名的证书链大小与后量子密钥交换支持
#   reality link | json          显示分享链接 / 客户端出站 JSON
#   reality status | uninstall
# =============================================================
set -euo pipefail

CONF_DIR=${REALITY_CONF_DIR:-/usr/local/etc/reality}
STATE=$CONF_DIR/state.env
DOMAINS=$CONF_DIR/domains.txt
XRAY_CONF=${REALITY_XRAY_CONF:-/usr/local/etc/xray/config.json}
SELF=/usr/local/bin/reality

# 5 个知名度较低的候选 dest 域名,安装时会在你的 VPS 上实测(TLS 1.3 / h2)。
# 它们只是起步用的候选,我没法替你确认托管位置和 ASN。
# 官方文档的最佳实践是选与 VPS 同 ASN 的站点:用 RealiTLScanner 扫 VPS 同网段,再 `reality add`。
DEFAULT_DOMAINS=(
  www.videolan.org
  www.gimp.org
  www.openbsd.org
  www.haproxy.org
  www.blender.org
)

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'
die()  { echo "${R}错误: $*${N}" >&2; exit 1; }
info() { echo "${G}[+]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
need_root() { [[ $EUID -eq 0 ]] || die "请使用 root 运行"; }

# ---------- 状态 ----------
set_state() {  # set_state KEY VALUE
  local k=$1 v=$2
  mkdir -p "$CONF_DIR"; touch "$STATE"
  grep -v "^${k}=" "$STATE" >"$STATE.tmp" || true
  printf '%s="%s"\n' "$k" "$v" >>"$STATE.tmp"
  mv "$STATE.tmp" "$STATE"; chmod 600 "$STATE"
}

load_state() {
  [[ -f $STATE ]] || die "未安装,请先运行: bash reality.sh install"
  # shellcheck disable=SC1090
  source "$STATE"
  MODE=${MODE:-vision}; XPATH=${XPATH:-/xhttp}
  MLDSA=${MLDSA:-0}; ENC=${ENC:-0}
  MLDSA_SEED=${MLDSA_SEED:-}; MLDSA_VERIFY=${MLDSA_VERIFY:-}
  DEC_STR=${DEC_STR:-}; ENC_STR=${ENC_STR:-}
}

# ---------- 域名检测 ----------
chain_len() {  # 粗略估算服务器返回的证书链总字节数
  local total=0 n b64
  while read -r b64; do
    [[ -n $b64 ]] || continue
    n=$(printf '%s' "$b64" | base64 -d 2>/dev/null | wc -c)
    total=$((total + n))
  done < <(timeout 10 openssl s_client -connect "$1:443" -servername "$1" -showcerts </dev/null 2>/dev/null \
           | awk '/BEGIN CERTIFICATE/{s="";next} /END CERTIFICATE/{print s;next} {s=s $0}')
  echo "$total"
}

REASON=""
check_domain() {  # 通过返回 0
  local d=$1 out
  REASON=""
  out=$(timeout 10 openssl s_client -connect "$d:443" -servername "$d" \
        -alpn h2 -tls1_3 </dev/null 2>/dev/null || true)
  if ! grep -q "TLSv1.3" <<<"$out"; then REASON="不支持 TLS1.3 或无法连接"; return 1; fi
  if ! grep -q "ALPN protocol: h2" <<<"$out"; then REASON="不支持 h2"; return 1; fi
  if [[ ${MLDSA:-0} == 1 ]]; then
    local len; len=$(chain_len "$d")
    if (( len < 3500 )); then REASON="证书链约 ${len}B,<3500,不满足 mldsa65 要求"; return 1; fi
  fi
  return 0
}

domain_info() {
  local d=$1 hdr last cf=""
  hdr=$(curl -s -o /dev/null -D - -m 8 -w "\n%{http_code} %{time_connect}" "https://$d" 2>/dev/null || true)
  last=$(tail -n1 <<<"$hdr"); last=${last:-"000 0"}
  if grep -qiE '^(cf-ray|server: cloudflare)' <<<"$hdr"; then cf=" [Cloudflare!]"; fi
  awk -v r="$last" -v cf="$cf" 'BEGIN{split(r,a," "); printf "HTTP %s, 连接 %.0fms%s", a[1], a[2]*1000, cf}'
}

load_domains() {
  mapfile -t DL < <(grep -v '^\s*#' "$DOMAINS" | sed '/^\s*$/d')
  [[ ${#DL[@]} -gt 0 ]] || die "域名列表为空: $DOMAINS"
}

cmd_list() {
  load_domains
  local cur=""
  if [[ -f $STATE ]]; then load_state; cur=${CUR_DOMAIN:-}; fi
  echo "正在从本机检测候选域名..."
  OK_LIST=()
  local i=0 d mark
  for d in "${DL[@]}"; do
    i=$((i+1)); mark=""; [[ $d == "$cur" ]] && mark=" <- 当前"
    if check_domain "$d"; then
      printf "%2d. ${G}可用${N}   %-26s %s%s\n" "$i" "$d" "$(domain_info "$d")" "$mark"
      OK_LIST+=("$d")
    else
      printf "%2d. ${R}不可用${N} %-26s %s%s\n" "$i" "$d" "$REASON" "$mark"
    fi
  done
  echo "提示: 标 [Cloudflare!] 的域名,未通过验证的流量会被你的服务器转发给它,不建议使用。"
}

# ---------- 配置生成 ----------
build_config() {
  local flow="" dec="none" net="tcp"
  if [[ $MODE == vision ]]; then flow="xtls-rprx-vision"; fi
  if [[ $MODE == xhttp ]]; then net="xhttp"; fi
  if [[ $ENC == 1 ]]; then dec=$DEC_STR; flow="xtls-rprx-vision"; fi

  jq -n --arg port "$PORT" --arg uuid "$UUID" --arg flow "$flow" --arg dec "$dec" \
        --arg net "$net" --arg xpath "$XPATH" --arg d "$CUR_DOMAIN" \
        --arg priv "$PRIVATE_KEY" --arg sid "$SHORT_ID" --arg seed "$MLDSA_SEED" '
  {
    log: {loglevel: "warning"},
    inbounds: [{
      listen: "0.0.0.0",
      port: ($port|tonumber),
      protocol: "vless",
      settings: {
        clients: [ {id: $uuid} + (if $flow != "" then {flow: $flow} else {} end) ],
        decryption: $dec
      },
      streamSettings: ({
        network: $net,
        security: "reality",
        realitySettings: ({
          show: false,
          target: ($d + ":443"),
          xver: 0,
          serverNames: [$d],
          privateKey: $priv,
          shortIds: [$sid]
        } + (if $seed != "" then {mldsa65Seed: $seed} else {} end))
      } + (if $net == "xhttp" then {xhttpSettings: {path: $xpath, mode: "auto"}} else {} end)),
      sniffing: {enabled: true, destOverride: ["http","tls","quic"]}
    }],
    outbounds: [
      {protocol: "freedom", tag: "direct"},
      {protocol: "blackhole", tag: "block"}
    ]
  }'
}

apply_config() {  # 先用 xray -test 校验,通过才替换并重启
  local tmp log; tmp=$(mktemp); log=$(mktemp)
  build_config >"$tmp"
  if ! xray run -test -c "$tmp" >"$log" 2>&1; then
    cat "$log"; rm -f "$tmp" "$log"
    die "新配置未通过 xray -test,已保持原配置不变"
  fi
  mkdir -p "$(dirname "$XRAY_CONF")"
  cat "$tmp" >"$XRAY_CONF"; chmod 644 "$XRAY_CONF"   # 保持可被 xray 用户读取
  rm -f "$tmp" "$log"
  systemctl restart xray; sleep 1
  systemctl is-active --quiet xray || die "xray 启动失败,查看: journalctl -u xray -e"
}

# ---------- 分享链接 / 客户端 JSON ----------
build_link() {
  local flow="" enc="none" q
  if [[ $MODE == vision ]]; then flow="xtls-rprx-vision"; fi
  if [[ $ENC == 1 ]]; then enc=$ENC_STR; flow="xtls-rprx-vision"; fi
  q="encryption=${enc}&security=reality&sni=${CUR_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}"
  if [[ -n $flow ]]; then q+="&flow=${flow}"; fi
  if [[ $MODE == xhttp ]]; then q+="&type=xhttp&path=%2F${XPATH#/}&mode=auto"; else q+="&type=tcp"; fi
  if [[ $MLDSA == 1 ]]; then q+="&pqv=${MLDSA_VERIFY}"; fi
  echo "vless://${UUID}@${SERVER_IP}:${PORT}?${q}#Reality-LA-${MODE}-${CUR_DOMAIN}"
}

cmd_json() {
  load_state
  local flow="" enc="none" net="tcp"
  if [[ $MODE == vision ]]; then flow="xtls-rprx-vision"; fi
  if [[ $MODE == xhttp ]]; then net="xhttp"; fi
  if [[ $ENC == 1 ]]; then enc=$ENC_STR; flow="xtls-rprx-vision"; fi
  jq -n --arg ip "$SERVER_IP" --arg port "$PORT" --arg uuid "$UUID" --arg flow "$flow" \
        --arg enc "$enc" --arg net "$net" --arg xpath "$XPATH" --arg d "$CUR_DOMAIN" \
        --arg pbk "$PUBLIC_KEY" --arg sid "$SHORT_ID" --arg ver "$MLDSA_VERIFY" '
  {
    protocol: "vless",
    settings: {vnext: [{
      address: $ip, port: ($port|tonumber),
      users: [ {id: $uuid, encryption: $enc} + (if $flow != "" then {flow: $flow} else {} end) ]
    }]},
    streamSettings: ({
      network: $net,
      security: "reality",
      realitySettings: ({serverName: $d, fingerprint: "chrome", password: $pbk, shortId: $sid}
        + (if $ver != "" then {mldsa65Verify: $ver} else {} end))
    } + (if $net == "xhttp" then {xhttpSettings: {path: $xpath, mode: "auto"}} else {} end))
  }'
  echo "(注: 较旧的 Xray 内核里 password 字段叫 publicKey)" >&2
}

show_link() {
  load_state
  echo
  echo "================ 当前节点 ================"
  echo "地址: $SERVER_IP   端口: $PORT"
  echo "传输: $MODE   域名(SNI/dest): $CUR_DOMAIN"
  echo "后量子: REALITY ML-DSA-65=$([[ $MLDSA == 1 ]] && echo 开 || echo 关)  VLESS Encryption=$([[ $ENC == 1 ]] && echo 开 || echo 关)"
  echo
  echo "分享链接:"
  build_link
  echo
  command -v qrencode >/dev/null && qrencode -t ANSIUTF8 "$(build_link)" || true
  echo "=========================================="
  echo "提示: 部分客户端不识别链接里的 encryption / pqv 参数,此时用 reality json 输出的 JSON 导入。"
}

# ---------- 安装 ----------
cmd_install() {
  need_root
  [[ -r /etc/os-release ]] && . /etc/os-release
  [[ ${ID:-} == debian || ${ID_LIKE:-} == *debian* ]] || die "仅支持 Debian / Ubuntu 系"

  info "安装依赖..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl openssl jq unzip ca-certificates qrencode iproute2

  info "安装 Xray (官方 XTLS/Xray-install)..."
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  command -v xray >/dev/null || die "xray 安装失败"

  mkdir -p "$CONF_DIR"; rm -f "$STATE"
  printf '%s\n' "${DEFAULT_DOMAINS[@]}" >"$DOMAINS"

  local port=${PORT:-443} in_port
  read -rp "监听端口 [默认 $port]: " in_port || true
  port=${in_port:-$port}
  if ss -ltn | awk '{print $4}' | grep -qE "[:.]${port}\$"; then
    die "端口 $port 已被占用,请换一个端口或先停掉占用的服务"
  fi

  MLDSA=0
  cmd_list
  [[ ${#OK_LIST[@]} -gt 0 ]] || die "没有任何可用域名,请检查 VPS 网络,或在 $DOMAINS 中换成其他域名后重试"
  local choice dom
  read -rp "选择序号 [回车 = 第一个可用: ${OK_LIST[0]}]: " choice || true
  if [[ -z ${choice:-} ]]; then dom=${OK_LIST[0]}
  else
    [[ $choice =~ ^[0-9]+$ ]] && (( choice>=1 && choice<=${#DL[@]} )) || die "序号无效"
    dom=${DL[$((choice-1))]}
  fi

  echo
  echo "传输方式:  1) TCP + Vision (默认,官方文档推荐搭配 REALITY)   2) XHTTP"
  local m mode=vision; read -rp "选择 [1/2]: " m || true
  [[ ${m:-1} == 2 ]] && mode=xhttp

  # 密钥
  local uuid keys priv pub sid
  uuid=$(xray uuid)
  keys=$(xray x25519)
  # 兼容新旧输出: 旧版 "Private key / Public key",新版 "PrivateKey / Password"(即客户端用的公钥)
  priv=$(awk -F': *' '/[Pp]rivate/{print $2; exit}' <<<"$keys" | tr -d '[:space:]')
  pub=$(awk -F': *' '/[Pp]ublic|Password/{print $2; exit}' <<<"$keys" | tr -d '[:space:]')
  [[ -n $priv && -n $pub ]] || { echo "$keys"; die "解析 x25519 密钥失败,请把上面的输出发给我"; }
  sid=$(openssl rand -hex 8)

  local ip
  ip=$(curl -4 -fsS -m 8 https://api.ipify.org 2>/dev/null || curl -4 -fsS -m 8 https://ifconfig.me 2>/dev/null || true)
  [[ -n $ip ]] || read -rp "无法自动获取公网 IP,请手动输入: " ip

  set_state SERVER_IP "$ip";  set_state PORT "$port";      set_state UUID "$uuid"
  set_state PRIVATE_KEY "$priv"; set_state PUBLIC_KEY "$pub"; set_state SHORT_ID "$sid"
  set_state CUR_DOMAIN "$dom"; set_state MODE "$mode"
  set_state XPATH "/$(openssl rand -hex 4)"
  set_state MLDSA 0; set_state ENC 0

  load_state
  info "写入并校验 Xray 配置..."
  apply_config

  if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    info "启用 BBR..."
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' >/etc/sysctl.d/99-bbr.conf
    sysctl --system >/dev/null || true
  fi
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${port}/tcp" >/dev/null && info "ufw 已放行 ${port}/tcp"
  fi
  systemctl enable xray >/dev/null 2>&1 || true

  if [[ -f $0 ]]; then install -m 755 "$0" "$SELF"; else warn "请先把脚本保存为文件再运行,否则无法安装 reality 命令"; fi

  info "安装完成!"
  show_link
  if [[ $mode == xhttp ]]; then
    warn "XHTTP + REALITY 不能使用 Vision flow,新版 Xray 日志里会出现 'VLESS (with no Flow) deprecated' 警告(见 Xray-core issue #5576)。"
    warn "如需消除并启用后量子加密,运行: reality enc on"
  fi
  echo "域名失效: reality switch    切传输: reality mode vision|xhttp"
  echo "云厂商安全组/防火墙记得放行 TCP ${port}。"
}

# ---------- 切换 ----------
cmd_switch() {
  need_root; load_state; load_domains
  local arg=${1:-next} target="" i idx=-1
  if [[ $arg == next ]]; then
    for i in "${!DL[@]}"; do [[ ${DL[$i]} == "$CUR_DOMAIN" ]] && idx=$i; done
    local n=${#DL[@]} k d
    for ((k=1; k<=n; k++)); do
      d=${DL[$(( (idx+k) % n ))]}
      [[ $d == "$CUR_DOMAIN" ]] && continue
      echo -n "检测 $d ... "
      if check_domain "$d"; then echo "${G}可用${N}"; target=$d; break; else echo "${R}不可用${N} ($REASON)"; fi
    done
    [[ -n $target ]] || die "没有找到其他可用域名,可用 reality add 添加新的"
  elif [[ $arg =~ ^[0-9]+$ ]]; then
    (( arg>=1 && arg<=${#DL[@]} )) || die "序号超出范围"
    target=${DL[$((arg-1))]}
  else
    target=$arg
  fi
  if ! check_domain "$target"; then
    [[ ${FORCE:-0} == 1 ]] || die "$target 未通过检测: $REASON (强制切换请加 FORCE=1)"
  fi
  set_state CUR_DOMAIN "$target"; load_state
  apply_config
  info "已切换到: $target"
  show_link
}

cmd_add() {
  need_root; local d=${1:-}; [[ -n $d ]] || die "用法: reality add <域名>"
  mkdir -p "$CONF_DIR"; touch "$DOMAINS"
  if grep -qxF "$d" "$DOMAINS"; then warn "$d 已在列表中"; else echo "$d" >>"$DOMAINS"; info "已添加 $d"; fi
  [[ -f $STATE ]] && load_state
  echo -n "检测 $d ... "
  if check_domain "$d"; then echo "${G}可用${N} ($(domain_info "$d"))"; else echo "${R}不可用${N} ($REASON)"; fi
}

# ---------- 传输与后量子 ----------
cmd_mode() {
  need_root; load_state
  local m=${1:-}
  [[ $m == vision || $m == xhttp ]] || die "用法: reality mode vision|xhttp"
  if [[ $m == vision && $ENC == 1 ]]; then
    warn "Vision 模式下关闭 VLESS Encryption(该组合我没找到官方支持说明)"; set_state ENC 0
  fi
  set_state MODE "$m"; load_state
  apply_config
  info "已切换传输方式: $m"
  show_link
}

cmd_enc() {
  need_root; load_state
  case ${1:-} in
    on)
      [[ $MODE == xhttp ]] || die "VLESS Encryption 仅在 XHTTP 模式下启用(先: reality mode xhttp)"
      xray vlessenc >/dev/null 2>&1 || die "当前 Xray 版本不支持 vlessenc,请升级 Xray"
      local out; out=$(xray vlessenc)
      mapfile -t decs < <(grep -o '"decryption": *"[^"]*"' <<<"$out" | cut -d'"' -f4)
      mapfile -t encs < <(grep -o '"encryption": *"[^"]*"' <<<"$out" | cut -d'"' -f4)
      if [[ ${#decs[@]} -eq 0 || ${#encs[@]} -eq 0 ]]; then echo "$out"; die "解析 xray vlessenc 输出失败,请把上面的输出发给我"; fi
      # 取最后一组(ML-KEM-768 认证);只有一组时用那一组
      set_state DEC_STR "${decs[-1]}"; set_state ENC_STR "${encs[-1]}"; set_state ENC 1
      ;;
    off) set_state ENC 0 ;;
    *) die "用法: reality enc on|off" ;;
  esac
  load_state; apply_config
  info "VLESS Encryption: $([[ $ENC == 1 ]] && echo 已开启 || echo 已关闭)"
  [[ $ENC == 1 ]] && warn "实验性: XHTTP + REALITY + Encryption + Vision 的组合,我没有找到官方给出的完整示例。若连不上: reality enc off"
  show_link
}

cmd_mldsa() {
  need_root; load_state
  case ${1:-} in
    on)
      xray mldsa65 >/dev/null 2>&1 || die "当前 Xray 版本不支持 mldsa65,请升级 Xray"
      if ! check_domain "$CUR_DOMAIN"; then
        [[ ${FORCE:-0} == 1 ]] || die "当前域名 $CUR_DOMAIN 不满足要求: ${REASON:-}。先 reality switch 换域名,或用 reality pqcheck 查看"
      fi
      local out seed ver; out=$(xray mldsa65)
      seed=$(awk -F': *' '/[Ss]eed/{print $2; exit}' <<<"$out" | tr -d '[:space:]')
      ver=$(awk -F': *' '/[Vv]erify|[Pp]ublic/{print $2; exit}' <<<"$out" | tr -d '[:space:]')
      [[ -n $seed && -n $ver ]] || { echo "$out"; die "解析 xray mldsa65 输出失败,请把上面的输出发给我"; }
      set_state MLDSA_SEED "$seed"; set_state MLDSA_VERIFY "$ver"; set_state MLDSA 1
      ;;
    off) set_state MLDSA 0; set_state MLDSA_SEED ""; set_state MLDSA_VERIFY "" ;;
    *) die "用法: reality mldsa on|off" ;;
  esac
  load_state; apply_config
  info "REALITY ML-DSA-65: $([[ $MLDSA == 1 ]] && echo 已开启 || echo 已关闭)"
  [[ $MLDSA == 1 ]] && warn "开启后,以后换域名时也要求证书链 >3500 字节,候选域名里满足的会变少;客户端需要较新内核并填入 mldsa65Verify。"
  show_link
}

cmd_pqcheck() {
  local d=${1:-}
  if [[ -z $d ]]; then load_state; d=$CUR_DOMAIN; fi
  echo "域名: $d"
  echo "证书链大小(粗估): $(chain_len "$d") 字节 (启用 mldsa65 需 >3500)"
  echo "---- xray tls ping 输出(用来确认目标是否支持 X25519MLKEM768) ----"
  xray tls ping "$d" || warn "xray tls ping 失败"
}

cmd_status() {
  load_state
  systemctl --no-pager --lines=0 status xray || true
  echo "当前域名: $CUR_DOMAIN   端口: $PORT   传输: $MODE   mldsa65=$MLDSA   enc=$ENC"
}

cmd_uninstall() {
  need_root
  local yn; read -rp "确认卸载 Xray 和全部配置? [y/N]: " yn || true
  [[ ${yn:-n} =~ ^[Yy]$ ]] || exit 0
  systemctl stop xray 2>/dev/null || true
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge || true
  rm -rf "$CONF_DIR" "$SELF" /etc/sysctl.d/99-bbr.conf
  info "已卸载"
}

usage() { sed -n '2,19p' "$0"; }

main() {
  case "${1:-}" in
    install)   cmd_install ;;
    list)      cmd_list ;;
    switch)    shift; cmd_switch "${1:-next}" ;;
    add)       shift; cmd_add "${1:-}" ;;
    mode)      shift; cmd_mode "${1:-}" ;;
    enc)       shift; cmd_enc "${1:-}" ;;
    mldsa)     shift; cmd_mldsa "${1:-}" ;;
    pqcheck)   shift; cmd_pqcheck "${1:-}" ;;
    link)      show_link ;;
    json)      cmd_json ;;
    status)    cmd_status ;;
    uninstall) cmd_uninstall ;;
    *)         usage ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
