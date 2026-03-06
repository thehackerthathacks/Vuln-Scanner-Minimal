#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

TOOLS=(nmap xmllint)
for t in "${TOOLS[@]}"; do
    command -v "$t" &>/dev/null || { echo -e "${RED}[!] Missing required tool: $t${RESET}"; exit 1; }
done

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target_network> [output_dir]"
    echo -e "  Example: $0 192.168.1.0/24"
    echo -e "  Example: $0 10.0.0.0/24 /tmp/scan_results"
    exit 1
}

[[ $# -lt 1 ]] && usage

TARGET="$1"
OUTDIR="${2:-/tmp/vuln_scan_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

XML_OUT="$OUTDIR/nmap_scan.xml"
REPORT="$OUTDIR/attack_suggestions.txt"

echo -e "${CYAN}${BOLD}========================================${RESET}"
echo -e "${CYAN}${BOLD}   Network Vulnerability Scanner        ${RESET}"
echo -e "${CYAN}${BOLD}========================================${RESET}"
echo -e "${YELLOW}[*] Target  : $TARGET${RESET}"
echo -e "${YELLOW}[*] Output  : $OUTDIR${RESET}"
echo ""

echo -e "${YELLOW}[*] Phase 1: Host discovery...${RESET}"
mapfile -t LIVE_HOSTS < <(nmap -sn --open "$TARGET" -oG - 2>/dev/null | awk '/Up$/{print $2}')

if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No live hosts found. Stopping.${RESET}"
    exit 0
fi

echo -e "${GREEN}[+] Found ${#LIVE_HOSTS[@]} live host(s):${RESET}"
for h in "${LIVE_HOSTS[@]}"; do echo -e "    ${GREEN}→ $h${RESET}"; done
echo ""

echo -e "${YELLOW}[*] Phase 2: Deep scan (ports, versions, OS, vuln scripts)...${RESET}"
echo -e "${YELLOW}    This may take a few minutes...${RESET}"

nmap -sV -sC -O --script=vuln,banner,default \
    -p- --open \
    -T4 \
    --min-rate 1000 \
    -oX "$XML_OUT" \
    "${LIVE_HOSTS[@]}" 2>/dev/null

if [[ ! -s "$XML_OUT" ]]; then
    echo -e "${RED}[!] nmap produced no output. Stopping.${RESET}"
    exit 1
fi

echo ""
echo -e "${YELLOW}[*] Phase 3: Analyzing results...${RESET}"
echo ""

declare -A ATTACK_MAP

suggest_attacks() {
    local ip="$1"
    local port="$2"
    local service="$3"
    local version="$4"
    local script_output="$5"

    local suggestions=()

    local svc_lower
    svc_lower=$(echo "$service $version" | tr '[:upper:]' '[:lower:]')

    case "$port" in
        21)
            suggestions+=("${CYAN}[FTP:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt ftp://$ip${RESET}")
            suggestions+=("  MSF anonymous     : ${GREEN}use auxiliary/scanner/ftp/anonymous${RESET}   set RHOSTS $ip")
            suggestions+=("  MSF ftp login     : ${GREEN}use auxiliary/scanner/ftp/ftp_login${RESET}   set RHOSTS $ip")
            [[ "$svc_lower" == *"vsftpd 2.3.4"* ]] && \
                suggestions+=("  ${RED}[CRITICAL] vsftpd 2.3.4 backdoor:${RESET} ${GREEN}use exploit/unix/ftp/vsftpd_234_backdoor${RESET}")
            ;;
        22)
            suggestions+=("${CYAN}[SSH:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt ssh://$ip -t 4${RESET}")
            suggestions+=("  MSF login scanner : ${GREEN}use auxiliary/scanner/ssh/ssh_login${RESET}   set RHOSTS $ip")
            [[ "$svc_lower" == *"openssh"* && "$script_output" == *"CVE"* ]] && \
                suggestions+=("  ${RED}Check CVEs in script output for this OpenSSH version${RESET}")
            ;;
        23)
            suggestions+=("${CYAN}[Telnet:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt telnet://$ip${RESET}")
            suggestions+=("  MSF login         : ${GREEN}use auxiliary/scanner/telnet/telnet_login${RESET}   set RHOSTS $ip")
            ;;
        25|587|465)
            suggestions+=("${CYAN}[SMTP:$port]${RESET}")
            suggestions+=("  MSF user enum     : ${GREEN}use auxiliary/scanner/smtp/smtp_enum${RESET}   set RHOSTS $ip")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt smtp://$ip${RESET}")
            ;;
        80|8080|8000|8008)
            suggestions+=("${CYAN}[HTTP:$port]${RESET}")
            suggestions+=("  Nikto web scan    : ${GREEN}nikto -h http://$ip:$port${RESET}")
            suggestions+=("  Dir brute-force   : ${GREEN}gobuster dir -u http://$ip:$port -w /usr/share/wordlists/dirb/common.txt${RESET}")
            suggestions+=("  MSF http scan     : ${GREEN}use auxiliary/scanner/http/http_version${RESET}   set RHOSTS $ip; set RPORT $port")
            [[ "$script_output" == *"sql"* || "$script_output" == *"SQLi"* ]] && \
                suggestions+=("  ${RED}[SQLi hint] Try:${RESET} ${GREEN}sqlmap -u http://$ip:$port/ --dbs${RESET}")
            [[ "$svc_lower" == *"apache"* ]] && \
                suggestions+=("  MSF Apache struts : ${GREEN}search type:exploit name:apache${RESET} (check version)")
            ;;
        443|8443)
            suggestions+=("${CYAN}[HTTPS:$port]${RESET}")
            suggestions+=("  Nikto web scan    : ${GREEN}nikto -h https://$ip:$port -ssl${RESET}")
            suggestions+=("  Dir brute-force   : ${GREEN}gobuster dir -u https://$ip:$port -w /usr/share/wordlists/dirb/common.txt -k${RESET}")
            [[ "$script_output" == *"HEARTBLEED"* || "$script_output" == *"heartbleed"* ]] && \
                suggestions+=("  ${RED}[CRITICAL] Heartbleed:${RESET} ${GREEN}use auxiliary/scanner/ssl/openssl_heartbleed${RESET}   set RHOSTS $ip")
            ;;
        139|445)
            suggestions+=("${CYAN}[SMB:$port]${RESET}")
            suggestions+=("  MSF EternalBlue   : ${GREEN}use exploit/windows/smb/ms17_010_eternalblue${RESET}   set RHOSTS $ip")
            suggestions+=("  MSF SMB login     : ${GREEN}use auxiliary/scanner/smb/smb_login${RESET}   set RHOSTS $ip")
            suggestions+=("  CrackMapExec      : ${GREEN}crackmapexec smb $ip -u users.txt -p passwords.txt${RESET}")
            suggestions+=("  Enum shares       : ${GREEN}smbclient -L //$ip -N${RESET}")
            [[ "$script_output" == *"ms17-010"* || "$script_output" == *"VULNERABLE"* ]] && \
                suggestions+=("  ${RED}[CRITICAL] EternalBlue confirmed vulnerable!${RESET}")
            ;;
        3389)
            suggestions+=("${CYAN}[RDP:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt rdp://$ip${RESET}")
            suggestions+=("  MSF BlueKeep      : ${GREEN}use exploit/windows/rdp/cve_2019_0708_bluekeep_rce${RESET}   set RHOSTS $ip")
            suggestions+=("  MSF RDP scanner   : ${GREEN}use auxiliary/scanner/rdp/rdp_scanner${RESET}   set RHOSTS $ip")
            ;;
        3306)
            suggestions+=("${CYAN}[MySQL:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt mysql://$ip${RESET}")
            suggestions+=("  MSF login scanner : ${GREEN}use auxiliary/scanner/mysql/mysql_login${RESET}   set RHOSTS $ip")
            suggestions+=("  MSF MySQL enum    : ${GREEN}use auxiliary/scanner/mysql/mysql_hashdump${RESET}   set RHOSTS $ip")
            ;;
        5432)
            suggestions+=("${CYAN}[PostgreSQL:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt postgres://$ip${RESET}")
            suggestions+=("  MSF login         : ${GREEN}use auxiliary/scanner/postgres/postgres_login${RESET}   set RHOSTS $ip")
            ;;
        6379)
            suggestions+=("${CYAN}[Redis:$port]${RESET}")
            suggestions+=("  Unauth check      : ${GREEN}redis-cli -h $ip ping${RESET}")
            suggestions+=("  MSF Redis         : ${GREEN}use auxiliary/scanner/redis/redis_server${RESET}   set RHOSTS $ip")
            ;;
        27017|27018)
            suggestions+=("${CYAN}[MongoDB:$port]${RESET}")
            suggestions+=("  Unauth check      : ${GREEN}mongo $ip --eval 'db.adminCommand({ listDatabases: 1 })'${RESET}")
            suggestions+=("  MSF MongoDB       : ${GREEN}use auxiliary/scanner/mongodb/mongodb_login${RESET}   set RHOSTS $ip")
            ;;
        1433)
            suggestions+=("${CYAN}[MSSQL:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -L users.txt -P passwords.txt mssql://$ip${RESET}")
            suggestions+=("  MSF login         : ${GREEN}use auxiliary/scanner/mssql/mssql_login${RESET}   set RHOSTS $ip")
            suggestions+=("  MSF enum          : ${GREEN}use auxiliary/admin/mssql/mssql_enum${RESET}   set RHOSTS $ip")
            ;;
        161)
            suggestions+=("${CYAN}[SNMP:$port UDP]${RESET}")
            suggestions+=("  Community brute   : ${GREEN}onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $ip${RESET}")
            suggestions+=("  MSF SNMP enum     : ${GREEN}use auxiliary/scanner/snmp/snmp_enum${RESET}   set RHOSTS $ip")
            ;;
        2049)
            suggestions+=("${CYAN}[NFS:$port]${RESET}")
            suggestions+=("  Show exports      : ${GREEN}showmount -e $ip${RESET}")
            suggestions+=("  MSF NFS           : ${GREEN}use auxiliary/scanner/nfs/nfsmount${RESET}   set RHOSTS $ip")
            ;;
        5900|5901)
            suggestions+=("${CYAN}[VNC:$port]${RESET}")
            suggestions+=("  Hydra brute-force : ${GREEN}hydra -P passwords.txt vnc://$ip${RESET}")
            suggestions+=("  MSF VNC login     : ${GREEN}use auxiliary/scanner/vnc/vnc_login${RESET}   set RHOSTS $ip")
            ;;
        *)
            if [[ -n "$service" && "$service" != "unknown" ]]; then
                suggestions+=("${CYAN}[$service:$port]${RESET}")
                suggestions+=("  MSF search        : ${GREEN}search type:exploit name:$service${RESET}")
                suggestions+=("  Hydra (generic)   : ${GREEN}hydra -L users.txt -P passwords.txt $ip -s $port $service${RESET}")
            fi
            ;;
    esac

    if [[ ${#suggestions[@]} -gt 0 ]]; then
        ATTACK_MAP["$ip"]+=$(printf '%s\n' "${suggestions[@]}")$'\n'
    fi
}

parse_xml_and_suggest() {
    local hosts
    hosts=$(xmllint --xpath "//host" "$XML_OUT" 2>/dev/null || true)
    [[ -z "$hosts" ]] && return

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        for port in "${port_list[@]}"; do
            local service version script_out
            service=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@name)" \
                "$XML_OUT" 2>/dev/null || true)
            version=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@version)" \
                "$XML_OUT" 2>/dev/null || true)
            script_out=$(xmllint --xpath \
                "//host[address/@addr='$ip']/ports/port[@portid='$port']/script" \
                "$XML_OUT" 2>/dev/null || true)

            suggest_attacks "$ip" "$port" "$service" "$version" "$script_out"
        done
    done
}

parse_xml_and_suggest

if [[ ${#ATTACK_MAP[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No exploitable services found on discovered hosts. Stopping.${RESET}"
    exit 0
fi

{
    echo "========================================"
    echo "  Attack Suggestions Report"
    echo "  Generated: $(date)"
    echo "  Target: $TARGET"
    echo "========================================"
    echo ""
} > "$REPORT"

TOTAL_TARGETS=0
for ip in "${!ATTACK_MAP[@]}"; do
    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    echo -e "${BOLD}${RED}[TARGET] $ip${RESET}"
    echo -e "${ATTACK_MAP[$ip]}"

    {
        echo "[TARGET] $ip"
        echo "${ATTACK_MAP[$ip]}"
        echo ""
    } >> "$REPORT"
done

echo ""
echo -e "${CYAN}${BOLD}========================================${RESET}"
echo -e "${GREEN}[+] Scan complete.${RESET}"
echo -e "${GREEN}[+] Targets with attack surface : $TOTAL_TARGETS${RESET}"
echo -e "${GREEN}[+] Raw nmap XML                : $XML_OUT${RESET}"
echo -e "${GREEN}[+] Attack suggestions report   : $REPORT${RESET}"
echo -e "${CYAN}${BOLD}========================================${RESET}"
