import nmap
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

import requests

# 안전 범위 가드 — CLAUDE.md 원칙. 로컬 격리 타겟만 탐색 허용.
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

# 존재한다고 판정할 상태 코드. 404/연결실패는 "없음"으로 본다.
# 500은 CGI가 잘못된 입력에 터진 신호일 수 있어 포함(존재 가능성 높음).
ALIVE_STATUS = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500}

# 내장 wordlist. 이름 × 확장자 조합으로 CGI/스크립트 엔드포인트를 퍼징한다.
# vulhub Shellshock의 /victim.cgi 같은 비표준 경로를 결정론적으로 발견하기 위함.
_DIRECT_PATHS = [
    "/", "/index.html", "/index.php", "/index.cgi",
    "/robots.txt", "/.git/config", "/server-status", "/server-info",
    "/cgi-bin/", "/admin/", "/uploads/", "/static/", "/api/",
]

_NAMES = [
    "victim", "safe", "test", "hello", "admin", "status", "info",
    "shell", "cmd", "bin", "sh", "main", "default", "login", "user",
    "search", "env", "printenv", "index", "debug", "backup", "config",
]

_EXTS = [".cgi", ".sh", ".pl", ".php"]


def _build_wordlist():
    """직접 경로 + (cgi-bin 안/밖) × 이름 × 확장자 조합으로 후보 경로 생성."""
    paths = list(_DIRECT_PATHS)
    for name in _NAMES:
        for ext in _EXTS:
            paths.append(f"/{name}{ext}")
            paths.append(f"/cgi-bin/{name}{ext}")
    # 중복 제거(순서 보존)
    seen = set()
    uniq = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _probe_path(base_url, path, timeout=5):
    """단일 경로를 GET으로 두드려 살아있는지 확인. 살아있으면 dict, 아니면 None."""
    url = urljoin(base_url, path)
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "AIBB-Scanner/1.0"},
        )
    except requests.RequestException:
        return None

    if resp.status_code not in ALIVE_STATUS:
        return None

    body = resp.text or ""
    return {
        "path": path,
        "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "size": len(resp.content or b""),
        # CGI 본문 일부를 남겨 LLM이 엔드포인트 성격을 추론하도록(예: Shellshock CGI 출력)
        "body_preview": body[:200],
    }


def discover_http_paths(target_url, wordlist=None, max_workers=20, timeout=5):
    """wordlist 기반 HTTP 경로 탐색.

    LLM이 표준 경로만 추측하다 실패하는 문제를 해결하기 위해, 살아있는 경로를
    스캐너가 결정론적으로 직접 찾아 scan_data에 실어 LLM에 전달한다.

    Returns: {"target_url", "discovered_paths": [...], "checked": N, "error": None}
    """
    parsed = urlparse(target_url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return {
            "target_url": target_url,
            "discovered_paths": [],
            "checked": 0,
            "error": f"blocked: host '{parsed.hostname}' not in whitelist",
        }

    paths = wordlist if wordlist is not None else _build_wordlist()
    print(f"[*] HTTP 경로 탐색 시작: {target_url} ({len(paths)}개 후보)")

    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe_path, target_url, p, timeout): p for p in paths}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found.append(result)

    # 상태코드 → 경로 순으로 정렬(결정론적 출력)
    found.sort(key=lambda r: (r["status"], r["path"]))
    for r in found:
        print(f"    [+] {r['status']:>3}  {r['path']}  ({r['content_type']})")
    print(f"[*] 경로 탐색 완료: {len(found)}/{len(paths)} 살아있음")

    return {
        "target_url": target_url,
        "discovered_paths": found,
        "checked": len(paths),
        "error": None,
    }


def run_nmap_scan(target_ip, port_range="1-1000"):
    print(f"[*] Nmap 스캔 시작: {target_ip} (포트: {port_range})")
    nm = nmap.PortScanner()
    try:
        nm.scan(target_ip, port_range, arguments='-sV -T4')
        scan_results = {
            "target_ip": target_ip,
            "host_status": "down",
            "open_ports": [],
            "error": None
        }
        for host in nm.all_hosts():
            scan_results["host_status"] = nm[host].state()
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_data = nm[host][proto][port]
                    if port_data['state'] == 'open':
                        scan_results["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "service_name": port_data['name'],
                            "version": port_data.get('version', 'unknown')
                        })
        return scan_results
    except Exception as e:
        return {"target_ip": target_ip, "error": str(e)}

def run_nuclei_scan(target_url):
    """
    Nuclei를 실행하여 타겟 URL의 취약점을 스캔하고 JSON 형태로 파싱합니다.
    """
    print(f"[*] Nuclei 스캔 시작: {target_url}")

    cmd = ["nuclei", "-u", target_url, "-silent", "-jsonl"]

    found_vulnerabilities = []

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    vuln_info = {
                        "vulnerability_name": data.get("info", {}).get("name", "Unknown"),
                        "severity": data.get("info", {}).get("severity", "Unknown"),
                        "cve_id": data.get("info", {}).get("classification", {}).get("cve-id", []),
                        "description": data.get("info", {}).get("description", "No description")
                    }
                    found_vulnerabilities.append(vuln_info)
                except json.JSONDecodeError:
                    continue

        return {"target_url": target_url, "vulnerabilities": found_vulnerabilities, "error": None}

    except Exception as e:
        return {"target_url": target_url, "error": str(e)}

def execute_full_scan(target_ip, target_port):
    """
    [Main.py에서 호출할 최종 함수]
    Nmap + Nuclei + HTTP 경로 탐색 결과를 합쳐서 하나의 JSON 보고서로 만듭니다.
    """
    # 1. Nmap 실행
    nmap_result = run_nmap_scan(target_ip, port_range=str(target_port))

    # 2. 웹 서비스 URL 조립
    target_url = f"http://{target_ip}:{target_port}"

    # 3. Nuclei 실행
    nuclei_result = run_nuclei_scan(target_url)

    # 4. HTTP 경로 탐색 (wordlist 기반) — 살아있는 경로를 LLM에 직접 전달
    path_result = discover_http_paths(target_url)

    # 5. 결과 병합
    final_report = {
        "reconnaissance": nmap_result,
        "vulnerability_assessment": nuclei_result,
        "path_discovery": path_result
    }

    return json.dumps(final_report, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    test_target = "127.0.0.1"
    test_port = "8080" # Shellshock 컨테이너 포트

    print("=== AIBB Scanner Module Test (Nmap + Nuclei + Path Discovery) ===")
    final_json = execute_full_scan(test_target, test_port)

    print("\n[LLM 전달용 최종 통합 데이터]")
    print(final_json)
