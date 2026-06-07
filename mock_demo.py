#!/usr/bin/env python3
"""
Mock 데모 - API 키 없이 자율 공격 파이프라인(Tool Use 루프)을 시연/검증한다.

사용법:
  # 1) 오프라인 (docker/nmap/api 전부 불필요 — 어디서나 즉시 실행)
  python mock_demo.py --offline

  # 2) 실제 타겟 상대 (docker로 shellshock 타겟을 띄운 상태에서)
  python mock_demo.py                       # 기본 http://127.0.0.1:8080
  python mock_demo.py http://127.0.0.1:8080

LLM의 '자율 판단'만 MockAnthropic으로 대체할 뿐, 스캐너 결과 주입 / Tool Use 루프 /
화이트리스트 가드 / 디스크 로그 등 나머지 실제 코드 경로는 그대로 실행된다.
"""
import sys
import json

# Windows 콘솔(cp949)에서도 한글/기호가 깨지지 않게 stdout을 utf-8로.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from modules.autonomous_attack_bot import AutonomousAttackBot
from modules.mock_llm import MockAnthropic, mock_execute_attack

# Scanner가 wordlist 탐색으로 /victim.cgi를 찾았다고 가정한 샘플 scan_data.
# (실제 실행에서는 scanner.execute_full_scan 결과가 이 자리에 들어간다.)
SAMPLE_SCAN_DATA = {
    "reconnaissance": {
        "target_ip": "127.0.0.1",
        "host_status": "up",
        "open_ports": [{"port": 8080, "protocol": "tcp",
                        "service_name": "http", "version": "Apache httpd"}],
    },
    "vulnerability_assessment": {"vulnerabilities": []},
    "path_discovery": {
        "discovered_paths": [
            {"path": "/victim.cgi", "status": 200, "content_type": "text/html"},
            {"path": "/safe.cgi", "status": 200, "content_type": "text/html"},
        ],
        "checked": 187,
        "error": None,
    },
}


def main():
    args = [a for a in sys.argv[1:]]
    offline = "--offline" in args
    args = [a for a in args if a != "--offline"]
    target_url = args[0] if args else "http://127.0.0.1:8080"

    print("=" * 56)
    print("  AIBB Mock 데모 - API 키 없이 Tool Use 루프 시연")
    print(f"  모드: {'OFFLINE (HTTP 시뮬레이션)' if offline else 'LIVE (실제 타겟)'}")
    print(f"  타겟: {target_url}")
    print("=" * 56)

    # 가짜 LLM 주입 → API 키 불필요
    bot = AutonomousAttackBot(client=MockAnthropic())

    if offline:
        # 실제 HTTP 대신 시뮬레이터로 교체 → docker 없이도 동작
        bot.execute_attack = mock_execute_attack

    result = bot.autonomous_attack(
        target_url=target_url,
        scan_data=SAMPLE_SCAN_DATA,
        target_name="shellshock_mock",
    )

    print("\n" + "=" * 56)
    print("[결과]")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("=" * 56)

    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
