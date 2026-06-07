#!/usr/bin/env python3
"""
Shell 데모 - AI 에이전트가 '쉘을 열어' 직접 명령으로 침투하는 모습을 시연.

기존 mock_demo(http_request 툴)와 달리, 여기선 AI(지금은 Mock 두뇌)가
run_command 툴로 격리된 공격자 컨테이너의 bash 세션에서 curl 등을 직접 실행해
타겟을 침투한다. ("쉘이 열려서 본인이 명령으로 시도")

사용법:
  # 1) 오프라인 (docker/api 전부 불필요 — 어디서나 즉시)
  python shell_demo.py --offline

  # 2) 라이브 (실제 공격자 컨테이너 -> 실제 타겟)
  #    먼저 타겟 기동:  cd targets/shellshock && docker compose up -d --build
  python shell_demo.py

구조(라이브):
  [Bot+Mock두뇌] --run_command--> [aibb-attacker(bash)] --curl--> [aibb-shellshock(타겟)]
"""
import sys
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from modules.autonomous_attack_bot import AutonomousAttackBot
from modules.mock_llm import MockAnthropicShell
from modules.shell_session import DockerShellSession, MockShellSession

NETWORK = "aibb-net"
ATTACKER = "aibb-attacker"
TARGET = "aibb-shellshock"
TARGET_REF = f"http://{TARGET}"

SAMPLE_SCAN_DATA = {
    "reconnaissance": {
        "target_ip": TARGET,
        "host_status": "up",
        "open_ports": [{"port": 80, "protocol": "tcp", "service_name": "http"}],
    },
    "vulnerability_assessment": {"vulnerabilities": []},
    "path_discovery": {
        "discovered_paths": [
            {"path": "/victim.cgi", "status": 500, "content_type": "text/html"},
            {"path": "/safe.cgi", "status": 500, "content_type": "text/html"},
        ],
        "checked": 187, "error": None,
    },
}


def _run(cmd, ignore_errors=True):
    """docker 명령 실행. (stdout, ok) 반환."""
    print(f"  $ {' '.join(cmd)}")
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0 and not ignore_errors:
        print(out.strip())
        raise RuntimeError(f"command failed: {' '.join(cmd)}")
    return out.strip(), p.returncode == 0


def setup_live_env():
    """공격자 컨테이너를 빌드/기동하고 타겟과 같은 네트워크에 연결."""
    print("[Setup] 라이브 환경 구성 (network/attacker)")

    # 타겟이 떠있는지 확인
    out, _ = _run(["docker", "ps", "--filter", f"name={TARGET}", "--format", "{{.Names}}"])
    if TARGET not in out:
        print(f"\n[ERROR] 타겟 컨테이너 '{TARGET}' 가 안 떠 있습니다.")
        print("  먼저: cd targets/shellshock && docker compose up -d --build")
        sys.exit(2)

    _run(["docker", "network", "create", NETWORK])            # 있으면 무시됨
    _run(["docker", "network", "connect", NETWORK, TARGET])   # 이미 연결돼 있으면 무시
    _run(["docker", "build", "-t", ATTACKER, "targets/attacker"], ignore_errors=False)
    _run(["docker", "rm", "-f", ATTACKER])                    # 기존 것 제거
    _run(["docker", "run", "-d", "--name", ATTACKER, "--network", NETWORK, ATTACKER],
         ignore_errors=False)
    print(f"[Setup] 완료 — 공격자({ATTACKER}) -> 타겟({TARGET}) 같은 네트워크 연결\n")


def teardown_live_env():
    print("\n[Teardown] 공격자 컨테이너 정리")
    _run(["docker", "rm", "-f", ATTACKER])


def main():
    offline = "--offline" in sys.argv

    print("=" * 60)
    print("  AIBB Shell 데모 - AI가 쉘을 열어 직접 명령으로 침투")
    print(f"  모드: {'OFFLINE (쉘 시뮬)' if offline else 'LIVE (공격자 컨테이너)'}")
    print(f"  타겟: {TARGET_REF}")
    print("=" * 60)

    bot = AutonomousAttackBot(client=MockAnthropicShell(target=TARGET_REF))

    if offline:
        shell = MockShellSession()
        result = bot.shell_attack(TARGET_REF, SAMPLE_SCAN_DATA, shell,
                                  target_name="shellshock_shell_mock")
    else:
        setup_live_env()
        shell = DockerShellSession(ATTACKER, target_alias=TARGET)
        try:
            result = bot.shell_attack(TARGET_REF, SAMPLE_SCAN_DATA, shell,
                                      target_name="shellshock_shell")
        finally:
            shell.close()
            teardown_live_env()

    import json
    print("\n" + "=" * 60)
    print("[결과]")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("=" * 60)
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
