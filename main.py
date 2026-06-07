#!/usr/bin/env python3
"""
AIBB (AI BunkerBuster) - Main Controller (Blind Mode)
LLM이 Scanner 결과만 보고 자율적으로 공격
"""
import sys
import json
from dotenv import load_dotenv

load_dotenv()

from modules.docker_manager import DockerManager
from modules.scanner import execute_full_scan
from modules.autonomous_attack_bot import AutonomousAttackBot

TARGETS = {
    "1": {
        "name": "shellshock",
        "path": "./targets/shellshock",
        "port": 8080,
        "url": "http://localhost:8080"
    },
    "2": {
        "name": "spring4shell",
        "path": "./targets/spring4shell",
        "port": 8080,
        "url": "http://localhost:8080"
    }
}


class AIBB:
    def __init__(self):
        print("[*] AIBB (AI BunkerBuster) Initializing")
        self.docker_mgr = DockerManager()
        self.attack_bot = AutonomousAttackBot()
        self.active_target = None  # 현재 실행 중인 타겟

    def show_menu(self):
        print("\n" + "="*50)
        print("  AIBB — 타겟 선택")
        print("="*50)
        for key, t in TARGETS.items():
            print(f"  {key}. {t['name']}")
        print("  0. 종료")
        print("="*50)

    def select_target(self):
        while True:
            self.show_menu()
            choice = input("번호 입력: ").strip()
            if choice == "0":
                return None
            if choice in TARGETS:
                return TARGETS[choice]
            print("[!] 잘못된 입력입니다.")

    def switch_target(self, new_target):
        """타겟 전환 시 기존 컨테이너 내리고 새 것 올리기."""
        if self.active_target and self.active_target['path'] != new_target['path']:
            print(f"\n[*] 타겟 전환 — 기존 컨테이너 종료: {self.active_target['name']}")
            self.docker_mgr.stop_container(self.active_target['path'])
            self.active_target = None

        if self.active_target is None:
            print(f"\n[Step 1] Docker 컨테이너 기동: {new_target['name']}")
            if not self.docker_mgr.start_container(new_target['path']):
                print("[ERROR] Docker 기동 실패")
                return False
            self.active_target = new_target

        return True

    def run_scan(self, target):
        print(f"\n[Step 2] 스캔 (Nmap + Nuclei)")
        scan_result = execute_full_scan("127.0.0.1", target['port'])
        scan_data = json.loads(scan_result)

        print(f"\n[Scan Summary]")
        print(f"  Status: {scan_data['reconnaissance']['host_status']}")
        for port in scan_data['reconnaissance']['open_ports']:
            print(f"  Port {port['port']}: {port['service_name']} {port['version']}")
        vulns = scan_data['vulnerability_assessment']['vulnerabilities']
        print(f"  Vulnerabilities: {len(vulns)}")
        for v in vulns:
            print(f"    - {v['vulnerability_name']} ({v['severity']})")

        return scan_data

    def run_attack(self, target, scan_data):
        print(f"\n[Step 3] AI 자율 공격 (Blind Mode)")
        result = self.attack_bot.autonomous_attack(
            target_url=target['url'],
            scan_data=scan_data,
            target_name=target['name']
        )
        return result

    def print_result(self, target_name, result):
        print("\n" + "="*50)
        print("[Report]")
        print("="*50)
        if result.get('success'):
            print(f"  {target_name}: SUCCESS")
            print(f"  Flag : {result['flag']}")
            print(f"  Iterations: {result.get('iterations', result.get('attempts'))}")
        else:
            print(f"  {target_name}: FAIL")
            print(f"  Total attempts: {result.get('total_attempts', '?')}")

    def run(self):
        try:
            while True:
                target = self.select_target()

                if target is None:
                    print("\n[*] 종료합니다.")
                    if self.active_target:
                        print(f"[*] 컨테이너 종료: {self.active_target['name']}")
                        self.docker_mgr.stop_container(self.active_target['path'])
                    break

                # 컨테이너 기동/전환
                if not self.switch_target(target):
                    continue

                # 스캔
                try:
                    scan_data = self.run_scan(target)
                except Exception as e:
                    print(f"[ERROR] 스캔 실패: {e}")
                    continue

                # 공격
                try:
                    result = self.run_attack(target, scan_data)
                    self.print_result(target['name'], result)
                except Exception as e:
                    print(f"[ERROR] 공격 실패: {e}")
                    import traceback
                    traceback.print_exc()
                    continue

                # 루프 여부 확인 (컨테이너는 그대로 유지)
                print("\n처음으로 돌아갈까요? (y/n): ", end="")
                ans = input().strip().lower()
                if ans != "y":
                    print(f"\n[*] 컨테이너 종료: {self.active_target['name']}")
                    self.docker_mgr.stop_container(self.active_target['path'])
                    self.active_target = None
                    break

        except KeyboardInterrupt:
            print("\n\n[!] 사용자 중단")
            if self.active_target:
                self.docker_mgr.stop_container(self.active_target['path'])


def main():
    try:
        aibb = AIBB()
        aibb.run()
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
