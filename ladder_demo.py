#!/usr/bin/env python3
"""
Hint Ladder 데모 - "몇 단계 힌트에서 풀리나"를 측정하는 하니스 시연.

hint_level 0부터 올리며 시도하고, 처음 성공한 레벨(solved_at_level)을 기록한다.
힌트-인지 Mock 두뇌를 쓰면 L0/L1 실패 -> L2 성공이 재현된다.

사용법:
  python ladder_demo.py --offline     # docker/api 불필요
  python ladder_demo.py               # 라이브(공격자 컨테이너 -> 실제 타겟)

주의: Mock은 사다리 '하니스가 동작함'을 보이는 시연일 뿐, 실제 연구 측정이 아니다.
실제 측정 = 진짜 LLM(API 키) + 정화된 툴 + 이 하니스.
"""
import sys
import json

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from modules.autonomous_attack_bot import AutonomousAttackBot
from modules.mock_llm import MockAnthropicShellLaddered
from modules.shell_session import DockerShellSession, MockShellSession
from shell_demo import (setup_live_env, teardown_live_env,
                        ATTACKER, TARGET, TARGET_REF, SAMPLE_SCAN_DATA)


def main():
    offline = "--offline" in sys.argv

    print("=" * 60)
    print("  AIBB Hint Ladder 데모 - solved_at_level 측정")
    print(f"  모드: {'OFFLINE (쉘 시뮬)' if offline else 'LIVE (공격자 컨테이너)'}")
    print("=" * 60)

    bot = AutonomousAttackBot(client=MockAnthropicShellLaddered(target=TARGET_REF))

    if offline:
        shell = MockShellSession()
        result = bot.laddered_attack(TARGET_REF, SAMPLE_SCAN_DATA,
                                     target_name="shellshock_ladder_mock",
                                     hint_target="shellshock", mode="shell",
                                     shell=shell, max_level=3)
    else:
        setup_live_env()
        shell = DockerShellSession(ATTACKER, target_alias=TARGET)
        try:
            result = bot.laddered_attack(TARGET_REF, SAMPLE_SCAN_DATA,
                                         target_name="shellshock_ladder",
                                         hint_target="shellshock", mode="shell",
                                         shell=shell, max_level=3)
        finally:
            shell.close()
            teardown_live_env()

    print("\n" + "=" * 60)
    print("[Hint Ladder 결과]")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("solved"):
        print(f"\n  => 이 타겟은 hint_level {result['solved_at_level']} 에서 풀림.")
    print("=" * 60)
    return 0 if result.get("solved") else 1


if __name__ == "__main__":
    sys.exit(main())
