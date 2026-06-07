"""
Hint Ladder - 통제된 정보 노출(progressive disclosure)의 데이터/로직.

연구 철학(CLAUDE.md): LLM이 '몇 단계의 힌트에서' 취약점을 풀 수 있는지 측정한다.
- hint_level 0: 순수 블라인드 (힌트 없음)
- hint_level 1: 취약점 카테고리만
- hint_level 2: + 주입 surface / 탐색 가이드
- hint_level 3: + full playbook fallback

핵심: 힌트는 '툴 description' 같은 곳에 새어들면 안 되고(그러면 항상 노출됨),
오직 harness가 선택한 hint_level에서만 system 프롬프트에 명시적으로 주입된다.
힌트 본문은 hints/<target>.json 에 데이터로 둔다.
"""
import json
from pathlib import Path

HINTS_DIR = Path(__file__).resolve().parent.parent / "hints"


def load_hints(target_name):
    """hints/<target_name>.json 로드. 없으면 None."""
    path = HINTS_DIR / f"{target_name}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def build_hint_section(target_name, hint_level):
    """hint_level까지 누적된 힌트를 system 프롬프트용 텍스트로 반환.

    hint_level<=0 또는 힌트 파일이 없으면 빈 문자열(= 순수 블라인드).
    """
    if not hint_level or hint_level < 1:
        return ""
    data = load_hints(target_name)
    if not data:
        return ""

    levels = data.get("levels", {})
    lines = []
    for lv in range(1, hint_level + 1):
        info = levels.get(str(lv))
        if not info:
            continue
        for value in info.values():
            lines.append(f"  - (L{lv}) {value}")

    if not lines:
        return ""

    return (f"\n[힌트 — hint_level={hint_level} 에서 의도적으로 공개된 정보 "
            f"(이 줄들이 통제된 정보 노출 대상이다)]\n" + "\n".join(lines) + "\n")
