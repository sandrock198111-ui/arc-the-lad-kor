"""Reviewed v0.30 UI wording and deliberate 13-column help wrapping."""

from __future__ import annotations

from ui_safe_v29_overrides import OVERRIDES as V29_OVERRIDES


def wrap13(first: str, second: str) -> str:
    if len(first) > 13:
        raise ValueError(f"first help row is too long: {first!r}")
    return first + " " * (13 - len(first)) + second


OVERRIDES = dict(V29_OVERRIDES)
OVERRIDES.update(
    {
        ("equipment_description", 8): "던지기 LV +1",
        ("equipment_description", 20): "점프 LV +1",
        ("equipment_description", 22): "받기 LV +1",
        ("skill_description", 1): wrap13("불바다로 범위", "적에게 피해"),
        ("skill_description", 6): wrap13("일정 범위 아군", "체력 회복"),
        ("skill_description", 12): wrap13("적 체력을 줄여", "아군 회복"),
        ("skill_description", 21): wrap13("일정 범위 아군", "체력 회복"),
        ("skill_description", 23): wrap13("일정 범위 아군", "민첩 상승"),
        ("skill_description", 24): wrap13("아군 방향을", "포코처럼 변화"),
        ("skill_description", 25): wrap13("큰 불꽃으로", "범위 적 피해"),
        ("skill_description", 26): wrap13("일정 범위 적을", "잠들게 함"),
        ("skill_description", 27): wrap13("눈보라로 범위", "적에게 피해"),
        ("skill_description", 28): wrap13("돌풍으로 범위", "적에게 피해"),
        ("skill_description", 43): wrap13("강화 마물을", "불러 힘 상승"),
        ("skill_description", 47): wrap13("갈 수 없는 곳에", "길 생성"),
    }
)
