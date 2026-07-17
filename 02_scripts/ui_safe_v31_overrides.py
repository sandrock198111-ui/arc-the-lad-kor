"""v0.31 one-line skill help layered on the accepted v0.30 wording."""

from ui_safe_v30_overrides import OVERRIDES as V30_OVERRIDES


OVERRIDES = dict(V30_OVERRIDES)
OVERRIDES.update(
    {
        ("skill_description", 1): "불바다로 주변 적 공격",
        ("skill_description", 6): "주변 아군 체력 회복",
        ("skill_description", 12): "적 체력 줄여 아군 회복",
        ("skill_description", 21): "주변 아군 체력 회복",
        ("skill_description", 23): "주변 아군 민첩 상승",
        ("skill_description", 24): "아군 방향을 포코로 변경",
        ("skill_description", 25): "큰 불꽃으로 범위 공격",
        ("skill_description", 26): "범위 적을 잠들게 함",
        ("skill_description", 27): "눈보라로 주변 적 공격",
        ("skill_description", 28): "돌풍으로 주변 적 공격",
        ("skill_description", 43): "강한 마물로 힘 상승",
        ("skill_description", 47): "못 가는 곳에 길 생성",
    }
)
