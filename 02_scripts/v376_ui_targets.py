"""Individually reviewed corrections from the V375 exhaustive audit.

The user authorized the corrective build on 2026-09-10. Stable IDs, not fuzzy
Japanese guesses, identify changes. Uncertain audit rows are not selected.
"""
TARGETS={
 'equipment_name:14':'바이올렛 레이서',
 'equipment_name:26':'딜의 이빨',
 'equipment_name:42':'지옥의 스코프',
 'equipment_name:48':'레이라의 머리장식',
 'equipment_name:55':'태양의 모자',
 'equipment_name:57':'클라비스의 책',
 'equipment_name:61':'프레이의 문장',
 'equipment_description:30':'적이 거의 반드시|아이템을 떨어뜨림',
 'equipment_description:48':'부활시킨 아군의|체력 전부 회복(쿠쿠루)',
 'equipment_description:49':'피해와 회복량 편차 증가',
 'consumable_name:8':'독약',
 'consumable_name:16':'공격의 병',
 'skill_name:43':'오돈',
 'skill_name:56':'더스트 루인',
 'skill_description:20':'여러 폭탄을 동시에 발사',
 'skill_description:24':'모두 포코와 같은 방향',
 'skill_description:32':'범위 안의 적들을 고정',
 'skill_description:33':'심안법 대상에 광탄',
 'skill_description:37':'자신보다 훨씬 약한 적 소멸',
 'skill_description:43':'오돈 소환',
 'character_name:4':'고겐','character_name:5':'이가',
 'character_name:15':'닌자','character_name:35':'슈퍼 시노비',
 'character_name:62':'스턴 골렘','character_name:72':'코 아비스',
 'character_name:85':'오돈','character_name:104':'다크 고겐','character_name:105':'다크 이가',
 'region_name:3':'오르니스 언덕','region_name:5':'코르보 평원',
 'region_name:7':'쿠이나 언덕','region_name:12':'니카라스 숲',
 'region_name:13':'센바라 늪','region_name:20':'아젠다 고지',
 'region_name:26':'이슈마 암장','region_name:27':'니델 공항',
 'ui_pointer:81EFC':'니델',
 'location_name:17':'오르니스 언덕',
 'location_name:21':'아젠다 고지 동굴','location_name:22':'아젠다 고지 외부',
 'location_name:29':'니델 공항','location_name:30':'콜로세움 대기실',
 'location_name:31':'콜로세움 무대','location_name:42':'코르보 평원',
 'location_name:44':'쿠이나 언덕','location_name:46':'니카라스 숲',
 'location_name:47':'센바라 늪','location_name:50':'이슈마 암장',
 'location_name:51':'콜로세움 투기장',
 'ui_pointer:82348':'{E7:07}{E7:06} 대상 변경',
 'ui_pointer:82354':'{E7:01} 스킬을 선택하세요',
 'ui_pointer:82358':'{E7:03} 돌아갑니다',
 'ui_pointer:8236C':'{E7:01} 비어 있는 곳을 선택하세요',
 'ui_pointer:82948':'독 공격','ui_pointer:82988':'독 안개',
 'ui_pointer:829D8':'데스 볼','ui_pointer:829DC':'더스트 루인',
 'extra_ui:82630':'승','extra_ui:82634':'패',
 'extra_ui:8299C':'불꽃','extra_ui:82A68':'?????',
 'extra_ui:82AE8':'진행','extra_ui:82AEC':'동료','extra_ui:82AF0':'장',
 'extra_ui:82AF4':'세계','extra_ui:82AF8':'지역','extra_ui:82AFC':'값',
}
# These aliases use the exact same original Japanese skill name and must
# follow the main menu's adopted spelling. They reuse pointers where possible.
ALIASES={
 0x82950:51,0x8295C:25,0x82960:28,0x82964:30,0x8296C:7,
 0x82970:10,0x82974:11,0x82980:6,0x82998:54,0x829B0:53,
 0x829D0:57,0x829E8:2,0x829F4:5,0x829F8:6,0x829FC:7,
 0x82A08:10,0x82A0C:11,0x82A14:13,0x82A18:14,0x82A1C:15,
 0x82A20:16,0x82A24:17,0x82A28:18,0x82A30:20,0x82A38:22,
 0x82A40:24,0x82A44:25,0x82A50:28,0x82A54:30,0x82A58:34,
 0x82A60:36,0x82A7C:48,0x82A80:50,0x82A84:58,
}
# Text was incorrectly placed inside original actor records89/90. Preserve
# its current semantics at a verified text address before restoring records.
PRESERVE_RELOCATE={0x82534:' ',0x82538:' 상승'}
