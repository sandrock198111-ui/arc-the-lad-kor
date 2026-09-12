"""Read-only V375 equipment/consumable followup; outputs analysis JSON/MD only."""
from pathlib import Path
from zipfile import ZipFile
import hashlib
import json
import struct
import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIAS = 0x8011A800


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def main():
    with ZipFile(ROOT / '00_original/arc.zip') as z:
        original = z.read('PSX.EXE')
    with ZipFile(ROOT / '03_output/arc1_v375_next_choice_TEST_ONLY.zip') as z:
        current = z.read('PSX.EXE')
    assert digest(original) == '947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67'
    assert digest(current) == '57AC9833007E92B0A4E6730A11B44DE1958C6E7BBBA3BBA2C4C69B3F980D3782'
    md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN)
    specifications = [
        ('resurrection_actor', 0x8012E388, 0x8012E4C4, True),
        ('resurrection_recipient', 0x80128D78, 0x80128DF4, True),
        ('equipped_id_check', 0x80164478, 0x801644BC, True),
        ('equipment_stat_application', 0x80174C88, 0x80174EC4, True),
        ('stat_read', 0x80175250, 0x801753F4, True),
        ('random_and_variation', 0x80174478, 0x8017455C, True),
        ('damage_item_healing', 0x80172F3C, 0x801735C4, True),
        ('consumable_dispatch', 0x80164EB8, 0x80165084, True),
        ('level_check', 0x80173A38, 0x80173C14, True),
        ('level_threshold_and_increment', 0x80173DA8, 0x80173EB4, True),
        ('consumable_attributes', 0x801A1CE8, 0x801A1D68, False),
        ('equipment_attributes', 0x801A1D68, 0x801A1EE8, False),
        ('stat_get_jump_table', 0x8011B7DC, 0x8011B7DC + 67 * 4, False),
        ('consumable_effect_jump_table', 0x8011B610, 0x8011B628, False),
        ('party_level_coefficients', 0x8019D424, 0x8019D42C, False),
    ]
    spans = []
    for label, start, end, code in specifications:
        a, b = original[start-BIAS:end-BIAS], current[start-BIAS:end-BIAS]
        record = dict(label=label, start=hex(start), end_exclusive=hex(end),
                      file_offset=hex(start-BIAS), length=len(a), byte_exact=a == b,
                      original_sha256=digest(a), current_sha256=digest(b))
        if code:
            record['original_disassembly'] = [f'{i.address:08X} {i.mnemonic} {i.op_str}' for i in md.disasm(a, start)]
        else:
            record['original_hex'] = a.hex(' ')
        assert a == b, label
        spans.append(record)
    # Actual item IDs and effect dispatch evidence, without relying on descriptions.
    attrs = original[0x87568+48*6:0x87568+50*6]
    assert attrs == bytes.fromhex('02 00 00 00 00 00 00 01 1a 00 64 00')
    assert struct.unpack_from('<I', original, 0x8011B7DC+0x1A*4-BIAS)[0] == 0x80175368
    assert original[0x801A1CF0-BIAS:0x801A1CF4-BIAS] == b'\x05\0\0\0'
    assert struct.unpack_from('<I', original, 0x8011B610+4*4-BIAS)[0] == 0x80164F4C
    # Arithmetic verification of the decoded level transition, not a CPU execution.
    coefficients = list(original[0x8019D424-BIAS:0x8019D42C-BIAS])
    level_cases = []
    for char_id, factor in enumerate(coefficients):
        assert factor > 0
        for before in range(1, 60):
            exp = before * factor
            level = before
            while level < 60 and exp >= level * factor:
                exp -= level * factor
                level += 1
            assert (level, exp) == (before+1, 0)
            level_cases.append(dict(character_id=char_id, before=before, after=level, remaining_exp=exp))
    conclusions = [
        dict(id='equipment_description:48', status='CONFIRMED_DEFECT', severity='high',
             finding='현재 문구는 쿠쿠루가 부활 마법을 받으면 만HP가 된다고 한다. 실제 장비 검사는 부활 시전자의 장비이며 그 시전자가 되살리는 대상의 HP를 만HP로 유지한다.',
             proposed_meaning='쿠쿠루의 부활 마법으로 대상을 최대 체력으로 부활시킴',
             evidence=['8012E394 s0=a0 actor; 8012E3B8 equipped(actor,0x31)',
                       '8012E438 target_id=actor+AA; 8012E43C call 80128D78 with a3=equipment result',
                       '80128D8C saves equipment flag; 80128DA4 skips half-HP removal when flag nonzero',
                       '80128DAC..28DC8 reads newly created recipient maximum HP at +14 and removes half only without equipment',
                       '8012E474..2E484 subsequently charges MP to same actor, separating actor from new recipient']),
        dict(id='equipment_description:49', status='CONFIRMED_DEFECT', severity='medium',
             finding='피해 편차 증가는 사실이나 회복량 변동에도 영향을 준다. 원본의 일반적인 편차 설명을 피해만으로 좁혀 회복 효과 범위를 누락했다.',
             proposed_meaning='공격·회복 효과량의 편차 증가',
             evidence=['equipment49 raw 00 01 1A 00 64 00: percentage increase 100 to stat 0x1A',
                       '80174D50..74DF4 reads original stat and computes original + original*100/100',
                       'getter table 8011B844 -> 80175368 reads stat +30',
                       '801744E0..74544 applies base + trunc(base*(rand(2*spread)-spread)/100)',
                       '80173038 physical, 801731D8 magic, 80173330 item use spread',
                       '8017354C,80173554 sum caster/recipient spread; 80173580 applies same variation to healing']),
        dict(id='consumable_description:2', status='ACCEPTABLE_ABBREVIATION', severity='none',
             finding='레벨 1 상승은 실제 효과와 일치한다. 레벨 60 상한에서 변화하지 않는 예외는 원본 설명 역시 생략한다.',
             evidence=['consumable table row2 801A1CF0 = 05 00 00 00',
                       '80164ED8 dispatch type5 -> 80164F4C -> 80164F64; item index2 -> 80164FAC',
                       '80164FBC guards level<60; 80164FC8/64FD8 threshold function to both stats+8',
                       '80173DA8 threshold = current level * character coefficient',
                       '80173BCC checks exp >= threshold; 80173E54/73E70 subtract threshold; 80173E88/73EA0 increment level once',
                       'Decoded arithmetic verified for 8 party IDs x levels1..59 =472 cases; no CPU harness claimed'])
    ]
    result = dict(original_exe_sha256=digest(original), current_exe_sha256=digest(current),
                  method='Original PSX.EXE disassembly/data, byte-exact V375 comparison; arithmetic model only, no emulator execution',
                  compared_spans=spans, conclusions=conclusions, level_coefficients=coefficients,
                  level_arithmetic_cases=level_cases, game_files_modified=False)
    (HERE/'equipment_mechanics_followup.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    lines=['# V375 장비·소모품 미확정 3행 후속 분석', '',
           '원본 PSX.EXE와 V375의 실행 코드·속성 데이터를 직접 추적했다. 외부 공략은 사용하지 않았다. 게임 파일 수정 없음.', '',
           '15개 명시 범위의 원본/V375 바이트가 모두 동일하다. 구간 주소·길이·각 SHA256과 원본 디스어셈블은 JSON에 수록했다. 이 검사는 실제 DuckStation 실행이나 화면 재현을 대신하지 않는다.', '']
    for r in conclusions:
        lines += ['## '+r['id']+' — '+r['status'], '', r['finding'], '']
        lines += ['- '+e for e in r['evidence']]
        lines += ['']
    lines += ['CSV 판정 갱신 제안: description48/49를 CONFIRMED_DEFECT로, consumable_description2를 ACCEPTABLE_ABBREVIATION으로 변경한다. 이 후속 작업의 쓰기 범위는 helper/후속MD/JSON에 한정되어 이전 CSV는 직접 수정하지 않았다.', '',
              '회복량 편차는 시전자뿐 아니라 회복 대상의 장비 변동폭도 더해진다. 피해만으로 좁힌 설명은 이를 전달하지 못한다. 새 문구는 의미 제안이며 정식 번역 수정·승인이 아니다.', '',
              '재현: python 01_work/analysis/v375_full_audit/audit_equipment_mechanics.py', '',
              '검산: 15/15 code/data spans byte-exact, attributes and dispatch assertions PASS, decoded arithmetic 472/472 PASS. 실제 게임에서의 장비 교체·부활·회복량·레벨업 UI 검증은 별도 필요.']
    (HERE/'equipment_mechanics_followup.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(dict(byte_exact_spans=len(spans), level_arithmetic_cases=len(level_cases), conclusions=[(x['id'],x['status']) for x in conclusions]), ensure_ascii=False))


if __name__ == '__main__':
    main()
