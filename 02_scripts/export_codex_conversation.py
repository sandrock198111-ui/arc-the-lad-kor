#!/usr/bin/env python3
"""Export visible user/assistant messages from a Codex rollout JSONL.

The export intentionally excludes developer/system instructions, hidden reasoning,
tool call payloads, and embedded image base64.  Paseo agent notices that appeared
as visible user-side messages are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


SEOUL = timezone(timedelta(hours=9), name="KST")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Codex rollout JSONL")
    parser.add_argument("output", type=Path, help="UTF-8 transcript TXT")
    parser.add_argument(
        "--cutoff",
        help="Include records through this ISO-8601 timestamp (inclusive)",
    )
    return parser.parse_args()


def visible_text(content: object) -> tuple[str, int]:
    if not isinstance(content, list):
        return "", 0

    parts: list[str] = []
    omitted_images = 0
    for item in content:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind in {"input_text", "output_text"}:
            text = item.get("text")
            if isinstance(text, str) and text:
                parts.append(text)
        elif kind == "input_image":
            omitted_images += 1
            parts.append(
                "[첨부 이미지의 base64 데이터는 생략했습니다. "
                "대화 본문에 표시된 이미지 이름·경로를 참조하십시오.]"
            )
    return "\n".join(parts), omitted_images


def is_platform_context(role: str, text: str) -> bool:
    """Drop injected context that was not authored as a chat message."""
    stripped = text.lstrip()
    return role == "user" and stripped.startswith("<recommended_plugins>")


def normalize_line_endings(text: str) -> str:
    """Keep message text while removing non-semantic trailing whitespace."""
    return "\n".join(line.rstrip() for line in text.splitlines()).rstrip()


def local_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(SEOUL).isoformat(timespec="milliseconds")


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if source == output:
        raise SystemExit("source and output must differ")

    messages: list[tuple[str, str, str]] = []
    counts: Counter[str] = Counter()
    source_hash = hashlib.sha256()
    omitted_images = 0
    skipped_platform_messages = 0

    with source.open("rb") as handle:
        for raw_line in handle:
            record = json.loads(raw_line.decode("utf-8"))
            timestamp = record.get("timestamp")
            if not isinstance(timestamp, str):
                continue
            if args.cutoff and timestamp > args.cutoff:
                continue
            source_hash.update(raw_line)

            if record.get("type") != "response_item":
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict) or payload.get("type") != "message":
                continue
            role = payload.get("role")
            if role not in {"user", "assistant"}:
                continue

            text, image_count = visible_text(payload.get("content"))
            text = normalize_line_endings(text)
            if not text:
                continue
            if is_platform_context(role, text):
                skipped_platform_messages += 1
                continue

            if role == "user" and text.lstrip().startswith("<paseo-system>"):
                label = "Paseo/에이전트 알림"
            elif role == "user":
                label = "사용자"
            else:
                label = "Codex"

            messages.append((timestamp, label, text))
            counts[label] += 1
            omitted_images += image_count

    if not messages:
        raise SystemExit("no visible messages found")

    first_timestamp = messages[0][0]
    last_timestamp = messages[-1][0]
    lines = [
        "Arc the Lad 1 한글화 프로젝트 - Codex/Paseo 대화 기록",
        "=" * 72,
        "",
        f"원본 세션: {source.name}",
        f"원본 세션 cutoff 구간 SHA-256: {source_hash.hexdigest().upper()}",
        f"기록 범위(UTC): {first_timestamp} ~ {last_timestamp}",
        f"기록 범위(KST): {local_timestamp(first_timestamp)} ~ {local_timestamp(last_timestamp)}",
        f"내보내기 cutoff: {args.cutoff or '없음'}",
        f"메시지 수: {len(messages)} "
        f"(사용자 {counts['사용자']}, Codex {counts['Codex']}, "
        f"Paseo/에이전트 알림 {counts['Paseo/에이전트 알림']})",
        f"생략된 플랫폼 컨텍스트 메시지: {skipped_platform_messages}",
        f"base64를 생략한 첨부 이미지 블록: {omitted_images}",
        "",
        "범위 설명:",
        "- 사용자와 Codex 사이에 화면으로 전달된 메시지를 시간순으로 보존했습니다.",
        "- 화면에 나타난 Paseo/하위 에이전트 알림은 보존했습니다.",
        "- 시스템·개발자 지침, 숨겨진 추론, 도구 호출 원문, 토큰/인증정보는 제외했습니다.",
        "- 업로드 파일 자체와 이미지 base64는 포함하지 않고, 대화에 표시된 경로와 설명만 보존했습니다.",
        "- 이 파일은 사용자의 내보내기 요청 시점까지를 기록하므로 이후 완료 보고는 포함하지 않습니다.",
        "",
        "=" * 72,
        "",
    ]

    for index, (timestamp, label, text) in enumerate(messages, start=1):
        lines.append(f"[{index:04d}] {local_timestamp(timestamp)} [{label}]")
        lines.append("-" * 72)
        lines.append(text.rstrip())
        lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8", newline="\n")

    digest = hashlib.sha256(output.read_bytes()).hexdigest().upper()
    print(f"output={output}")
    print(f"messages={len(messages)}")
    print(f"counts={dict(counts)}")
    print(f"omitted_images={omitted_images}")
    print(f"skipped_platform_messages={skipped_platform_messages}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
