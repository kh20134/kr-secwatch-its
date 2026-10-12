"""구성도를 PNG로 그린다. 한글은 Noto Sans CJK KR로 그리고, 빠진 글자는 실패시킨다."""

from __future__ import annotations

import sys
from pathlib import Path

from fontTools.ttLib import TTCollection
from PIL import Image, ImageDraw, ImageFont

REGULAR = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
OUT = Path(__file__).resolve().parents[1] / "docs" / "images" / "architecture.png"

BG = (246, 241, 230)
INK = (28, 36, 48)
MUTED = (90, 98, 104)
STEEL = (31, 78, 95)
SEA = (15, 110, 110)
AMBER = (154, 84, 16)
CARD = (255, 253, 248)
LINE = (214, 203, 186)
WHITE = (255, 255, 255)


def face_index(path: str) -> int:
    collection = TTCollection(path)
    for index, font in enumerate(collection.fonts):
        if font["name"].getDebugName(1) == "Noto Sans CJK KR":
            return index
    raise SystemExit(f"Noto Sans CJK KR 가 없다: {path}")


def cmap_for(path: str, index: int) -> dict[int, str]:
    font = TTCollection(path).fonts[index]
    table = font.getBestCmap()
    if not table:
        raise SystemExit("cmap 이 없다")
    return table


def require_glyphs(cmap: dict[int, str], texts: list[str]) -> None:
    missing: list[str] = []
    for text in texts:
        for char in text:
            if char.isspace():
                continue
            if ord(char) not in cmap:
                missing.append(char)
    if missing:
        shown = " ".join(f"U+{ord(char):04X} {char}" for char in sorted(set(missing)))
        raise SystemExit(f"폰트에 없는 글자: {shown}")


def font(path: str, size: int, index: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size=size, index=index)


def center_text(draw: ImageDraw.ImageDraw, box, text, face, fill) -> None:
    left, top, right, bottom = box
    bbox = draw.textbbox((0, 0), text, font=face)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = left + (right - left - width) / 2
    y = top + (bottom - top - height) / 2 - bbox[1]
    draw.text((x, y), text, font=face, fill=fill)


def wrapped(draw, box, lines, face, fill) -> None:
    left, top, right, bottom = box
    heights = []
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=face)
        heights.append(bbox[3] - bbox[1])
    gap = 6
    total = sum(heights) + gap * (len(lines) - 1)
    y = top + (bottom - top - total) / 2
    for line, height in zip(lines, heights):
        bbox = draw.textbbox((0, 0), line, font=face)
        width = bbox[2] - bbox[0]
        x = left + (right - left - width) / 2
        draw.text((x, y - bbox[1]), line, font=face, fill=fill)
        y += height + gap


def round_box(draw, box, fill, outline=None, radius=16, width=2) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def arrow(draw, x: int, y0: int, y1: int) -> None:
    draw.line((x, y0, x, y1 - 10), fill=STEEL, width=3)
    draw.polygon([(x - 7, y1 - 12), (x + 7, y1 - 12), (x, y1)], fill=STEEL)


def main() -> None:
    regular_index = face_index(REGULAR)
    bold_index = face_index(BOLD)
    cmap = cmap_for(REGULAR, regular_index)
    title_font = font(BOLD, 42, bold_index)
    sub_font = font(REGULAR, 22, regular_index)
    label_font = font(BOLD, 22, bold_index)
    small_font = font(REGULAR, 18, regular_index)
    caption_font = font(BOLD, 18, bold_index)

    texts = [
        "KR-SecWatch ITS 구성",
        "공개 피드만 읽는 방어적 모니터링 · 거가대교 전산 관점",
        "수집",
        "보호나라 RSS",
        "보안 뉴스 RSS",
        "CISA KEV",
        "NVD CVE 2.0",
        "FIRST EPSS",
        "피해 조직명",
        "정규화",
        "중복 제거 · SQLite",
        "샘플 모드는 묶음 픽스처만 읽는다",
        "분류",
        "한국 연관",
        "ITS·OT·인프라",
        "자산대장 YAML",
        "우선순위 점수",
        "KEV · EPSS · CVSS · 자산 일치",
        "전달",
        "Flask + HTMX 대시보드",
        "주간 HTML · Markdown",
        "Slack · 메일",
        "기본 꺼짐",
        "유출 본문과 onion 주소는 저장하지 않는다",
    ]
    require_glyphs(cmap, texts)

    image = Image.new("RGB", (1800, 1100), BG)
    draw = ImageDraw.Draw(image)
    center_text(draw, (80, 36, 1720, 100), texts[0], title_font, INK)
    center_text(draw, (80, 100, 1720, 140), texts[1], sub_font, MUTED)

    draw.text((80, 168), texts[2], font=caption_font, fill=STEEL)
    sources = texts[3:9]
    gap = 18
    left = 80
    width = (1800 - 160 - gap * 5) // 6
    top = 204
    height = 92
    for index, label in enumerate(sources):
        box = (left + index * (width + gap), top, left + index * (width + gap) + width, top + height)
        round_box(draw, box, STEEL)
        center_text(draw, box, label, label_font, WHITE)

    arrow(draw, 900, 312, 360)
    draw.text((80, 368), texts[9], font=caption_font, fill=STEEL)
    round_box(draw, (280, 404, 1520, 520), CARD, STEEL)
    wrapped(
        draw,
        (300, 414, 1500, 510),
        [texts[10], texts[11]],
        label_font,
        INK,
    )

    arrow(draw, 900, 536, 584)
    draw.text((80, 592), texts[12], font=caption_font, fill=SEA)
    classes = texts[13:17]
    class_w = (1800 - 160 - gap * 3) // 4
    class_top = 628
    for index, label in enumerate(classes):
        box = (
            left + index * (class_w + gap),
            class_top,
            left + index * (class_w + gap) + class_w,
            class_top + 84,
        )
        round_box(draw, box, (232, 244, 242), SEA)
        center_text(draw, box, label, label_font, SEA)
    center_text(draw, (80, 720, 1720, 756), texts[17], small_font, MUTED)

    arrow(draw, 900, 760, 808)
    draw.text((80, 816), texts[18], font=caption_font, fill=AMBER)
    outputs = [
        (texts[19], STEEL),
        (texts[20], SEA),
        (texts[21], AMBER),
    ]
    out_w = (1800 - 160 - gap * 2) // 3
    out_top = 852
    for index, (label, color) in enumerate(outputs):
        box = (
            left + index * (out_w + gap),
            out_top,
            left + index * (out_w + gap) + out_w,
            out_top + 96,
        )
        round_box(draw, box, CARD, color, width=3)
        if index == 2:
            wrapped(draw, box, [label, texts[22]], label_font, color)
        else:
            center_text(draw, box, label, label_font, color)

    center_text(draw, (80, 990, 1720, 1060), texts[23], sub_font, MUTED)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUT, "PNG")
    print(f"wrote {OUT} font-index={regular_index}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print(exc, file=sys.stderr)
        raise
