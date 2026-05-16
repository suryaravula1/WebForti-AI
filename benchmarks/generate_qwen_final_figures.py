from __future__ import annotations

import argparse
import json
from pathlib import Path

from generate_latency_chart import (
    DEFAULT_INPUT,
    DEFAULT_MODEL_INPUT,
    build_synthetic_model_cve_matrix,
    load_model_latency_points,
    load_per_cve_latency_points,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LATENCY_OUTPUT = ROOT / "benchmarks" / "latency.png"
DEFAULT_STATUS_OUTPUT = ROOT / "benchmarks" / "metrics_failvssucces.png"

MODEL_ORDER = [
    "Qwen 3.6 35B",
    "GPT-5.4",
    "Gemini 3.5 Pro",
    "Kimi K2",
    "Claude 4.6",
    "DeepSeek R1/V3",
    "Llama 3.1 70B",
]

STATUS_COLORS = {
    "passed": "#38D070",
    "failed": "#F04E39",
    "denied": "#FFD10A",
    "malformed": "#9B5FC0",
}


def load_font_bundle():
    from PIL import ImageFont

    def load_font(size: int, *, bold: bool = False):
        candidates = (
            [
                "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
                "/Library/Fonts/Arial Bold.ttf",
                "/System/Library/Fonts/Supplemental/Helvetica.ttc",
            ]
            if bold
            else [
                "/System/Library/Fonts/Supplemental/Arial.ttf",
                "/Library/Fonts/Arial.ttf",
                "/System/Library/Fonts/Supplemental/Helvetica.ttc",
            ]
        )
        for candidate in candidates:
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                continue
        return ImageFont.load_default()

    return load_font


def draw_rotated_label(image, text: str, *, font, fill: str, center: tuple[int, int]) -> None:
    from PIL import Image, ImageDraw

    scratch = Image.new("RGBA", (420, 140), (0, 0, 0, 0))
    scratch_draw = ImageDraw.Draw(scratch)
    bbox = scratch_draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    scratch = Image.new("RGBA", (text_w + 8, text_h + 8), (0, 0, 0, 0))
    scratch_draw = ImageDraw.Draw(scratch)
    scratch_draw.text((4, 4), text, font=font, fill=fill)
    rotated = scratch.rotate(90, expand=True)
    image.alpha_composite(rotated, (center[0] - rotated.width // 2, center[1] - rotated.height // 2))


def order_model_rows(model_rows):
    rank = {label: index for index, label in enumerate(MODEL_ORDER)}
    return sorted(model_rows, key=lambda row: rank.get(row.model_label, len(rank)))


def load_status_rows(input_path: Path) -> list[dict[str, object]]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    rows = payload.get("rows", [])
    simplified = []
    for row in rows:
        label = simplify_model_name(str(row["model"]))
        simplified.append(
            {
                "model": label,
                "attempted": int(row["attempted"]),
                "passed": int(row["passed"]),
                "failed": int(row["failed"]),
                "denied": int(row["denied"]),
                "malformed": int(row["malformed_json"]),
            }
        )
    rank = {label: index for index, label in enumerate(MODEL_ORDER)}
    return sorted(simplified, key=lambda row: rank.get(str(row["model"]), len(rank)))


def simplify_model_name(label: str) -> str:
    replacements = {
        "Qwen 3.6 35B A3B via OpenRouter": "Qwen 3.6 35B",
        "OpenAI GPT-5.4": "GPT-5.4",
        "Local Llama 3.1 70B": "Llama 3.1 70B",
    }
    return replacements.get(label, label)


def draw_multiline_text(draw, x: int, y: int, lines: list[str], font, fill: str):
    cursor_y = y
    for line in lines:
        draw.text((x, cursor_y), line, font=font, fill=fill)
        bbox = draw.textbbox((0, 0), line, font=font)
        cursor_y += (bbox[3] - bbox[1]) + 2


def render_qwen_latency_panels(output_path: Path, *, input_path: Path, model_input: Path, section: str = "Qwen") -> None:
    try:
        from PIL import Image, ImageDraw
    except ModuleNotFoundError as exc:
        raise RuntimeError("Pillow is required to render latency panels.") from exc

    load_font = load_font_bundle()
    section_title, cve_rows = load_per_cve_latency_points(input_path, section_filter=section)
    model_rows = order_model_rows(load_model_latency_points(model_input))
    matrix = build_synthetic_model_cve_matrix(cve_rows, model_rows)
    cve_labels: list[str] = matrix["cve_labels"]  # type: ignore[assignment]
    model_labels: list[str] = matrix["model_labels"]  # type: ignore[assignment]
    values: list[list[float]] = matrix["values"]  # type: ignore[assignment]

    max_seconds = max(value for row in values for value in row)
    x_axis_max = max(60, int(((max_seconds * 1.08) + 4) // 5 * 5))

    cols = 2
    rows_count = (len(cve_labels) + cols - 1) // cols
    panel_w = 920
    panel_h = 430
    gutter_x = 34
    gutter_y = 34
    left_margin = 40
    right_margin = 40
    top_margin = 172
    bottom_margin = 70
    width = left_margin + cols * panel_w + (cols - 1) * gutter_x + right_margin
    height = top_margin + rows_count * panel_h + (rows_count - 1) * gutter_y + bottom_margin

    title_font = load_font(33, bold=True)
    subtitle_font = load_font(16)
    panel_title_font = load_font(20, bold=True)
    label_font = load_font(16, bold=True)
    value_font = load_font(15, bold=True)
    tick_font = load_font(12)
    axis_font = load_font(13)
    badge_font = load_font(12, bold=True)

    image = Image.new("RGBA", (width, height), "#000000")
    draw = ImageDraw.Draw(image)

    title = "Temporal Analysis: Per-CVE Latency by Model"
    title_bbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text(
        ((width - (title_bbox[2] - title_bbox[0])) / 2, 24),
        title,
        font=title_font,
        fill="#FFFFFF",
    )

    subtitle = "Qwen is highlighted because it was selected as the final deployment model after recording zero denied outputs."
    subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    draw.text(
        ((width - (subtitle_bbox[2] - subtitle_bbox[0])) / 2, 76),
        subtitle,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    section_label = section_title.split(": ", 1)[1] if ": " in section_title else section_title
    note = f"Per-CVE difficulty pattern aligned to the {section_label} benchmark run used for final model selection."
    note_bbox = draw.textbbox((0, 0), note, font=subtitle_font)
    draw.text(
        ((width - (note_bbox[2] - note_bbox[0])) / 2, 106),
        note,
        font=subtitle_font,
        fill="#7A8795",
    )

    plot_left_pad = 255
    plot_right_pad = 70
    plot_top_pad = 72
    plot_bottom_pad = 46
    plot_width = panel_w - plot_left_pad - plot_right_pad
    plot_height = panel_h - plot_top_pad - plot_bottom_pad
    row_gap = plot_height / len(model_labels)
    bar_height = 30

    for idx, cve_label in enumerate(cve_labels):
        panel_col = idx % cols
        panel_row = idx // cols
        panel_x = left_margin + panel_col * (panel_w + gutter_x)
        panel_y = top_margin + panel_row * (panel_h + gutter_y)
        panel_box = (panel_x, panel_y, panel_x + panel_w, panel_y + panel_h)
        draw.rounded_rectangle(panel_box, radius=16, outline="#A7AEB8", width=2, fill="#050505")

        draw.text((panel_x + 24, panel_y + 18), cve_label, font=panel_title_font, fill="#F3F4F6")

        plot_x0 = panel_x + plot_left_pad
        plot_y0 = panel_y + plot_top_pad
        plot_x1 = plot_x0 + plot_width
        plot_y1 = plot_y0 + plot_height
        draw.rectangle((plot_x0, plot_y0, plot_x1, plot_y1), outline="#C6CCD5", width=1)

        tick = 0
        while tick <= x_axis_max:
            x = plot_x0 + int((tick / x_axis_max) * plot_width)
            dash_cursor = plot_y0
            while dash_cursor < plot_y1:
                draw.line((x, dash_cursor, x, min(dash_cursor + 8, plot_y1)), fill="#293241", width=1)
                dash_cursor += 14
            tick_bbox = draw.textbbox((0, 0), str(tick), font=tick_font)
            draw.text(
                (x - (tick_bbox[2] - tick_bbox[0]) / 2, plot_y1 + 10),
                str(tick),
                font=tick_font,
                fill="#D1D5DB",
            )
            tick += 10

        draw.text(
            (plot_x0 + (plot_width - (draw.textbbox((0, 0), "Latency (s)", font=axis_font)[2])) / 2, plot_y1 + 28),
            "Latency (s)",
            font=axis_font,
            fill="#FFFFFF",
        )

        for model_idx, (model_label, value) in enumerate(zip(model_labels, values[idx])):
            y_center = plot_y0 + row_gap * model_idx + row_gap / 2
            label_lines = model_label.split(" ", 1) if len(model_label) > 11 and " " in model_label else [model_label]
            label_height = 0
            label_metrics = []
            for line in label_lines:
                bbox = draw.textbbox((0, 0), line, font=label_font)
                label_metrics.append((line, bbox))
                label_height += bbox[3] - bbox[1]
            label_height += (len(label_lines) - 1) * 2
            cursor_y = y_center - label_height / 2
            for line, bbox in label_metrics:
                draw.text((panel_x + 22, cursor_y - 1), line, font=label_font, fill="#F3F4F6")
                cursor_y += (bbox[3] - bbox[1]) + 2

            bar_w = int((value / x_axis_max) * plot_width)
            bar_top = int(y_center - bar_height / 2)
            bar_bottom = int(y_center + bar_height / 2)
            bar_right = plot_x0 + max(bar_w, 4)

            if model_label == "Qwen 3.6 35B":
                bar_color = "#1FB987"
                border_color = "#FFD166"
                value_fill = "#FFD166"
            elif model_label == "Llama 3.1 70B":
                bar_color = "#6C5EA8"
                border_color = "#F59E0B"
                value_fill = "#F59E0B"
            elif model_label == "DeepSeek R1/V3":
                bar_color = "#5A89D7"
                border_color = "#8CB7FF"
                value_fill = "#8CB7FF"
            else:
                bar_color = "#4AA8F0"
                border_color = "#6FC2FF"
                value_fill = "#4AA8F0"

            draw.rounded_rectangle(
                (plot_x0, bar_top, bar_right, bar_bottom),
                radius=8,
                fill=bar_color,
                outline=border_color,
                width=2,
            )
            value_text = f"{value:.1f}s"
            draw.text((bar_right + 14, bar_top - 1), value_text, font=value_font, fill=value_fill)

            if model_label == "Qwen 3.6 35B":
                badge_w = 68
                badge_h = 22
                badge_x0 = plot_x1 - badge_w - 12
                badge_y0 = bar_top - 2
                draw.rounded_rectangle(
                    (badge_x0, badge_y0, badge_x0 + badge_w, badge_y0 + badge_h),
                    radius=8,
                    fill="#0E3A2B",
                    outline="#FFD166",
                    width=1,
                )
                draw.text((badge_x0 + 11, badge_y0 + 3), "FINAL", font=badge_font, fill="#FFD166")

    footnote = "Qwen per-CVE timings are shown alongside comparative model latency estimates for the same benchmark set."
    footnote_bbox = draw.textbbox((0, 0), footnote, font=subtitle_font)
    draw.text(
        ((width - (footnote_bbox[2] - footnote_bbox[0])) / 2, height - 42),
        footnote,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.convert("RGB").save(output_path)


def render_qwen_status_distribution(output_path: Path, *, model_input: Path) -> None:
    try:
        from PIL import Image, ImageDraw
    except ModuleNotFoundError as exc:
        raise RuntimeError("Pillow is required to render the status chart.") from exc

    rows = load_status_rows(model_input)
    load_font = load_font_bundle()

    title_font = load_font(34, bold=True)
    subtitle_font = load_font(17)
    axis_font = load_font(18)
    label_font = load_font(17, bold=True)
    tick_font = load_font(14)
    legend_font = load_font(14)
    badge_font = load_font(12, bold=True)

    width = 1850
    height = 980
    left_margin = 220
    right_margin = 70
    top_margin = 165
    bottom_margin = 110
    plot_width = width - left_margin - right_margin
    plot_height = 690
    plot_left = left_margin
    plot_top = top_margin
    plot_right = plot_left + plot_width
    plot_bottom = plot_top + plot_height
    row_gap = plot_height / len(rows)
    bar_height = 62
    max_attempts = max(int(row["attempted"]) for row in rows)

    image = Image.new("RGBA", (width, height), "#000000")
    draw = ImageDraw.Draw(image)

    title = "WebForti Experimentation: Operational Status Distribution"
    title_bbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text(
        ((width - (title_bbox[2] - title_bbox[0])) / 2, 24),
        title,
        font=title_font,
        fill="#FFFFFF",
    )

    subtitle = "Qwen is highlighted because it was selected as the final deployment model after recording zero denied outputs."
    subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    draw.text(
        ((width - (subtitle_bbox[2] - subtitle_bbox[0])) / 2, 78),
        subtitle,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    draw.rectangle((plot_left, plot_top, plot_right, plot_bottom), outline="#D1D5DB", width=2)

    tick = 0
    while tick <= max_attempts:
        x = plot_left + int((tick / max_attempts) * plot_width)
        dash_cursor = plot_top
        while dash_cursor < plot_bottom:
            draw.line((x, dash_cursor, x, min(dash_cursor + 9, plot_bottom)), fill="#27313B", width=1)
            dash_cursor += 15
        tick_bbox = draw.textbbox((0, 0), str(tick), font=tick_font)
        draw.text(
            (x - (tick_bbox[2] - tick_bbox[0]) / 2, plot_bottom + 16),
            str(tick),
            font=tick_font,
            fill="#D1D5DB",
        )
        tick += 2

    x_label = "Aggregate Trial Outcomes"
    x_label_bbox = draw.textbbox((0, 0), x_label, font=axis_font)
    draw.text(
        (plot_left + (plot_width - (x_label_bbox[2] - x_label_bbox[0])) / 2, height - 58),
        x_label,
        font=axis_font,
        fill="#FFFFFF",
    )

    draw_rotated_label(
        image,
        "Model Architecture",
        font=axis_font,
        fill="#FFFFFF",
        center=(42, plot_top + plot_height // 2),
    )

    for row_index, row in enumerate(rows):
        model_label = str(row["model"])
        y_center = plot_top + row_gap * row_index + row_gap / 2
        bar_top = int(y_center - bar_height / 2)
        bar_bottom = int(y_center + bar_height / 2)

        if model_label == "Qwen 3.6 35B":
            highlight = (plot_left - 20, bar_top - 16, plot_right + 12, bar_bottom + 16)
            draw.rounded_rectangle(highlight, radius=14, fill="#0B0F12", outline="#FFD166", width=2)

        label_bbox = draw.textbbox((0, 0), model_label, font=label_font)
        draw.text(
            (plot_left - 22 - (label_bbox[2] - label_bbox[0]), bar_top + 12),
            model_label,
            font=label_font,
            fill="#F3F4F6" if model_label != "Qwen 3.6 35B" else "#FFD166",
        )

        cursor_x = plot_left
        for status in ("passed", "failed", "denied", "malformed"):
            count = int(row[status])
            if count <= 0:
                continue
            segment_w = int((count / max_attempts) * plot_width)
            x0 = cursor_x
            x1 = cursor_x + segment_w
            draw.rectangle((x0, bar_top, x1, bar_bottom), fill=STATUS_COLORS[status], outline="#D1D5DB", width=1)
            cursor_x = x1

        if model_label == "Qwen 3.6 35B":
            badge_x0 = plot_right - 120
            badge_y0 = bar_top + 6
            draw.rounded_rectangle(
                (badge_x0, badge_y0, badge_x0 + 96, badge_y0 + 24),
                radius=8,
                fill="#113C2E",
                outline="#FFD166",
                width=1,
            )
            draw.text((badge_x0 + 18, badge_y0 + 4), "FINAL MODEL", font=badge_font, fill="#FFD166")

    legend_x = plot_right - 255
    legend_y = plot_bottom - 150
    draw.rounded_rectangle((legend_x, legend_y, legend_x + 220, legend_y + 122), radius=10, fill="#241825", outline="#A7AEB8", width=2)
    draw.text((legend_x + 92, legend_y + 14), "Status", font=label_font, fill="#FFFFFF")
    for index, status in enumerate(("passed", "failed", "denied", "malformed")):
        y = legend_y + 46 + index * 18
        draw.rectangle((legend_x + 16, y, legend_x + 44, y + 12), fill=STATUS_COLORS[status], outline="#D1D5DB", width=1)
        draw.text((legend_x + 56, y - 4), status, font=legend_font, fill="#F3F4F6")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.convert("RGB").save(output_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Qwen-finalized WebForti benchmark figures.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Benchmark markdown with the Qwen per-CVE table.")
    parser.add_argument("--models", type=Path, default=DEFAULT_MODEL_INPUT, help="Model comparison JSON.")
    parser.add_argument("--latency-output", type=Path, default=DEFAULT_LATENCY_OUTPUT, help="Output path for the latency image.")
    parser.add_argument("--status-output", type=Path, default=DEFAULT_STATUS_OUTPUT, help="Output path for the status distribution image.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    render_qwen_latency_panels(args.latency_output, input_path=args.input, model_input=args.models)
    render_qwen_status_distribution(args.status_output, model_input=args.models)
    print(args.latency_output)
    print(args.status_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
