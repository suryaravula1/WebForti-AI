from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "docs" / "benchmark_results.md"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "latency.png"
DEFAULT_MODEL_INPUT = ROOT / "benchmarks" / "model_comparison.json"
SECTION_RE = re.compile(r"^##\s+(?P<title>.+?)\s*$")
SECONDS_RE = re.compile(r"(?P<seconds>\d+(?:\.\d+)?)s$")


@dataclass(frozen=True)
class CveLatencyPoint:
    cve_id: str
    job_status: str
    verification_status: str
    seconds: float


@dataclass(frozen=True)
class ModelLatencyPoint:
    model_label: str
    average_seconds: float


def extract_per_cve_tables(markdown_text: str) -> list[tuple[str, list[CveLatencyPoint]]]:
    tables: list[tuple[str, list[CveLatencyPoint]]] = []
    lines = markdown_text.splitlines()
    current_section = ""
    index = 0

    while index < len(lines):
        line = lines[index].rstrip()
        heading_match = SECTION_RE.match(line)
        if heading_match:
            current_section = heading_match.group("title")
            index += 1
            continue

        if line.strip() != "Per-CVE results:":
            index += 1
            continue

        table_lines: list[str] = []
        cursor = index + 1
        while cursor < len(lines) and not lines[cursor].strip():
            cursor += 1
        while cursor < len(lines) and lines[cursor].lstrip().startswith("|"):
            table_lines.append(lines[cursor].strip())
            cursor += 1

        rows = _parse_per_cve_table(table_lines)
        if rows:
            tables.append((current_section, rows))
        index = cursor

    return tables


def select_per_cve_table(
    tables: list[tuple[str, list[CveLatencyPoint]]],
    section_filter: str | None = None,
) -> tuple[str, list[CveLatencyPoint]]:
    if not tables:
        raise ValueError("No per-CVE benchmark tables were found.")

    if not section_filter:
        return tables[-1]

    lowered_filter = section_filter.lower()
    matches = [table for table in tables if lowered_filter in table[0].lower()]
    if not matches:
        raise ValueError(f"No per-CVE benchmark table matched section filter: {section_filter}")
    return matches[-1]


def load_per_cve_latency_points(
    input_path: Path,
    *,
    section_filter: str | None = None,
) -> tuple[str, list[CveLatencyPoint]]:
    markdown_text = input_path.read_text(encoding="utf-8")
    tables = extract_per_cve_tables(markdown_text)
    return select_per_cve_table(tables, section_filter)


def load_model_latency_points(input_path: Path) -> list[ModelLatencyPoint]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    rows = payload.get("rows", [])
    points = [
        ModelLatencyPoint(
            model_label=_simplify_model_label(row["model"]),
            average_seconds=float(row["synthetic_avg_seconds"]),
        )
        for row in rows
    ]
    return sorted(points, key=lambda point: point.average_seconds)


def build_synthetic_model_cve_matrix(
    cve_rows: list[CveLatencyPoint],
    model_rows: list[ModelLatencyPoint],
) -> dict[str, object]:
    if not cve_rows or not model_rows:
        raise ValueError("Per-CVE rows and model rows are both required.")

    baseline_average = sum(row.seconds for row in cve_rows) / len(cve_rows)
    cve_labels = [row.cve_id for row in cve_rows]
    model_labels = [row.model_label for row in model_rows]
    values: list[list[float]] = []

    for cve_row in cve_rows:
        complexity_factor = cve_row.seconds / baseline_average
        values.append([round(model.average_seconds * complexity_factor, 1) for model in model_rows])

    return {
        "cve_labels": cve_labels,
        "model_labels": model_labels,
        "values": values,
        "baseline_average_seconds": round(baseline_average, 4),
    }


def render_latency_chart(
    rows: list[CveLatencyPoint],
    output_path: Path,
    *,
    section_title: str,
) -> None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Pillow is required to render the latency chart. Use a Python runtime with Pillow installed."
        ) from exc

    if not rows:
        raise ValueError("At least one per-CVE benchmark row is required to render a chart.")

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

    def round_up(value: float, step: int) -> int:
        return max(step, int(((value + step - 1) // step) * step))

    def dashed_vertical_line(draw: ImageDraw.ImageDraw, x: int, y0: int, y1: int, *, color: str) -> None:
        dash = 12
        gap = 8
        cursor = y0
        while cursor < y1:
            draw.line((x, cursor, x, min(cursor + dash, y1)), fill=color, width=2)
            cursor += dash + gap

    def draw_rotated_label(
        image: Image.Image,
        text: str,
        *,
        font: ImageFont.ImageFont,
        fill: str,
        center: tuple[int, int],
    ) -> None:
        scratch = Image.new("RGBA", (400, 120), (0, 0, 0, 0))
        scratch_draw = ImageDraw.Draw(scratch)
        bbox = scratch_draw.textbbox((0, 0), text, font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
        scratch = Image.new("RGBA", (text_w + 8, text_h + 8), (0, 0, 0, 0))
        scratch_draw = ImageDraw.Draw(scratch)
        scratch_draw.text((4, 4), text, font=font, fill=fill)
        rotated = scratch.rotate(90, expand=True)
        image.alpha_composite(rotated, (center[0] - rotated.width // 2, center[1] - rotated.height // 2))

    labels = [row.cve_id for row in rows]
    values = [row.seconds for row in rows]
    max_seconds = max(values)
    x_axis_max = round_up(max_seconds * 1.18, 5)
    x_tick_step = 5 if x_axis_max <= 40 else 10

    left_margin = 340
    right_margin = 220
    top_margin = 185
    bottom_margin = 150
    row_gap = 110
    bar_height = 74
    plot_width = 1400
    plot_height = row_gap * len(rows)
    width = left_margin + plot_width + right_margin
    height = top_margin + plot_height + bottom_margin
    plot_left = left_margin
    plot_top = top_margin
    plot_right = plot_left + plot_width
    plot_bottom = plot_top + plot_height

    title_font = load_font(34, bold=True)
    subtitle_font = load_font(18)
    axis_label_font = load_font(20)
    tick_font = load_font(15)
    cve_font = load_font(18, bold=True)
    value_font = load_font(18, bold=True)

    section_label = section_title.split(": ", 1)[1] if ": " in section_title else section_title

    image = Image.new("RGBA", (width, height), "#000000")
    draw = ImageDraw.Draw(image)

    title = "Temporal Analysis: Per-CVE Verification Latency"
    title_bbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text(
        ((width - (title_bbox[2] - title_bbox[0])) / 2, 28),
        title,
        font=title_font,
        fill="#FFFFFF",
    )

    subtitle = f"{section_label} | {len(rows)} seeded CVEs"
    subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    draw.text(
        ((width - (subtitle_bbox[2] - subtitle_bbox[0])) / 2, 86),
        subtitle,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    draw.rectangle((plot_left, plot_top, plot_right, plot_bottom), outline="#D1D5DB", width=2)

    tick_value = 0
    while tick_value <= x_axis_max:
        x = plot_left + int((tick_value / x_axis_max) * plot_width)
        dashed_vertical_line(draw, x, plot_top, plot_bottom, color="#2A313C")
        tick_bbox = draw.textbbox((0, 0), str(tick_value), font=tick_font)
        draw.text(
            (x - (tick_bbox[2] - tick_bbox[0]) / 2, plot_bottom + 16),
            str(tick_value),
            font=tick_font,
            fill="#D1D5DB",
        )
        tick_value += x_tick_step

    draw_rotated_label(
        image,
        "CVE Identifier",
        font=axis_label_font,
        fill="#FFFFFF",
        center=(70, plot_top + plot_height // 2),
    )

    x_label = "Verification Latency (Seconds)"
    x_label_bbox = draw.textbbox((0, 0), x_label, font=axis_label_font)
    draw.text(
        (plot_left + (plot_width - (x_label_bbox[2] - x_label_bbox[0])) / 2, height - 70),
        x_label,
        font=axis_label_font,
        fill="#FFFFFF",
    )

    for index, row in enumerate(rows):
        bar_top = plot_top + index * row_gap + (row_gap - bar_height) // 2
        bar_bottom = bar_top + bar_height
        bar_right = plot_left + int((row.seconds / x_axis_max) * plot_width)
        bar_color = "#3FA9F5" if row.verification_status == "pass" else "#F97316"

        cve_bbox = draw.textbbox((0, 0), row.cve_id, font=cve_font)
        cve_w = cve_bbox[2] - cve_bbox[0]
        cve_h = cve_bbox[3] - cve_bbox[1]
        draw.text(
            (plot_left - 22 - cve_w, bar_top + (bar_height - cve_h) / 2 - 2),
            row.cve_id,
            font=cve_font,
            fill="#F3F4F6",
        )

        draw.rounded_rectangle(
            (plot_left, bar_top, max(bar_right, plot_left + 3), bar_bottom),
            radius=10,
            fill=bar_color,
            outline="#58B7FF" if row.verification_status == "pass" else "#FB923C",
            width=2,
        )

        value_text = f"{row.seconds:.1f}s"
        value_bbox = draw.textbbox((0, 0), value_text, font=value_font)
        value_w = value_bbox[2] - value_bbox[0]
        value_h = value_bbox[3] - value_bbox[1]
        draw.text(
            (bar_right + 20, bar_top + (bar_height - value_h) / 2 - 1),
            value_text,
            font=value_font,
            fill=bar_color,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.convert("RGB").save(output_path)


def render_model_cve_matrix(
    cve_rows: list[CveLatencyPoint],
    model_rows: list[ModelLatencyPoint],
    output_path: Path,
    *,
    section_title: str,
) -> None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Pillow is required to render the latency chart. Use a Python runtime with Pillow installed."
        ) from exc

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

    matrix = build_synthetic_model_cve_matrix(cve_rows, model_rows)
    cve_labels: list[str] = matrix["cve_labels"]  # type: ignore[assignment]
    model_labels: list[str] = matrix["model_labels"]  # type: ignore[assignment]
    values: list[list[float]] = matrix["values"]  # type: ignore[assignment]

    left_margin = 290
    right_margin = 60
    top_margin = 220
    bottom_margin = 110
    cell_width = 192
    cell_height = 86
    grid_width = cell_width * len(model_labels)
    grid_height = cell_height * len(cve_labels)
    width = left_margin + grid_width + right_margin
    height = top_margin + grid_height + bottom_margin

    image = Image.new("RGBA", (width, height), "#000000")
    draw = ImageDraw.Draw(image)

    title_font = load_font(32, bold=True)
    subtitle_font = load_font(16)
    axis_font = load_font(17, bold=True)
    header_font = load_font(15, bold=True)
    row_font = load_font(18, bold=True)
    cell_font = load_font(16, bold=True)

    title = "Temporal Analysis: Per-CVE Latency by Model"
    title_bbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text(
        ((width - (title_bbox[2] - title_bbox[0])) / 2, 26),
        title,
        font=title_font,
        fill="#FFFFFF",
    )

    section_label = section_title.split(": ", 1)[1] if ": " in section_title else section_title
    subtitle = f"Illustrative estimate from {section_label} per-CVE profile and repo model averages"
    subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    draw.text(
        ((width - (subtitle_bbox[2] - subtitle_bbox[0])) / 2, 82),
        subtitle,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    grid_left = left_margin
    grid_top = top_margin
    grid_right = grid_left + grid_width
    grid_bottom = grid_top + grid_height
    min_value = min(value for row in values for value in row)
    max_value = max(value for row in values for value in row)
    span = max(max_value - min_value, 0.1)

    draw.rectangle((grid_left, grid_top, grid_right, grid_bottom), outline="#D1D5DB", width=2)

    for col_index, model_label in enumerate(model_labels):
        x0 = grid_left + col_index * cell_width
        box = (x0 + 6, grid_top - 60, x0 + cell_width - 6, grid_top - 12)
        draw.rounded_rectangle(box, radius=10, fill="#111827", outline="#4B5563", width=2)
        parts = model_label.split(" ", 1)
        header_lines = parts if len(parts) == 2 else [model_label]
        line_metrics = [draw.textbbox((0, 0), line, font=header_font) for line in header_lines]
        total_h = sum(metric[3] - metric[1] for metric in line_metrics) + (len(header_lines) - 1) * 2
        cursor_y = grid_top - 36 - total_h / 2
        for line, metric in zip(header_lines, line_metrics):
            line_w = metric[2] - metric[0]
            line_h = metric[3] - metric[1]
            draw.text(
                (x0 + (cell_width - line_w) / 2, cursor_y),
                line,
                font=header_font,
                fill="#F3F4F6",
            )
            cursor_y += line_h + 2

    for row_index, cve_label in enumerate(cve_labels):
        y0 = grid_top + row_index * cell_height
        cve_bbox = draw.textbbox((0, 0), cve_label, font=row_font)
        cve_w = cve_bbox[2] - cve_bbox[0]
        cve_h = cve_bbox[3] - cve_bbox[1]
        draw.text(
            (grid_left - 18 - cve_w, y0 + (cell_height - cve_h) / 2 - 1),
            cve_label,
            font=row_font,
            fill="#F3F4F6",
        )

        for col_index, value in enumerate(values[row_index]):
            x0 = grid_left + col_index * cell_width
            x1 = x0 + cell_width
            y1 = y0 + cell_height
            normalized = (value - min_value) / span
            red = int(59 + normalized * 121)
            green = int(157 - normalized * 69)
            blue = int(246 - normalized * 112)
            fill_color = (red, green, blue)
            draw.rounded_rectangle(
                (x0 + 6, y0 + 6, x1 - 6, y1 - 6),
                radius=12,
                fill=fill_color,
                outline="#60A5FA" if normalized < 0.55 else "#F59E0B",
                width=2,
            )
            value_text = f"{value:.1f}s"
            value_bbox = draw.textbbox((0, 0), value_text, font=cell_font)
            value_w = value_bbox[2] - value_bbox[0]
            value_h = value_bbox[3] - value_bbox[1]
            draw.text(
                (x0 + (cell_width - value_w) / 2, y0 + (cell_height - value_h) / 2 - 2),
                value_text,
                font=cell_font,
                fill="#F9FAFB",
            )

    axis_x_bbox = draw.textbbox((0, 0), "Models", font=axis_font)
    draw.text(
        (grid_left + (grid_width - (axis_x_bbox[2] - axis_x_bbox[0])) / 2, grid_top - 102),
        "Models",
        font=axis_font,
        fill="#FFFFFF",
    )
    axis_y_bbox = draw.textbbox((0, 0), "CVEs", font=axis_font)
    draw.text(
        (72, grid_top - 2),
        "CVEs",
        font=axis_font,
        fill="#FFFFFF",
    )

    footnote = "Estimated from measured Qwen per-CVE timings and the synthetic model averages documented in the repo."
    footnote_bbox = draw.textbbox((0, 0), footnote, font=subtitle_font)
    draw.text(
        ((width - (footnote_bbox[2] - footnote_bbox[0])) / 2, height - 56),
        footnote,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.convert("RGB").save(output_path)


def render_per_cve_panels(
    cve_rows: list[CveLatencyPoint],
    model_rows: list[ModelLatencyPoint],
    output_path: Path,
    *,
    section_title: str,
) -> None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Pillow is required to render the latency chart. Use a Python runtime with Pillow installed."
        ) from exc

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
    top_margin = 150
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

    image = Image.new("RGBA", (width, height), "#000000")
    draw = ImageDraw.Draw(image)

    title = "Temporal Analysis: Assumed Per-CVE Latency by Model"
    title_bbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text(
        ((width - (title_bbox[2] - title_bbox[0])) / 2, 24),
        title,
        font=title_font,
        fill="#FFFFFF",
    )

    section_label = section_title.split(": ", 1)[1] if ": " in section_title else section_title
    subtitle = f"Assumption-based view using previous model latency image + {section_label} per-CVE pattern"
    subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    draw.text(
        ((width - (subtitle_bbox[2] - subtitle_bbox[0])) / 2, 76),
        subtitle,
        font=subtitle_font,
        fill="#9CA3AF",
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

        panel_title_bbox = draw.textbbox((0, 0), cve_label, font=panel_title_font)
        draw.text(
            (panel_x + 24, panel_y + 18),
            cve_label,
            font=panel_title_font,
            fill="#F3F4F6",
        )

        plot_x0 = panel_x + plot_left_pad
        plot_y0 = panel_y + plot_top_pad
        plot_x1 = plot_x0 + plot_width
        plot_y1 = plot_y0 + plot_height
        draw.rectangle((plot_x0, plot_y0, plot_x1, plot_y1), outline="#C6CCD5", width=1)

        tick_step = 10
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
            tick += tick_step

        axis_bbox = draw.textbbox((0, 0), "Latency (s)", font=axis_font)
        draw.text(
            (plot_x0 + (plot_width - (axis_bbox[2] - axis_bbox[0])) / 2, plot_y1 + 28),
            "Latency (s)",
            font=axis_font,
            fill="#FFFFFF",
        )

        for model_idx, (model_label, value) in enumerate(zip(model_labels, values[idx])):
            y_center = plot_y0 + row_gap * model_idx + row_gap / 2
            label_parts = model_label.split(" ", 1)
            label_lines = label_parts if len(label_parts) == 2 and len(model_label) > 11 else [model_label]
            total_text_h = 0
            metrics = []
            for line in label_lines:
                bbox = draw.textbbox((0, 0), line, font=label_font)
                metrics.append((line, bbox))
                total_text_h += bbox[3] - bbox[1]
            total_text_h += (len(label_lines) - 1) * 2
            cursor_y = y_center - total_text_h / 2
            for line, bbox in metrics:
                text_w = bbox[2] - bbox[0]
                text_h = bbox[3] - bbox[1]
                draw.text(
                    (panel_x + 22, cursor_y - 1),
                    line,
                    font=label_font,
                    fill="#F3F4F6",
                )
                cursor_y += text_h + 2

            bar_w = int((value / x_axis_max) * plot_width)
            bar_top = int(y_center - bar_height / 2)
            bar_bottom = int(y_center + bar_height / 2)
            bar_right = plot_x0 + max(bar_w, 4)
            bar_color = "#3FA9F5"
            border_color = "#58B7FF"
            if "Llama" in model_label:
                bar_color = "#6C5EA8"
                border_color = "#F59E0B"
            elif "DeepSeek" in model_label:
                bar_color = "#4F86D1"
                border_color = "#7FB3FF"
            draw.rounded_rectangle(
                (plot_x0, bar_top, bar_right, bar_bottom),
                radius=8,
                fill=bar_color,
                outline=border_color,
                width=2,
            )
            value_text = f"{value:.1f}s"
            draw.text(
                (bar_right + 14, bar_top - 1),
                value_text,
                font=value_font,
                fill=border_color if "Llama" in model_label else "#3FA9F5",
            )

    footnote = "Assumption-based figure for presentation use; derived from repo model averages and observed Qwen per-CVE difficulty."
    footnote_bbox = draw.textbbox((0, 0), footnote, font=subtitle_font)
    draw.text(
        ((width - (footnote_bbox[2] - footnote_bbox[0])) / 2, height - 42),
        footnote,
        font=subtitle_font,
        fill="#9CA3AF",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.convert("RGB").save(output_path)


def _parse_per_cve_table(table_lines: list[str]) -> list[CveLatencyPoint]:
    rows: list[CveLatencyPoint] = []
    for line in table_lines[2:]:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        seconds_match = SECONDS_RE.search(cells[3])
        if not seconds_match:
            continue
        rows.append(
            CveLatencyPoint(
                cve_id=cells[0],
                job_status=cells[1],
                verification_status=cells[2],
                seconds=float(seconds_match.group("seconds")),
            )
        )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a WebForti latency chart from per-CVE benchmark results.")
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Markdown benchmark-results file containing a per-CVE table.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Destination image path for the latency chart.",
    )
    parser.add_argument(
        "--models",
        type=Path,
        default=DEFAULT_MODEL_INPUT,
        help="Model comparison JSON used for illustrative multi-model latency estimates.",
    )
    parser.add_argument(
        "--section",
        default=None,
        help="Optional section-title substring to select a specific per-CVE benchmark table.",
    )
    parser.add_argument(
        "--mode",
        choices=("per-cve-bars", "model-cve-matrix", "per-cve-panels"),
        default="per-cve-panels",
        help="Chart mode to render.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    section_title, rows = load_per_cve_latency_points(args.input, section_filter=args.section)
    if args.mode == "per-cve-bars":
        render_latency_chart(rows, args.output, section_title=section_title)
    elif args.mode == "model-cve-matrix":
        model_rows = load_model_latency_points(args.models)
        render_model_cve_matrix(rows, model_rows, args.output, section_title=section_title)
    else:
        model_rows = load_model_latency_points(args.models)
        render_per_cve_panels(rows, model_rows, args.output, section_title=section_title)
    print(args.output)
    return 0


def _simplify_model_label(label: str) -> str:
    replacements = {
        "OpenAI GPT-5.4": "GPT-5.4",
        "Gemini 2.5 Pro": "Gemini 2.5 Pro",
        "Claude 4.6": "Claude 4.6",
        "Kimi K2": "Kimi K2",
        "Qwen 3.6 35B A3B via OpenRouter": "Qwen 3.6 35B",
        "DeepSeek R1/V3": "DeepSeek R1/V3",
        "Local Llama 3.1 70B": "Llama 3.1 70B",
    }
    return replacements.get(label, label)


if __name__ == "__main__":
    raise SystemExit(main())
