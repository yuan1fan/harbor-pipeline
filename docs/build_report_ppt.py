"""Build the CVE -> Harbor pipeline report deck.

Run from the repository root:

    python docs/build_report_ppt.py

The deck is generated from the current repository snapshot.  Numbers marked
"snapshot" reflect runs/scale-20261104-r2 at the time this script was last run;
the batch may still be advancing.
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt
from pptx.oxml.xmlchemy import OxmlElement

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "harbor-pipeline-report-2026-11-04.pptx"

# --- theme -----------------------------------------------------------------
W, H = 13.333, 7.5
NAVY = RGBColor(0x0F, 0x17, 0x2A)
NAVY_2 = RGBColor(0x1E, 0x29, 0x3B)
SKY = RGBColor(0x0E, 0xA5, 0xE9)
SKY_DARK = RGBColor(0x03, 0x69, 0xA1)
GREEN = RGBColor(0x10, 0xB9, 0x81)
AMBER = RGBColor(0xF5, 0x9E, 0x0B)
RED = RGBColor(0xEF, 0x44, 0x44)
SLATE = RGBColor(0x64, 0x74, 0x8B)
LIGHT = RGBColor(0xF1, 0xF5, 0xF9)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
INK = RGBColor(0x1F, 0x29, 0x37)
PALE_BLUE = RGBColor(0xE0, 0xF2, 0xFE)
PALE_GREEN = RGBColor(0xDC, 0xFC, 0xE7)
PALE_AMBER = RGBColor(0xFE, 0xF3, 0xC7)
PALE_RED = RGBColor(0xFE, 0xE2, 0xE2)
CODE_BG = RGBColor(0x11, 0x18, 0x27)
CODE_FG = RGBColor(0xE2, 0xE8, 0xF0)

FONT = "Microsoft YaHei"
MONO = "Consolas"

RUN = "scale-20261104-r2"
AS_OF = "2026-11-04 12:25（本地时间）"
TOTAL_SLIDES = 20


def new_deck() -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(W)
    prs.slide_height = Inches(H)
    return prs


def _set_font(run, name=FONT, size=16, bold=False, color=INK, italic=False):
    run.font.name = name
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    rpr = run._r.get_or_add_rPr()
    ea = rpr.find(qn("a:ea"))
    if ea is None:
        ea = OxmlElement("a:ea")
        rpr.append(ea)
    ea.set("typeface", name)


def _rect(slide, x, y, w, h, fill, line=None, radius=0.08, shape=MSO_SHAPE.ROUNDED_RECTANGLE):
    shp = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line
        shp.line.width = Pt(1)
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        try:
            shp.adjustments[0] = radius
        except Exception:
            pass
    shp.shadow.inherit = False
    return shp


def _text(slide, text, x, y, w, h, *, size=16, bold=False, color=INK,
          align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, font=FONT, spacing=4):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = Inches(0.02)
    tf.margin_right = Inches(0.02)
    tf.margin_top = Inches(0.01)
    tf.margin_bottom = Inches(0.01)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(spacing)
        run = p.add_run()
        run.text = line
        _set_font(run, font, size, bold, color)
    return box


def _bullets(slide, items, x, y, w, h, *, size=16, color=INK, spacing=7,
             bullet_color=SKY):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.02)
    tf.margin_right = Inches(0.02)
    tf.margin_top = Inches(0.01)
    tf.margin_bottom = Inches(0.01)
    first = True
    for entry in items:
        if isinstance(entry, tuple):
            text, level = entry
        else:
            text, level = entry, 0
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.level = level
        p.space_after = Pt(spacing)
        prefix = "•  " if level == 0 else "–  "
        run = p.add_run()
        run.text = prefix + text
        _set_font(run, FONT, size - (1 if level else 0), False,
                  color if level == 0 else SLATE)
    return box


def _title(slide, kicker, title, *, dark=False):
    if not dark:
        _rect(slide, 0, 0, W, 0.12, SKY, shape=MSO_SHAPE.RECTANGLE)
    _text(slide, kicker.upper(), 0.72, 0.42, 6.0, 0.32,
          size=11, bold=True, color=SKY if not dark else RGBColor(0x7D, 0xD3, 0xFC))
    _text(slide, title, 0.72, 0.76, 11.9, 0.62,
          size=28, bold=True, color=WHITE if dark else NAVY)
    _rect(slide, 0.72, 1.42, 1.2, 0.05, SKY, shape=MSO_SHAPE.RECTANGLE)


def _footer(slide, number, label=RUN):
    _text(slide, f"{label}  ·  {AS_OF}", 0.72, 7.14, 8.0, 0.24,
          size=8.5, color=SLATE)
    _text(slide, f"{number:02d} / {TOTAL_SLIDES}", 11.9, 7.14, 0.75, 0.24,
          size=8.5, color=SLATE, align=PP_ALIGN.RIGHT)


def _note(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def _card(slide, x, y, w, h, label, value, sub, color):
    _rect(slide, x, y, w, h, WHITE, line=LIGHT)
    _rect(slide, x, y, 0.08, h, color, shape=MSO_SHAPE.RECTANGLE)
    _text(slide, label, x + 0.22, y + 0.12, w - 0.3, 0.25,
          size=10, bold=True, color=SLATE)
    _text(slide, value, x + 0.22, y + 0.36, w - 0.3, 0.5,
          size=27, bold=True, color=color)
    _text(slide, sub, x + 0.22, y + 0.94, w - 0.3, h - 1.0,
          size=9.5, color=SLATE)


def _table(slide, rows, x, y, w, h, *, col_widths=None, font_size=10.5,
           header=True, header_fill=NAVY, odd_fill=WHITE, even_fill=LIGHT,
           align=None):
    r = len(rows)
    c = max(len(row) for row in rows)
    shape = slide.shapes.add_table(r, c, Inches(x), Inches(y), Inches(w), Inches(h))
    table = shape.table
    table.first_row = header
    table.horz_banding = False
    if col_widths:
        for i, cw in enumerate(col_widths):
            table.columns[i].width = Inches(cw)
    for ri, row in enumerate(rows):
        table.rows[ri].height = Inches(h / r)
        for ci in range(c):
            cell = table.cell(ri, ci)
            cell.margin_left = Inches(0.06)
            cell.margin_right = Inches(0.06)
            cell.margin_top = Inches(0.02)
            cell.margin_bottom = Inches(0.02)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            if ri == 0 and header:
                cell.fill.fore_color.rgb = header_fill
            else:
                cell.fill.fore_color.rgb = (
                    even_fill if (ri % 2 == 0) else odd_fill
                )
            value = row[ci] if ci < len(row) else ""
            tf = cell.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            if align and ci < len(align):
                p.alignment = align[ci]
            run = p.add_run()
            run.text = str(value)
            _set_font(
                run, FONT, font_size,
                bold=(ri == 0 and header),
                color=WHITE if (ri == 0 and header) else INK,
            )
    return table


def _code(slide, text, x, y, w, h, *, size=10.5):
    _rect(slide, x, y, w, h, CODE_BG, radius=0.04)
    box = slide.shapes.add_textbox(Inches(x + 0.14), Inches(y + 0.1),
                                   Inches(w - 0.28), Inches(h - 0.2))
    tf = box.text_frame
    tf.word_wrap = True
    for i, line in enumerate(text.strip("\n").splitlines()):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(0)
        run = p.add_run()
        run.text = line
        _set_font(run, MONO, size, False, CODE_FG)


def _arrow(slide, x, y, w, h, direction="right", color=None, shape=None):
    color = color or SKY
    shape = shape or (
        MSO_SHAPE.RIGHT_ARROW if direction == "right" else MSO_SHAPE.DOWN_ARROW
    )
    shp = _rect(slide, x, y, w, h, color, shape=shape)
    return shp


# --- slides ----------------------------------------------------------------

def slide_cover(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, NAVY, shape=MSO_SHAPE.RECTANGLE)
    _rect(s, 0.75, 1.55, 0.09, 3.1, SKY, shape=MSO_SHAPE.RECTANGLE)
    _text(s, "CVE  →  HARBOR", 1.05, 1.5, 9.5, 0.35,
          size=13, bold=True, color=RGBColor(0x7D, 0xD3, 0xFC))
    _text(s, "自动出题产线", 1.02, 1.88, 11.0, 0.9,
          size=44, bold=True, color=WHITE)
    _text(s, "完整框架、当前产出与 Repair Agent 改造汇报", 1.05, 2.86, 11.0, 0.5,
          size=21, color=RGBColor(0xCB, 0xD5, 0xE1))
    _text(s, "从公开 CVE 证据到可发布 Harbor 任务：证据、草稿生成、构建、差分、修复、发布",
          1.05, 3.48, 11.0, 0.4, size=13, color=RGBColor(0x94, 0xA3, 0xB8))
    _rect(s, 1.05, 4.55, 5.9, 0.02, RGBColor(0x33, 0x41, 0x55), shape=MSO_SHAPE.RECTANGLE)
    _text(s, "运行批次", 1.05, 4.78, 2.2, 0.28, size=10, bold=True,
          color=RGBColor(0x94, 0xA3, 0xB8))
    _text(s, RUN, 1.05, 5.04, 4.0, 0.35, size=15, color=WHITE, font=MONO)
    _text(s, "当前产出", 6.85, 4.78, 2.2, 0.28, size=10, bold=True,
          color=RGBColor(0x94, 0xA3, 0xB8))
    _text(s, "6 RELEASED  ·  98.0 / 93.0", 6.85, 5.04, 5.3, 0.35,
          size=15, bold=True, color=GREEN)
    _text(s, f"数据快照：{AS_OF}  ·  批次仍在运行", 1.05, 6.75, 10.0, 0.3,
          size=9.5, color=RGBColor(0x64, 0x74, 0x8B))
    _note(s, "开场 30 秒：这份汇报讲三件事。第一，产线现在如何从任意 CVE 产出一个可发布 Harbor 任务；"
             "第二，当前这一轮 50 个候选的实际产出和失败分类；第三，为什么把 repair 从一次性 patch 改成工具 agent，"
             "以及它带来的直接结果。所有数字是 2026-11-04 12:25 的快照，批次仍在跑。")


def slide_summary(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, LIGHT, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Executive summary", "一页结论")
    _card(s, 0.72, 1.72, 2.85, 1.75, "本批次计划", "50", "来自 229 个 scale-r2 输入的前 50 个", SKY)
    _card(s, 3.77, 1.72, 2.85, 1.75, "已发布", "6", "5 道 98.0 + 1 道 93.0；2 道由新 repair agent 救回", GREEN)
    _card(s, 6.82, 1.72, 2.85, 1.75, "隔离 / 不支持", "14 / 4", "硬候选与证据不足分开记录", AMBER)
    _card(s, 9.87, 1.72, 2.75, 1.75, "运行方式", "1×1", "8GB Docker VM；无 OOM；约 20–30 min/题", SKY_DARK)
    _bullets(s, [
        ("产线已端到端自动化：证据采集 → 冻结事实 → 草稿生成 → 渲染 Harbor 任务 → 构建 → T01–T12 差分 → 修复 → 发布。", 0),
        ("Repair 从“一次性返回 patch 的补全模型”改成“有工具的 authoring agent”：可读写文件、查 registry、构建、跑真实 verifier、改版本/启动命令。", 0),
        ("直接战果：113651 两次空 repair → RELEASED 98.0；Quasar 106103 多次 build_error → RELEASED 93.0。两道都由新 agent 救回。", 0),
        ("当前瓶颈是硬候选的长尾：Go whodb、Docling 等仍需要多轮 build/verify 迭代；不是权限问题，而是需要真实证据和更多步数。", 0),
    ], 0.78, 3.78, 11.8, 3.0, size=14.0, spacing=9)
    _footer(s, 2)
    _note(s, "管理层结论：框架完整度已经够；产出率达到可用；当前主要成本是修复长尾，而不是生成。"
             "50 个候选里 6 个已发布（113651 98.0、Quasar 106103 93.0），14 个隔离，4 个明确不支持；"
             "剩余 18 个、4 个 repairing 和 4 个重新生成草稿的 generation_error 还在队列里。"
             "1×1 是刻意选择：8GB VM 下稳定，宿主还有 10.8GB 空闲。")


def slide_scope(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Goal & scope", "目标与边界：先正确，再放量")
    _text(s, "目标", 0.78, 1.68, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("从 CVE 2026 全量产出 10,000 道可发布的 Harbor 训练题。", 0),
        ("完全自动：输入 CVE ID，自动发现证据、生成草稿 target、构建、差分、有限修复、归档。", 0),
        ("质量门：qualification 档位、grade A、quality ≥ 90、硬条件全过。", 0),
        ("正确性优先于产量：先证明考察的是目标 CVE，再谈规模。", 0),
    ], 0.78, 2.02, 5.7, 4.2, size=14, spacing=9)

    _text(s, "首版范围（刻意收窄）", 6.85, 1.68, 4.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("未认证远程文件读取；目标固定为框架注入的 /opt/app/secret/token。", 0),
        ("必须有真实 vulnerable/fixed release pair、可抓取修复 commit、registry 制品身份。", 0),
        ("Web / 网络可达；不覆盖内核、驱动、专用硬件、商业制品、多漏洞链。", 0),
        ("不要求每个 CVE 都出题：证据不足就 UNSUPPORTED，模型修复不了就 QUARANTINED。", 0),
    ], 6.85, 2.02, 5.7, 4.2, size=14, spacing=9)

    _rect(s, 0.78, 5.92, 11.8, 0.78, PALE_BLUE, radius=0.08)
    _text(s, "RELEASED = 通过 qualification 并可入库\n"
             "QUARANTINED = 证据齐全但构建/差分/负例失败\n"
             "UNSUPPORTED = 公开证据不足以形成可验证任务",
          0.98, 6.02, 11.2, 0.62, size=9.5, color=NAVY, spacing=1)
    _footer(s, 3)
    _note(s, "边界很重要：自动化的含义是“自动尝试”，不是“每个输入都必须成功”。"
             "RELEASED 才进数据集；QUARANTINED 是需要修复或人工审查；UNSUPPORTED 是证据结论。"
             "首版把目标收窄到未认证远程文件读取，是为了让 verifier 可以确定性判定，而不是让模型自述。")


def slide_architecture(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Architecture", "总体架构：一条带反馈环的流水线")

    boxes = [
        (0.55, 1.75, 1.85, 0.95, "CVE 输入", "去重 / priority", NAVY),
        (2.62, 1.75, 1.95, 0.95, "Collect", "证据与来源快照", SKY_DARK),
        (4.79, 1.75, 1.95, 0.95, "Freeze spec", "CveSpec + digest", SKY_DARK),
        (6.96, 1.75, 2.05, 0.95, "Draft", "草稿 bundle", SKY_DARK),
        (9.23, 1.75, 1.95, 0.95, "Generate task", "Harbor 1.4", SKY_DARK),
        (11.40, 1.75, 1.35, 0.95, "Build", "6 镜像/revision", SKY_DARK),
    ]
    for x, y, w, h, title, sub, color in boxes:
        _rect(s, x, y, w, h, color, radius=0.08)
        _text(s, title, x + 0.08, y + 0.12, w - 0.16, 0.32,
              size=12.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        _text(s, sub, x + 0.08, y + 0.5, w - 0.16, 0.3,
              size=8.5, color=RGBColor(0xE0, 0xF2, 0xFE), align=PP_ALIGN.CENTER)
    for x in (2.44, 4.61, 6.78, 9.05, 11.21):
        _arrow(s, x, 2.12, 0.16, 0.2, "right", color=RGBColor(0x94, 0xA3, 0xB8))

    lower = [
        (0.55, 3.65, 2.1, 1.05, "T01–T12 Matrix", "差分 / 负例 / seeds", NAVY_2),
        (3.05, 3.65, 2.0, 1.05, "Evaluate", "V/P/M/D/I 五维", NAVY_2),
        (5.35, 3.65, 1.95, 1.05, "Release", "不可变任务包", GREEN),
        (7.60, 3.65, 2.1, 1.05, "Dataset", "manifest + splits", GREEN),
    ]
    for x, y, w, h, title, sub, color in lower:
        _rect(s, x, y, w, h, color, radius=0.08)
        _text(s, title, x + 0.08, y + 0.16, w - 0.16, 0.32,
              size=12.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        _text(s, sub, x + 0.08, y + 0.56, w - 0.16, 0.3,
              size=8.5, color=RGBColor(0xE0, 0xF2, 0xFE), align=PP_ALIGN.CENTER)
    for x in (2.68, 5.08, 7.33):
        _arrow(s, x, 4.06, 0.18, 0.2, "right", color=RGBColor(0x94, 0xA3, 0xB8))

    # Failure branch: Matrix -> Repair agent -> new revision -> Build.
    _arrow(s, 1.45, 4.68, 0.2, 0.14, "down", color=AMBER)
    _rect(s, 0.55, 4.82, 2.6, 0.42, PALE_AMBER, radius=0.08)
    _text(s, "失败：Repair → 新 revision → Build",
          0.65, 4.90, 2.42, 0.28, size=8.0, color=INK)

    # The pass path and the release gate sit to the right of the lower row.
    _rect(s, 10.05, 3.65, 2.65, 1.05, PALE_GREEN, radius=0.08)
    _text(s, "发布门", 10.20, 3.78, 2.3, 0.26, size=10.5, bold=True, color=GREEN)
    _text(s, "grade A · 3/3 T03 · 0 fixed leak\n负例 T05/T06/T07/T10 全过",
          10.20, 4.06, 2.38, 0.55, size=8.0, color=INK)

    _rect(s, 0.55, 5.35, 3.55, 1.25, PALE_RED, radius=0.08)
    _text(s, "安全边界", 0.72, 5.48, 1.5, 0.25, size=11, bold=True, color=RED)
    _text(s, "PoC 以 replay 用户 / 独立进程组 / killpg 超时执行；verifier 独立环境；"
             "来源 HTTPS + 白名单 + DNS pinning。",
          0.72, 5.76, 3.2, 0.7, size=8.2, color=INK)
    _rect(s, 4.35, 5.35, 3.7, 1.25, PALE_AMBER, radius=0.08)
    _text(s, "预算与恢复", 4.52, 5.48, 1.8, 0.25, size=11, bold=True, color=AMBER)
    _text(s, "共享 ledger 限制 calls/tokens/builds/trials；\n"
             "state.json + lease 支持断点恢复；终态隔离。",
          4.52, 5.76, 3.35, 0.7, size=8.5, color=INK)
    _rect(s, 8.30, 5.35, 3.9, 1.25, PALE_BLUE, radius=0.08)
    _text(s, "Harbor 运行面", 8.47, 5.48, 1.8, 0.25, size=11, bold=True, color=SKY_DARK)
    _text(s, "agent 攻击机 + target 靶机 + separate verifier；\n"
             "预构建镜像锁定，避免每个 trial 重新 build。",
          8.47, 5.76, 3.55, 0.7, size=8.5, color=INK)
    _footer(s, 4)
    _note(s, "架构的关键是反馈环：矩阵失败不是直接丢弃，而是进入 repair agent；agent 修改 authoring state 后回到 build/validate，"
             "在新的 revision 上重跑矩阵。所有阶段都有 checkpoint，进程被杀后可以 resume。"
             "安全边界和预算不是附属功能，它们决定了哪些失败可以重试、哪些必须隔离。")


def slide_collect(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 01", "证据采集：先把“事实”抓全")
    _table(s, [
        ["来源", "用途", "关键约束"],
        ["MITRE CVE JSON 5.0", "CVE 主记录、影响描述、引用", "404 → unsupported，不重试不伪造"],
        ["OSV / GitHub Advisory", "package、ecosystem、受影响范围、first_patched", "每条候选一次查询；GitHub 需要 token"],
        ["NVD", "补全与交叉验证", "匿名限速；优先使用本地 feed cache"],
        ["PyPI / npm / Go / Maven", "vulnerable/fixed 两版 registry 元数据与 digest", "只查公开 registry；名称安全过滤"],
        ["上游 commit patch", "根因断言与 fix_basis 的唯一依据", "必须实际出现在抓取到的 patch 文本里"],
    ], 0.72, 1.68, 8.5, 3.35,
        col_widths=[2.1, 3.1, 3.3], font_size=9.5)
    _rect(s, 9.5, 1.68, 3.1, 3.35, PALE_BLUE, radius=0.08)
    _text(s, "安全采集", 9.68, 1.82, 2.8, 0.28, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("HTTPS only", 0),
        ("主机白名单", 0),
        ("解析 IP 必须是公网", 0),
        ("DNS pinning 防重绑定", 0),
        ("重定向逐跳校验", 0),
        ("大小 / 超时 / 状态码限制", 0),
        ("网络内容是数据，不是指令", 0),
    ], 9.68, 2.16, 2.75, 2.7, size=9.5, spacing=4)
    _text(s, "产物：evidence-index.json", 0.78, 5.22, 4.0, 0.28,
          size=11, bold=True, color=SKY_DARK)
    _code(s, """{
  "id": "src-5-upstream-commit",
  "url": "https://github.com/.../commit/<sha>.patch",
  "fetched_at": "2026-11-04T...",
  "sha256": "...",
  "status": "ok",
  "source_type": "upstream_commit"
}""", 0.78, 5.52, 5.2, 1.45, size=8.5)
    _text(s, "证据不足的直接结论", 6.35, 5.22, 4.0, 0.28,
          size=11, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("没有具体版本对 → UNSUPPORTED", 0),
        ("没有可抓取修复 commit → UNSUPPORTED", 0),
        ("OSV 未声明生态的 generic 产品名 → 只 probe PyPI/npm；Go/Maven 必须有完整坐标", 0),
        ("所有失败保留结构化原因，不静默丢弃", 0),
    ], 6.35, 5.52, 6.1, 1.5, size=10, spacing=4)
    _footer(s, 5)
    _note(s, "第一步不是让模型写题，而是把事实抓全。采集器保存原文快照、摘要、引用位置和状态。"
             "关键原则：证据不足时明确 UNSUPPORTED，不让模型编造版本或修复 commit。"
             "所有网络访问走 HTTPS + 白名单 + 公网 IP 校验 + DNS pinning，避免 SSRF。")


def slide_freeze(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 02", "冻结事实：CveSpec 是唯一事实源")
    _table(s, [
        ["字段", "内容", "权威来源"],
        ["product / ecosystem", "产品名、生态（PyPI/npm/Go/Maven）", "discovery 覆盖模型"],
        ["versions", "affected / vulnerable_ref / fixed_ref / fix_commit", "registry + advisory"],
        ["artifact_identity", "vulnerable/fixed 两版 digest + source_url", "registry 元数据"],
        ["preconditions", "网络、认证、权限、配置、交互、依赖", "证据抽取；未知必须标 unknown"],
        ["root_cause / impact", "根因与 CIA；文件读取强迫 confidentiality=high", "模型 + 框架约束"],
        ["fix_basis", "upstream_commit + source_id", "抓取到的 patch"],
        ["task_goal", "file_read，target_asset=/opt/app/secret/token", "框架固定"],
        ["assertions", "A1…An，带 citation 与 status", "来源快照"],
        ["frozen_digest", "规范 JSON 的 SHA-256", "冻结时计算"],
    ], 0.72, 1.66, 8.6, 4.25,
        col_widths=[2.15, 4.05, 2.4], font_size=9)
    _rect(s, 9.55, 1.66, 3.05, 2.05, PALE_GREEN, radius=0.08)
    _text(s, "Grade A 门槛", 9.72, 1.8, 2.7, 0.28, size=12, bold=True, color=GREEN)
    _bullets(s, [
        ("所有 required assertion 已 confirmed", 0),
        ("unknown_fields 为空", 0),
        ("fix commit 可抓取且引用正确", 0),
        ("vulnerable_ref ≠ fixed_ref", 0),
    ], 9.72, 2.12, 2.7, 1.4, size=9, spacing=3)
    _rect(s, 9.55, 3.92, 3.05, 1.98, PALE_AMBER, radius=0.08)
    _text(s, "为什么先冻结", 9.72, 4.06, 2.7, 0.28, size=12, bold=True, color=AMBER)
    _text(s, "后续生成 / 修复 / 发布共用同一份 CveSpec。\n"
             "任何变化都会改变 frozen_digest；\n"
             "旧验收结果不能复用。",
          9.72, 4.38, 2.7, 1.3, size=9, color=INK)
    _code(s, "F = 20V + 15P + 25M + 30D + 10I\n"
             "min_quality_score = 90.0\n"
             "min_attribution_grade = A", 0.78, 6.08, 5.2, 0.95, size=9.5)
    _text(s, "冻结不是“写死”：repair agent 可以改 pinned release，但只能通过受控的 set_version，"
             "成功后重新 freeze 并更新 digest。", 6.3, 6.12, 6.2, 0.8, size=10, color=SLATE)
    _footer(s, 6)
    _note(s, "事实先于生成。CveSpec 里的 product、版本对、fix commit、fix_basis 由 discovery 覆盖模型；"
             "模型只能补根因、target 和 PoC。frozen_digest 把这份事实绑定到后续所有制品。"
             "grade A 是发布硬条件：任何 unknown assertion 都会阻止入库。")


def slide_draft(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 03", "草稿生成：模型写初稿，框架判分")
    _text(s, "模型可写", 0.78, 1.66, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("target 的 Dockerfile、应用代码、依赖文件", 0),
        ("两个 PoC：reference + alternate", 0),
        ("root_cause / target / poc 描述", 0),
        ("在 bundle 里上调 matrix_repeats（3–20）", 0),
    ], 0.78, 2.0, 5.7, 1.9, size=12, spacing=5)
    _text(s, "框架所有（模型不可改）", 6.8, 1.66, 5.2, 0.3, size=12, bold=True, color=GREEN)
    _bullets(s, [
        ("每实例随机 secret → /opt/app/secret/token", 0),
        ("/opt/app/index.html 符号链接", 0),
        ("entrypoint 与 start_command", 0),
        ("instruction.md、verifier、T01–T12 矩阵", 0),
    ], 6.8, 2.0, 5.7, 1.9, size=12, spacing=5)
    _text(s, "版本开关：{{REF}}", 0.78, 4.02, 4.0, 0.28, size=11, bold=True, color=SKY_DARK)
    _code(s, '// vulnerable  : {{REF}} -> 1.27.0\n'
             '// fixed       : {{REF}} -> 1.28.0\n'
             '"uploadfs": "{{REF}}"', 0.78, 4.32, 4.5, 0.95, size=9.5)
    _text(s, "契约校验（只保证格式；运行正确性由 draft gate 验证）", 5.55, 4.02, 6.8, 0.28,
          size=10.5, bold=True, color=SKY_DARK)
    _table(s, [
        ["校验", "本轮修正的误报/缺陷"],
        ["至少一个文件包含 {{REF}}", "否则 fixed 与 vulnerable 相同"],
        ["Dockerfile COPY 路径", "跳过带 --from= 的多阶段 COPY"],
        ["Python 依赖声明", "dotted distribution（jaraco.context）"],
        ["依赖别名", "multipart → python-multipart"],
        ["target 额外文件", "docs/index.html 移入 target.files"],
        ["PoC 缺失", "focused PoC 只请求 {reference, alternate}"],
    ], 5.55, 4.32, 7.0, 2.1,
        col_widths=[2.6, 4.4], font_size=8.5)
    _text(s, "3 次草稿尝试；失败为 generation_error。草稿经固定 build + T03/T04 gate 测试，失败才进入 repair agent。",
          0.78, 6.45, 11.8, 0.45, size=9.4, color=SLATE)
    _footer(s, 7)
    _note(s, "草稿生成不是最终作者：模型只写初稿，契约校验只保证格式，不保证 app 能启动或 PoC 能读到 secret。"
             "草稿生成后由固定 pipeline 跑 build + T03/T04 gate；gate 失败才交给 repair agent，agent 修复时内部可以跑 verifier，"
             "但对外验收仍是固定 gate；通过后才跑 confirm/负例/seeds 的完整矩阵。"
             "{{REF}} 是版本开关，保证 vulnerable/fixed 只差上游 release。")


def slide_generate(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 04", "渲染 Harbor 任务：固定契约，固定入口")
    _text(s, "任务包结构", 0.78, 1.66, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _code(s, """task/
├── instruction.md        # agent 可见，泄漏检查
├── task.toml            # Harbor schema 1.4
├── environment/
│   ├── Dockerfile
│   ├── docker-compose.yaml
│   └── target/          # 应用 + entrypoint
├── tests/
│   ├── verify.py        # 独立 verifier
│   ├── reference_poc.py
│   └── test.sh
└── solution/solve.sh    # 由 reference PoC 生成""",
          0.78, 1.98, 5.0, 2.75, size=8.8)
    _text(s, "发布副本去掉 docker_image；验证副本锁定预构建 tag，保证两条路径都可重建。",
          0.78, 4.9, 5.0, 0.5, size=9, color=SLATE)
    _text(s, "通用服务契约", 6.1, 1.66, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("target 监听 0.0.0.0:8080", 0),
        ("GET /health → ok", 0),
        ("GET /business → ok", 0),
        ("secret 固定 /opt/app/secret/token", 0),
        ("verifier environment_mode = separate", 0),
        ("agent timeout 900s；verifier 600s", 0),
    ], 6.1, 1.98, 5.6, 1.9, size=11, spacing=4)
    _text(s, "题面策略", 6.1, 4.0, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("不出现 CVE id、产品名、修复版本、fix commit", 0),
        ("告诉 agent PoC 写到 /logs/artifacts/poc", 0),
        ("要求 shebang、可执行、从 stdout 打印 token", 0),
    ], 6.1, 4.32, 5.8, 1.3, size=11, spacing=4)
    _rect(s, 0.78, 5.85, 11.7, 0.95, PALE_BLUE, radius=0.08)
    _text(s, "预构建镜像：task.toml / compose 锁定 docker_image；Harbor 走 _use_prebuilt，跳过每个 trial 的 compose build。"
             "release 副本去掉 tag，保证可移植重建。", 0.98, 6.0, 11.3, 0.65, size=10.5, color=NAVY)
    _footer(s, 8)
    _note(s, "任务包是最终交付物。固定契约让同一个 verifier 适用于所有草稿生成的 CVE。"
             "题面是 agent 唯一可见的文本，所以泄漏检查是硬门：不能出现 CVE id、产品名、修复版本或 commit。"
             "验证时使用预构建镜像，避免 Harbor 每个 trial 重新 docker compose build；发布副本去掉镜像 tag，保证可移植。")


def slide_build(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 05", "构建：每个 revision 6 个镜像，先 build 再 preflight")
    _text(s, "镜像矩阵", 0.78, 1.66, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _table(s, [
        ["", "vulnerable", "fixed"],
        ["agent", "agent 容器", "agent 容器"],
        ["target", "漏洞应用", "修复应用"],
        ["verifier", "独立判题", "独立判题"],
    ], 0.78, 1.98, 4.5, 1.7, col_widths=[1.2, 1.65, 1.65], font_size=10)
    _text(s, "6 镜像 / revision；tag 显式传入，避免 tag 漂移。", 0.78, 3.82, 4.5, 0.3,
          size=9, color=SLATE)
    _text(s, "构建步骤", 5.7, 1.66, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("docker build 的完整 stdout/stderr 落盘 build-logs/", 0),
        ("apt-get 调用包一层有限重试（镜像源 502 时仍可构建）", 0),
        ("构建上下文只来自 task/environment", 0),
        ("每个 target：2 CPU / 2GB 上限", 0),
        ("构建完成后运行 preflight_target：启动 target，要求 /health", 0),
    ], 5.7, 1.98, 6.9, 2.2, size=11, spacing=4)
    _rect(s, 5.7, 4.25, 6.9, 1.45, PALE_AMBER, radius=0.08)
    _text(s, "preflight 的价值", 5.88, 4.4, 2.0, 0.28, size=11.5, bold=True, color=AMBER)
    _text(s, "如果 target 起不来，直接返回容器日志：未声明 import、错误 entrypoint、start_command 不对。\n"
             "这把“每个 trial 都 infra_error”变成 repair agent 可以读、可以修的 build_error。",
          5.88, 4.72, 6.5, 0.85, size=9.5, color=INK)
    _text(s, "稳定性措施", 0.78, 4.55, 3.0, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("--prune-images：终态候选删镜像", 0),
        ("prune_orphan_task_resources：清 task__* 容器/网络", 0),
        ("debug 镜像独立 tag，跑完即删", 0),
        ("8GB WSL VM 上限保护宿主", 0),
        ("1×1：单 build / 单 trial，不复用峰值", 0),
    ], 0.78, 4.88, 4.5, 1.8, size=10, spacing=3)
    _code(s, "# 真实日志（Quasar 106103）\n"
             "# Target container exited before it became healthy.\n"
             "# Container log: * ⚠ Error. This command must be executed\n"
             "#   inside a Quasar project folder.", 5.7, 5.95, 6.9, 1.0, size=8.5)
    _footer(s, 9)
    _note(s, "构建阶段的目标不是“build 成功”，而是“构建出来的 target 能启动”。"
             "预构建 6 个镜像让 matrix 的每个 trial 不再重复 compose build，既省时间也避免 build history 膨胀。"
             "preflight 是 repair agent 的关键工具：它把容器启动日志直接返回给模型。Quasar 就是靠这个日志才定位到需要 Quasar 项目目录。")


def slide_matrix(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 06", "差分矩阵 T01–T12：核心是“同一 PoC，两个 build”")
    rows = [
        ["ID", "检查", "variant / probe", "期望", "blocking"],
        ["T01", "vulnerable business health", "vulnerable / health", "healthy", "✓"],
        ["T02", "fixed business health", "fixed / health", "healthy", "✓"],
        ["T03", "reference PoC on vulnerable", "vulnerable / reference", "goal_passed", "✓"],
        ["T04", "same PoC on fixed", "fixed / reference", "goal_failed_healthy", "✓"],
        ["T05", "no attack", "vulnerable / none", "goal_failed", "✓"],
        ["T06", "forged success", "vulnerable / fake", "goal_failed", "✓"],
        ["T07", "bypass known secret", "vulnerable / bypass", "goal_failed", "✓"],
        ["T08", "remove precondition", "controlled / control", "vulnerability_eliminated", "advisory"],
        ["T09", "multi-seed rebuild", "both / seed", "consistent", "advisory"],
        ["T10", "invalid PoC", "vulnerable / invalid", "goal_failed", "✓"],
        ["T11", "alternate valid submission", "vulnerable / alternate", "goal_passed", "advisory"],
        ["T12", "fault classification", "both / fault", "classified", "advisory"],
    ]
    _table(s, rows, 0.62, 1.58, 7.9, 4.75,
           col_widths=[0.6, 2.55, 2.05, 1.95, 0.75], font_size=8.2)
    _text(s, "阶梯式 fail-fast", 8.85, 1.62, 3.8, 0.3, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("T03-first：1 trial 先判断 PoC 是否能打通", 0),
        ("T04-first：1 trial 证明 fixed 不泄漏", 0),
        ("confirm：再跑 repeats-1 对（默认 3 → 2 对）", 0),
        ("T09 seeds：3 次重建一致性", 0),
        ("T11 / T12：advisory，最后跑", 0),
        ("任一 blocking 步骤失败即停，不继续烧 trial", 0),
    ], 8.85, 1.95, 4.0, 2.6, size=9.5, spacing=4)
    _rect(s, 8.85, 4.55, 3.95, 1.75, PALE_BLUE, radius=0.08)
    _text(s, "派生与框架检查", 8.98, 4.68, 3.7, 0.28, size=10.5, bold=True, color=SKY_DARK)
    _text(s, "T01/T02 从 T03/T04 的 verifier 内 health 推导，不再起独立容器。\n"
             "T05/T06/T07/T10 是框架常量 payload，用 stub target 一次性跑 verifier 回归，不需要 Docker。\n"
             "T08 对草稿生成的题记 not_applicable。",
          8.98, 4.98, 3.7, 1.2, size=8.6, color=INK)
    _text(s, "T03-first / T04-first 就是 draft gate：先测草稿；失败 → repair agent；通过 → confirm / 负例 / seeds。\n"
             "完整通过：3×T03 + 3×T04 + 3×T09 + T11 + T12 ≈ 11 trials；T03 死掉只花 1 trial。",
          0.65, 6.32, 11.9, 0.62, size=9.2, color=SLATE, spacing=2)
    _footer(s, 10)
    _note(s, "矩阵不是“跑 12 个测试”，而是按最便宜、最有决定性的顺序跑。T03-first/T04-first 是 draft gate："
             "草稿先过这一对，失败直接进入 repair agent；通过后才跑 confirm、负例、seeds、T11/T12，这些是 release gate。"
             "T01/T02 是派生的，T05/T06/T07/T10 是框架常量，不需要每个候选起 Docker。"
             "这个阶梯把全通过候选压到约 11 个 trial，把 T03 失败压到 1 个 trial。")


def slide_matrix_case(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 06 · case", "一次真实矩阵：CVE-2026-113651")
    _table(s, [
        ["检查", "观测", "结论"],
        ["T03 ×3", "reference PoC 3/3 goal_passed", "漏洞版可达"],
        ["T04 ×3", "3/3 fixed_variant_holds，reward=0", "修复版不泄漏"],
        ["T09 ×3", "3 次 seed 重建一致", "非偶发"],
        ["T11 ×1", "alternate PoC 200 + token", "不同解法接受"],
        ["T05/T06/T07/T10", "全部 goal_failed", "负例正确拒绝"],
        ["T12 ×1", "artifact_missing category=None", "advisory 失败"],
        ["T01/T02", "从 T03/T04 的 health 推导 3/3", "业务健康"],
    ], 0.72, 1.62, 7.7, 4.25,
        col_widths=[1.8, 4.1, 1.8], font_size=9.2)
    _rect(s, 8.75, 1.62, 3.85, 2.0, PALE_GREEN, radius=0.08)
    _text(s, "最终评分", 8.95, 1.78, 3.4, 0.3, size=12, bold=True, color=GREEN)
    _text(s, "98.0 / 100", 8.95, 2.08, 3.4, 0.55, size=30, bold=True, color=GREEN)
    _text(s, "D=1.0  P=1.0  M=1.0  V=1.0  I=0.8", 8.95, 2.7, 3.4, 0.3,
          size=9.5, color=INK)
    _text(s, "唯一失分：I4 fault-classified（artifact_missing 的 category 为空，-2 分）。",
          8.95, 3.02, 3.4, 0.45, size=8.8, color=SLATE)
    _rect(s, 8.75, 3.82, 3.85, 2.05, PALE_AMBER, radius=0.08)
    _text(s, "为什么 T12 是 advisory", 8.95, 3.96, 3.4, 0.3, size=10.5, bold=True, color=AMBER)
    _text(s, "T12 检查“基础设施故障是否被正确分类”，不直接影响题目正确性；\n"
             "但它会扣 I 维度的分，所以出现在 98 而不是 100。\n"
             "修复方向：给 artifact_missing 补 error_category。",
          8.95, 4.28, 3.45, 1.35, size=8.8, color=INK)
    _code(s, "T03  goal_passed   3/3\nT04  fixed_holds   3/3\nT09  consistent    3/3\nT11  pass          1/1\nT12  fail          advisory",
          0.78, 6.1, 5.4, 0.9, size=9)
    _text(s, "矩阵通过后才会进入 evaluate / release；repair agent 只能让矩阵通过，不能编辑矩阵。",
          6.5, 6.2, 6.0, 0.6, size=10, color=SLATE)
    _footer(s, 11)
    _note(s, "这是 113651 的真实矩阵。T03 三次都成功，T04 三次都保持，T09 三次一致，T11 alternate 通过，四个负例全部拒绝。"
             "唯一失败是 T12 故障分类，advisory，扣 2 分。所以它是 98 分而不是 100 分。"
             "这页也说明发布门不是“reward 看起来对”，而是每个 blocking 条件都有观测。")


def slide_repair_why(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 07 · why", "为什么把 repair 改成 agent")
    _rect(s, 0.72, 1.65, 5.75, 4.55, PALE_RED, radius=0.08)
    _text(s, "旧设计：一次性 patch + 静态预判", 0.92, 1.8, 5.3, 0.32,
          size=13, bold=True, color=RED)
    _bullets(s, [
        ("模型返回 {reason, files}，harness 静态校验后应用。", 0),
        ("不能执行 PoC、不能 build、不能查 registry、不能看容器日志。", 0),
        ("只能改已存在的 environment/ 文件；PoC 只在部分错误下可改。", 0),
        ("pinned_ref 必须字面量出现；草稿生成的 Dockerfile/依赖正则也会误报。", 0),
        ("失败时只能根据一句 prose 猜；猜测又触发更多误报。", 0),
    ], 0.92, 2.2, 5.3, 2.6, size=11.5, spacing=6)
    _text(s, "结果", 0.92, 4.95, 1.0, 0.3, size=11, bold=True, color=RED)
    _text(s, "上一轮夜间诊断：12 道 T03 PoC 打不通；5 道 build 只能猜；4 道草稿被误报；"
             "uploadfs@1.27.0 被 pinned_ref 字面量检查挡住两次。",
          0.92, 5.25, 5.3, 0.85, size=10.0, color=INK)

    _rect(s, 6.85, 1.65, 5.75, 4.55, PALE_GREEN, radius=0.08)
    _text(s, "新设计：authoring agent + 固定验收门", 7.05, 1.8, 5.3, 0.32,
          size=13, bold=True, color=GREEN)
    _bullets(s, [
        ("模型有工具：读写文件、查 registry、build、跑真实 verifier、改版本/启动命令。", 0),
        ("“出题”的完整权限：environment/**、PoC、新增文件、pinned release、fixed override。", 0),
        ("验收门固定：instruction、task.toml、verifier、T01–T12 都在写范围之外，且每次重渲染。", 0),
        ("build 和 verifier 是 ground truth；不再用静态检查预测构建结果。", 0),
        ("每一步都有 observation 和 live trace；失败原因是证据，不是 prose。", 0),
    ], 7.05, 2.2, 5.3, 2.6, size=11.5, spacing=6)
    _text(s, "原则", 7.05, 4.95, 1.0, 0.3, size=11, bold=True, color=GREEN)
    _text(s, "给作者完整权限；给判分者完全独立。agent 可以运行测试，但不能改测试。",
          7.05, 5.25, 5.3, 0.85, size=10.5, color=INK)

    _footer(s, 12)
    _note(s, "这一页是设计转折点。旧设计想用静态检查把错误挡在 build 之前，但检查器本身会误报："
             "pinned_ref 字面量、multi-stage COPY、dotted import、multipart alias。"
             "用户的原则是对的：给 repairer 完整出题权限，让固定的测试做唯一 gate。"
             "所以新 agent 能 build、能跑 verifier、能查 registry，但 verifier 和矩阵永远在它写范围之外。")


def slide_repair_how(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 07 · how", "Agent 工具循环：每次只做一个动作")
    # cycle
    _rect(s, 0.7, 1.75, 2.15, 1.0, NAVY, radius=0.08)
    _text(s, "1. 模型输出\naction JSON", 0.82, 1.88, 1.9, 0.75,
          size=10.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    _rect(s, 3.25, 1.75, 2.15, 1.0, SKY_DARK, radius=0.08)
    _text(s, "2. Harness\n执行工具", 3.37, 1.88, 1.9, 0.75,
          size=10.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    _rect(s, 5.8, 1.75, 2.15, 1.0, NAVY_2, radius=0.08)
    _text(s, "3. Observation\n日志/状态/版本", 5.92, 1.88, 1.9, 0.75,
          size=10.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    _rect(s, 8.35, 1.75, 2.15, 1.0, AMBER, radius=0.08)
    _text(s, "4. 下一轮 prompt\n带完整 transcript", 8.47, 1.88, 1.9, 0.75,
          size=10.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    for x in (2.85, 5.4, 7.95):
        _arrow(s, x, 2.12, 0.35, 0.22, "right", color=RGBColor(0x94, 0xA3, 0xB8))
    _text(s, "固定 gate（只读）", 10.85, 1.75, 1.9, 0.28, size=10, bold=True, color=RED)
    _rect(s, 10.85, 2.05, 1.8, 0.7, PALE_RED, radius=0.08)
    _text(s, "verifier / matrix\ninstruction / task.toml", 10.95, 2.18, 1.6, 0.5,
          size=8.2, color=INK, align=PP_ALIGN.CENTER)

    _text(s, "工具集", 0.72, 3.15, 2.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _table(s, [
        ["工具", "能力"],
        ["list_files / read_file", "查看当前 editable 文件"],
        ["read_bundle / read_spec", "读取完整草稿 bundle 与冻结规格"],
        ["write_file / write_files", "改 environment/**、PoC、新增文件"],
        ["set_version", "改 vulnerable/fixed pinned release"],
        ["set_start_command", "改 target 启动命令"],
        ["set_fixed_override", "写 fixed variant 专属文件"],
        ["registry", "查 PyPI/npm/Go/Maven 真实版本"],
        ["build", "build 两个 variant + preflight，返回日志"],
        ["run_verifier / submit", "跑真实 T03+T04；通过才 finalize"],
    ], 0.72, 3.45, 6.4, 2.9, col_widths=[2.5, 3.9], font_size=8.2)

    _text(s, "预算与审计", 7.45, 3.15, 2.5, 0.28, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("40 steps / 6 verifier runs / 4 builds", 0),
        ("成功的 verifier 结果按 state digest 缓存", 0),
        ("重复 read_bundle / registry 失败有短路", 0),
        ("no-op 写、重复 override 直接提示", 0),
        ("每步写 repair-trace.jsonl", 0),
        ("最终只应用 verified state；未验证 patch 不落盘", 0),
    ], 7.45, 3.45, 5.2, 2.6, size=10, spacing=5)
    _code(s, "state = { spec, bundle, files }\n"
             "submit -> tools.debug(state)\n"
             "if pair_passed: persist spec/bundle/files",
          7.45, 5.95, 5.2, 0.85, size=8.8)
    _footer(s, 13)
    _note(s, "Agent 的协议很简单：每次只返回一个 action，harness 执行后把真实 observation 放回 transcript。"
             "工具覆盖了作者需要的全部动作：读、写、改版本、改启动命令、查 registry、build、跑 verifier。"
             "重要的安全点是：成功才落盘。未验证的 patch 不会进入下一轮矩阵；这样 agent 不能靠“改到看起来对”通过。"
             "每一步都写 repair-trace.jsonl，长跑过程可观察。")


def slide_case_study(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 07 · case", "CVE-2026-113651：两次空 repair → RELEASED 98.0")
    _rect(s, 0.72, 1.65, 5.55, 3.55, PALE_RED, radius=0.08)
    _text(s, "旧 repair（失败）", 0.92, 1.8, 4.5, 0.3, size=13, bold=True, color=RED)
    _bullets(s, [
        ("repair 1：空 patch", 0),
        ("repair 2：空 patch", 0),
        ("原因：package.json 写的是 \"uploadfs\": \"1.27.0\"，但 pinned_ref 检查要求字面量 \"uploadfs@1.27.0\" 出现在文件里。", 0),
        ("模型没有工具，无法看到 npm 真实错误，也无法运行 PoC。", 0),
    ], 0.92, 2.18, 5.1, 2.2, size=11, spacing=6)
    _text(s, "结论", 0.92, 4.32, 1.0, 0.28, size=10.5, bold=True, color=RED)
    _text(s, "不是模型不会修，是旧接口让它看不到、也不能改。", 0.92, 4.62, 5.1, 0.45,
          size=10.5, color=INK)

    _rect(s, 6.65, 1.65, 5.95, 3.55, PALE_GREEN, radius=0.08)
    _text(s, "新 repair agent（成功）", 6.85, 1.8, 5.2, 0.3, size=13, bold=True, color=GREEN)
    _bullets(s, [
        ("read package.json → registry → set_version 1.27.0", 0),
        ("build 失败：npm EINVALIDTAGNAME \"uploadfs@1.27.0\"", 0),
        ("read_bundle：root_cause 指向 uploadfs streamOut", 0),
        ("重写 server.js：getStream → streamOut", 0),
        ("run_verifier：500 → 404 → goal_passed", 0),
        ("submit → 矩阵 3/3 + 3/3 → RELEASED", 0),
    ], 6.85, 2.18, 5.45, 2.2, size=11, spacing=6)
    _text(s, "最终", 6.85, 4.32, 1.0, 0.28, size=10.5, bold=True, color=GREEN)
    _text(s, "quality 98.0；uploadfs 1.27.0 → 1.28.0；fix commit f84fd41c", 6.85, 4.62, 5.45, 0.45,
          size=10.5, color=INK)

    _code(s, "npm error code EINVALIDTAGNAME\n"
             "npm error Invalid tag name \"uploadfs@1.27.0\"\n"
             "...\n"
             "PAIR PASSED: vulnerable reached the secret and the fixed build holds.",
          0.78, 5.55, 11.8, 0.75, size=9)
    _text(s, "审计：repair-trace.jsonl 27 步 · repair-log 4 条 · matrix T03/T04 各 3 条 · release/audit.zip",
          0.78, 6.55, 11.8, 0.28, size=9, color=SLATE)
    _footer(s, 14)
    _note(s, "这是最有说服力的案例。旧设计两次 repair 都是空 patch，不是模型不会修，而是 pinned_ref 字面量检查把合法修复挡掉了。"
             "新 agent 先读 package.json、查 registry、改版本；build 报出 npm 非法 tag；读 bundle 发现应该走 streamOut；"
             "重写 server.js；verifier 从 500 到 404 到 goal_passed；最后矩阵通过，RELEASED 98.0。"
             "这就是“给工具”和“给完整权限”的直接价值。")


def slide_evaluate(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Step 08", "评估与发布：五维分 + 硬条件")
    _text(s, "质量分", 0.72, 1.62, 2.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _code(s, "F = 20V + 15P + 25M + 30D + 10I\n"
             "threshold = 90.0   grade = A", 0.72, 1.92, 4.55, 0.85, size=11)
    _table(s, [
        ["维度", "权重", "检查"],
        ["D Differential", "30", "health / T03 / T04 / 负例 / alternate"],
        ["M Meaningfulness", "25", "fix source / 根因引用 / trigger 观测"],
        ["V Validity", "20", "artifact identity / 版本对 / 来源 / build lock"],
        ["P Preconditions", "15", "前提完整 / 未认证 / 可达 / 控制项"],
        ["I Integrity", "10", "目标一致 / 策略干净 / infra 率 / 故障分类 / 网络"],
    ], 5.55, 1.62, 6.95, 2.15,
        col_widths=[2.15, 0.8, 4.0], font_size=8.8)
    _text(s, "硬条件（任一失败即不可发布）", 0.72, 4.15, 4.0, 0.28, size=11, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("grade A；无 unknown assertion", 0),
        ("T01/T02 健康；T03 3/3；fixed 0 泄漏", 0),
        ("T05/T06/T07/T10 负例全过", 0),
        ("infra error rate ≤ 0.2", 0),
        ("min_valid_trials = 3；quality ≥ 90", 0),
    ], 0.72, 4.45, 4.6, 1.8, size=10, spacing=3)
    _text(s, "发布包", 5.55, 4.05, 2.0, 0.28, size=11, bold=True, color=SKY_DARK)
    _code(s, """release/
├── task/                 # 可移植任务
├── spec.json
├── evaluation.json
├── matrix.json
├── build-manifest.json
├── evidence-index.json
├── audit.zip
└── README.md""", 5.55, 4.35, 3.5, 2.05, size=8.2)
    _text(s, "数据集清单", 9.35, 4.05, 2.0, 0.28, size=11, bold=True, color=SKY_DARK)
    _text(s, "dataset-manifest.json 记录 cve_id、project、patch_group、root_cause_group、"
             "split、artifact_digest、location。\n\n"
             "当前 4 条（116673 / 12171 / 23968 / 25527）；113651 / 106103 将在批次报告合并时写入。",
          9.35, 4.35, 3.2, 1.9, size=9.2, color=INK)
    _text(s, "已发布 6 道：5 道 98.0（D/P/M/V=1.0，I=0.8）；106103 93.0（D=0.833，T11 alternate 未过）。共同失分是 I4。",
          0.72, 6.55, 11.8, 0.3, size=9.5, color=SLATE)
    _footer(s, 15)
    _note(s, "评估不是单一分数，而是五个维度加权。D 是差分，权重最高 30；M 是根因证据 25；V 是版本/制品 20；P 是前提 15；I 是完整性 10。"
             "硬条件是发布门：grade A、T03 3/3、fixed 0 泄漏、四个负例全过、infra 率、最少 3 个有效 trial、90 分。"
             "当前 6 道：5 道 98.0，Quasar 106103 93.0（T11 alternate 未通过，D6 失分）；共同失分是 I4 故障分类。")


def slide_outputs(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Outputs", "当前产出与运行指标（快照）")
    _table(s, [
        ["状态", "数量", "说明"],
        ["RELEASED", "6", "5 道 98.0 + 106103 93.0"],
        ["QUARANTINED", "14", "4 build_error + 10 validation_error"],
        ["UNSUPPORTED", "4", "113664 / 23877 / 23889 / 26972"],
        ["EVIDENCE_READY", "4", "generation_error 已重置，等待重新生成草稿"],
        ["REPAIRING", "4", "112946 / 27606 / 27699 / 112310"],
    ], 0.72, 1.62, 5.75, 2.95,
        col_widths=[1.55, 0.75, 3.45], font_size=9.2)
    _text(s, "已发布题目", 6.75, 1.62, 3.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _table(s, [
        ["CVE", "项目", "分"],
        ["116673", "systeminformation", "98.0"],
        ["12171", "auto-changelog", "98.0"],
        ["23968", "copier", "98.0"],
        ["25527", "changedetection.io", "98.0"],
        ["113651", "uploadfs", "98.0"],
        ["106103", "@quasar/icongenie", "93.0"],
    ], 6.75, 1.92, 3.3, 2.3,
        col_widths=[1.5, 1.5, 0.6], font_size=8.4)
    _rect(s, 10.35, 1.62, 2.25, 2.95, PALE_BLUE, radius=0.08)
    _text(s, "批次规模", 10.52, 1.78, 1.9, 0.28, size=10.5, bold=True, color=SKY_DARK)
    _text(s, "计划 50\n已处理 32\n剩余 18", 10.52, 2.1, 1.9, 1.0,
          size=15, bold=True, color=NAVY)
    _text(s, "输入 229\n其中本批取\n前 50（priority ≤ 11）", 10.52, 3.3, 1.9, 1.0,
          size=8.5, color=SLATE)
    _text(s, "运行与耗时", 0.72, 4.75, 3.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _table(s, [
        ["指标", "观测"],
        ["并发", "1×1；repair debug 内部串行"],
        ["Docker VM", "8GB（MemTotal 8.32GB）"],
        ["vmmemWSL", "6.08GB / 8GB"],
        ["宿主空闲", "10.79GB / 31.8GB"],
        ["干净候选", "10–20 min"],
        ["一次 repair", "30–50 min"],
        ["硬候选", "60–120+ min"],
    ], 0.72, 5.05, 5.6, 1.7,
        col_widths=[1.7, 3.9], font_size=8.5)
    _rect(s, 6.75, 4.75, 5.85, 2.0, PALE_AMBER, radius=0.08)
    _text(s, "本批次的真实样本", 6.95, 4.9, 5.4, 0.28, size=10.5, bold=True, color=AMBER)
    _text(s, "113651：~40 min（4 次 repair + 矩阵）→ RELEASED 98.0\n"
             "106103：~70 min（三次 repair）→ RELEASED 93.0\n"
             "112005：~5 min（一次 build 失败确认）→ QUARANTINED\n"
             "112310：~28 min+（两次 repair，4 次 verifier）→ 重试中",
          6.95, 5.22, 5.45, 1.35, size=9, color=INK)
    _footer(s, 16)
    _note(s, "这是 12:25 的快照。6 道发布（5 道 98.0 + Quasar 106103 93.0），14 道隔离（4 build + 10 validation），"
             "4 道 unsupported，4 道 generation_error 已重置等待重新生成草稿，4 道 repairing。"
             "运行侧：1×1，8GB VM，vmmem 6.08GB，宿主还有 10.8GB；干净候选 10–20 分钟，一次 repair 30–50 分钟，硬候选 60–120 分钟。")


def slide_defects(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Iteration log", "本轮发现并修复的缺陷")
    _table(s, [
        ["缺陷", "症状", "修复", "状态"],
        ["pinned_ref 字面量误报", "113651 两次空 repair", "删除字面量 guard；版本由 set_version + 矩阵验证", "done"],
        ["variant ref 泄漏", "repair 改版本文件同时钉死 fixed", "{{REF}} 按 variant 替换；fixed_overrides 后置", "done"],
        ["多阶段 COPY 误报", "26329 合法 Dockerfile 被拒", "跳过带 --from= 的 COPY/ADD", "done"],
        ["dotted distribution 误报", "23949 的 jaraco.context", "前缀/别名匹配 jaraco-context", "done"],
        ["multipart 别名", "27483 的 python-multipart", "增加 multipart → python-multipart 映射", "done"],
        ["stray target file / 缺 PoC", "23888 的 docs/index.html + 无 poc", "归一化到 target.files；focused PoC 补全", "done"],
        ["repair 无工具", "只能猜 build 日志", "40-step agent 工具循环 + preflight 日志", "done"],
        ["registry 瞬时失败", "npm SSL EOF 重复重试", "成功缓存；失败最多 3 次；Go module path 提示", "done"],
        ["Docker OOM", "批次被宿主 kill；task__* 残留", "8GB VM、1×1、prune、killpg、网络清理", "done"],
    ], 0.62, 1.55, 12.0, 5.0,
        col_widths=[2.6, 3.4, 4.6, 1.0], font_size=8.4)
    _text(s, "全量测试通过；所有修复都有对应单元测试或真实 candidate 复跑。", 0.72, 6.68, 11.8, 0.28,
          size=10, color=SLATE)
    _footer(s, 17)
    _note(s, "这一页把本轮修的东西集中起来。核心不是某一个 bug，而是旧设计的模式：用静态检查预测 build，"
             "用字面量字符串判断版本，用“只能改已有文件”限制作者。每一条都对应一个真实失败和一次代码修复。"
             "Docker OOM 是另一条线：8GB VM、1×1、prune、killpg 清理，保证宿主不再被拖死。")


def slide_scale(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Scale-up", "10k 放大：漏斗、并发、存储")
    _text(s, "输入漏斗（实测 / 计划）", 0.72, 1.6, 4.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _table(s, [
        ["阶段", "数量"],
        ["NVD 2026 feed", "83,505"],
        ["预筛候选", "13,687"],
        ["300 样本 triage eligible", "257"],
        ["重跑 triage eligible", "237"],
        ["两版 registry 身份齐全", "85"],
        ["最终 RELEASED", "待本批校准"],
    ], 0.72, 1.9, 4.0, 2.7,
        col_widths=[2.9, 1.1], font_size=9)
    _text(s, "并发模型", 5.1, 1.6, 3.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("峰值 trial = workers × trial_workers", 0),
        ("峰值容器 ≈ 2× trial + verifier", 0),
        ("8GB VM：当前 1×1；2×1 需实测", 0),
        ("Linux 生产：扩大 Docker address pool", 0),
        ("4 shards：每 shard 3,422 候选（plan-only 实测）", 0),
        ("16 workers：6–15 天；32：3–8 天（计划估算）", 0),
    ], 5.1, 1.9, 3.7, 2.7, size=9.5, spacing=4)
    _text(s, "存储与配额", 9.1, 1.6, 3.0, 0.28, size=12, bold=True, color=SKY_DARK)
    _bullets(s, [
        ("发布包 20–50MB/题 → 200–500GB", 0),
        ("候选镜像 1–2GB；终态 prune", 0),
        ("构建缓存 1–3GB/并发候选", 0),
        ("GitHub token 5,000/h；NVD feed cache", 0),
        ("账本/运行目录放本地文件系统", 0),
    ], 9.1, 1.9, 3.7, 2.7, size=9.5, spacing=4)
    _rect(s, 0.72, 5.05, 11.95, 1.35, PALE_BLUE, radius=0.08)
    _text(s, "放大前必须先测三件事", 0.92, 5.2, 3.5, 0.28, size=11, bold=True, color=SKY_DARK)
    _text(s, "1) 20–50 个候选的端到端 qualification，记录 RELEASED/eligible 与单位成本；\n"
             "2) 2×1 在 8GB 或 12GB VM 下的峰值内存；\n"
             "3) 各生态（PyPI/npm/Go/Maven）的产出率，不要把 npm/PyPI 外推到 Go。",
          0.92, 5.5, 11.4, 0.8, size=9.5, color=INK)
    _footer(s, 18)
    _note(s, "10k 不是 10k 个输入直接出题，而是一个漏斗：83,505 条 NVD → 13,687 预筛 → 237 eligible → 85 有 registry 身份；"
             "最终 RELEASED 还要经过草稿生成、构建、矩阵和修复。"
             "并发峰值是 workers × trial_workers；8GB 下 1×1 稳定，2×1 要先实测。Linux 生产要扩大 Docker address pool。"
             "存储按 20–50MB/题估算 200–500GB；镜像必须 prune。放大前先做 20–50 个候选的 qualification 校准。")


def slide_risks(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, WHITE, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Risks & next", "风险、决策点与下一步")
    _text(s, "主要风险", 0.72, 1.62, 2.0, 0.28, size=12, bold=True, color=RED)
    _bullets(s, [
        ("硬候选长尾：Go / Maven / generic 的产出率可能显著低于 PyPI/npm。", 0),
        ("Repair 延迟：40 步 × 15–25s/步；硬候选单题 30–120 分钟。", 0),
        ("Docker 内存：2×1 未在 8GB 下验证；build 峰值是主要风险。", 0),
        ("Registry 瞬时失败：npm SSL EOF；已加缓存/重试，仍需监控。", 0),
        ("T12 / I4 故障分类缺口：发布题 98/93 而不是 100（106103 另有 T11 alternate 未过）。", 0),
        ("Dataset manifest 当前只含 4 条；113651 / 106103 待批次报告合并。", 0),
    ], 0.72, 1.95, 6.0, 3.1, size=10.5, spacing=5)
    _text(s, "建议决策", 7.0, 1.62, 2.5, 0.28, size=12, bold=True, color=GREEN)
    _bullets(s, [
        ("本批继续 1×1，先拿到完整产出率。", 0),
        ("硬候选保留 max_repairs=4；默认配置仍为 2。", 0),
        ("Quasar 已通过专项；Go / Docling 做第二轮专项，不阻塞批次。", 0),
        ("批次结束写 batch-report + dataset manifest，合并 113651 / 106103。", 0),
        ("放大前用 2×1 做 2–3 题内存实测。", 0),
        ("先跑 20–50 题 qualification 校准，再开 8 shards。", 0),
    ], 7.0, 1.95, 5.8, 3.1, size=10.5, spacing=5)
    _rect(s, 0.72, 5.35, 11.95, 1.2, PALE_GREEN, radius=0.08)
    _text(s, "一句话结论", 0.92, 5.5, 2.5, 0.28, size=11, bold=True, color=GREEN)
    _text(s, "框架已经能把真实 CVE 自动变成可发布 Harbor 任务；repair agent 改造解决了“看不到、只能猜、被误杀”的核心问题；"
             "下一步是用产出率和单位成本校准 10k 排期。",
          0.92, 5.8, 11.4, 0.6, size=10.5, color=INK)
    _footer(s, 19)
    _note(s, "风险要诚实：硬候选仍然会失败；repair 慢；2×1 没在 8GB 下验证；registry 会抖；T12/I4 有 2 分缺口，Quasar 另有 T11 未过；"
             "manifest 还没合并 113651 / 106103。建议本批保持 1×1 拿完整产出率，Go/Docling 做第二轮专项，"
             "批次结束写报告和 manifest，放大前做 2×1 内存实测和 20–50 题校准。")


def slide_appendix(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _rect(s, 0, 0, W, H, NAVY, shape=MSO_SHAPE.RECTANGLE)
    _title(s, "Appendix", "命令、产物与术语", dark=True)
    _text(s, "常用命令", 0.78, 1.62, 2.5, 0.28, size=11, bold=True, color=RGBColor(0x7D, 0xD3, 0xFC))
    _code(s, "python -m harbor_pipeline doctor\n"
             "python -m harbor_pipeline run --cve CVE-2026-113651 \\\n"
             "  --run-id scale-20261104-r2 --profile qualification\n"
             "python -m harbor_pipeline batch --input candidates/... \\\n"
             "  --run-id ... --profile qualification --workers 1 \\\n"
             "  --trial-workers 1 --prune-images\n"
             "python -m harbor_pipeline resume --run-id ...\n"
             "python -m harbor_pipeline report --run-id ...",
          0.78, 1.95, 6.2, 2.45, size=8.2)
    _text(s, "运行产物", 7.4, 1.62, 2.5, 0.28, size=11, bold=True, color=RGBColor(0x7D, 0xD3, 0xFC))
    _code(s, "runs/<run-id>/<CVE>/\n"
             "├── state.json / budget.json\n"
             "├── evidence/ + evidence-index.json\n"
             "├── cve-spec.json\n"
             "├── synthesis.json + synthesis-notes.json\n"
             "├── task/ + task-manifest.json\n"
             "├── image-set.json + build-logs/\n"
             "├── matrix.json + trials/\n"
             "├── evaluation.json\n"
             "├── repair-log.json + repair-trace.jsonl\n"
             "└── release/ (task, spec, matrix, audit.zip)",
          7.4, 1.95, 5.0, 2.45, size=8.2)
    _text(s, "术语", 0.78, 4.72, 2.0, 0.28, size=11, bold=True, color=RGBColor(0x7D, 0xD3, 0xFC))
    _bullets(s, [
        ("RELEASED：通过 qualification，可入数据集。", 0),
        ("QUARANTINED：证据齐全但构建/差分/负例失败。", 0),
        ("UNSUPPORTED：公开证据不足以形成可验证任务。", 0),
        ("T01–T12：差分矩阵；blocking 失败即停。", 0),
        ("{{REF}}：target 文件里的 variant 版本开关。", 0),
        ("prebuilt：每个 revision 的 6 个镜像。", 0),
        ("grade A：所有事实断言已确认、修复 commit 可抓取。", 0),
    ], 0.78, 5.05, 6.2, 1.75, size=9, spacing=2,
       color=RGBColor(0xE2, 0xE8, 0xF0))
    _text(s, "数据快照：2026-11-04 12:25（本地） · 批次仍在运行", 7.4, 6.6, 5.0, 0.28,
          size=9, color=RGBColor(0x94, 0xA3, 0xB8))
    _note(s, "附录给复现用：所有阶段都可以用 CLI 单独跑，也可以用 run 端到端跑；batch 支持 resume 和 shard。"
             "产物目录里 state.json 是状态机，budget.json 是共享账本，repair-trace.jsonl 是 agent 的逐步审计。"
             "术语表用于对齐 T01–T12、RELEASED/QUARANTINED/UNSUPPORTED 和 {{REF}}。")


def main():
    prs = new_deck()
    slide_cover(prs)
    slide_summary(prs)
    slide_scope(prs)
    slide_architecture(prs)
    slide_collect(prs)
    slide_freeze(prs)
    slide_draft(prs)
    slide_generate(prs)
    slide_build(prs)
    slide_matrix(prs)
    slide_matrix_case(prs)
    slide_repair_why(prs)
    slide_repair_how(prs)
    slide_case_study(prs)
    slide_evaluate(prs)
    slide_outputs(prs)
    slide_defects(prs)
    slide_scale(prs)
    slide_risks(prs)
    slide_appendix(prs)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(f"wrote {OUT} ({len(prs.slides)} slides)")


if __name__ == "__main__":
    main()
