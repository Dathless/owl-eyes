"""Data-driven A4 assessment report; every supplied string stays literal text."""

import json
from datetime import UTC, datetime
from html import escape
from io import BytesIO
from pathlib import Path
from threading import Lock

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

from app.schemas import ScanRecord

FONT_LOCK = Lock()
INK = colors.HexColor("#172a46")
BLUE = colors.HexColor("#2455a4")
MUTED = colors.HexColor("#536278")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
LABELS = dict(
    zip(
        SEVERITIES,
        ("Nghiêm trọng", "Cao", "Trung bình", "Thấp", "Thông tin", "Chưa xác định"),
        strict=True,
    )
)
METHODS = {
    "nuclei": (
        "Bốn template HTTP GET đã duyệt; xem coverage về phiên đăng nhập, "
        "severity critical/high/medium/low; không redirect hoặc OAST."
    ),
    "httpx": ("HTTPX Toolkit: status, tiêu đề và dấu vết công nghệ tại URL HTTP."),
    "wafw00f": "Nhận diện WAF tại URL DVWA; fingerprint không xác nhận lỗ hổng.",
    "gobuster": (
        "Tám đường dẫn cố định, một luồng; kiểm tra wildcard, không recursion/redirect."
    ),
    "wapiti": (
        "Chỉ kiểm tra header, cờ cookie và CSP thụ động tại URL DVWA, không crawl."
    ),
    "nmap": (
        "Nhận diện dịch vụ TCP/80 trên IP được cấu hình; banner không tự "
        "xác nhận lỗ hổng."
    ),
    "curl": "Đọc HTTP status/header của DVWA; không đi theo redirect.",
    "whatweb": ("Nhận diện dấu vết công nghệ HTTP; không xác minh phiên bản đã cài."),
    "ffuf": (
        "Kiểm tra tám đường dẫn DVWA cố định; không recursion, không theo redirect."
    ),
    "nikto": (
        "Baseline web có giới hạn; xác minh phiên DVWA trước scan khi được"
        " ghi nhận. Có thể quan sát origin/đường dẫn ngoài DVWA."
    ),
}
SCOPES = {
    "dvwa_path": "DVWA /dvwa",
    "http_origin": "HTTP origin",
    "host_service": "Dịch vụ trên host",
    "other_path": "Ngoài /dvwa",
    "unknown": "Chưa xác định",
}


def timestamp(value):
    return (
        value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        if value
        else "Chưa ghi nhận"
    )


def render_report_pdf(scan: ScanRecord) -> bytes:
    """Render one copied saved report, including all findings and cited evidence."""
    if scan.report is None:
        raise ValueError("A validated report is required")
    with FONT_LOCK:
        if "PCSans" not in pdfmetrics.getRegisteredFontNames():
            root = Path(__file__).resolve().parents[1] / "static" / "fonts"
            pdfmetrics.registerFont(TTFont("PCSans", str(root / "DejaVuSans.ttf")))
            pdfmetrics.registerFont(
                TTFont("PCSans-Bold", str(root / "DejaVuSans-Bold.ttf"))
            )
    body = ParagraphStyle(
        "PCBody",
        fontName="PCSans",
        fontSize=9.5,
        leading=15,
        textColor=INK,
        spaceAfter=8,
        splitLongWords=True,
    )
    small = ParagraphStyle(
        "PCSmall", parent=body, fontSize=8, leading=12, textColor=MUTED
    )
    heading = ParagraphStyle(
        "PCHeading",
        parent=body,
        fontName="PCSans-Bold",
        fontSize=15,
        leading=21,
        spaceBefore=20,
        spaceAfter=11,
        keepWithNext=True,
    )
    subheading = ParagraphStyle(
        "PCSubheading", parent=heading, fontSize=11, leading=17, spaceBefore=13
    )
    title = ParagraphStyle(
        "PCTitle",
        parent=heading,
        fontSize=25,
        leading=34,
        spaceBefore=20,
        spaceAfter=16,
    )

    # Paragraph supports markup; escape every data string before it reaches the parser.
    def p(value, style=body):
        literal = "".join(c for c in str(value) if c in "\n\t" or ord(c) >= 32)
        return Paragraph(escape(literal).replace("\n", "<br/>"), style)

    story = []
    envelope = scan.report
    report = envelope.report
    stale = scan.state != "completed"
    findings = sorted(
        report.findings,
        key=lambda f: (f.scope == "other_path", SEVERITIES.index(f.severity)),
    )
    evidence = {e.id: e for tool in scan.tools.values() for e in tool.evidence}
    cited = list(dict.fromkeys(eid for f in findings for eid in f.evidence_ids))
    refs = {eid: f"E{n:03d}" for n, eid in enumerate(cited, 1)}
    width = A4[0] - 100

    def section(number, text):
        rule = HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#dce3ee"))
        rule.keepWithNext = True
        space = Spacer(1, 8)
        space.keepWithNext = True
        story.extend([p(f"{number:02d}  {text}", heading), rule, space])

    def table(headers, rows, widths):
        data = [
            [p(value, small) for value in headers],
            *[[p(value, small) for value in row] for row in rows],
        ]
        item = LongTable(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        item.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0f8")),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f7f9fc")],
                    ),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#cbd6e5")),
                ]
            )
        )
        story.append(item)

    story.extend(
        [
            p("PENCHECKER  /  SECURITY ASSESSMENT", small),
            p("BÁO CÁO ĐÁNH GIÁ\nAN NINH ỨNG DỤNG", title),
            p("Metasploitable2 / DVWA · Báo cáo kỹ thuật có dẫn chứng", body),
        ]
    )
    if stale:
        story.extend(
            [
                p("BÁO CÁO TRƯỚC", subheading),
                p(
                    "Bản hợp lệ gần nhất; lần phân tích hiện tại chưa tạo được "
                    "báo cáo"
                    " thay thế. Nội dung dưới đây thuộc revision và provider "
                    "được ghi "
                    "nhận, không phải kết quả mới."
                ),
            ]
        )
    story.extend(
        [
            p(
                f"Rủi ro tổng thể: {LABELS[report.overall_risk]} "
                f"({report.overall_risk})",
                subheading,
            )
        ]
    )
    table(
        ("Thông tin", "Giá trị"),
        [
            ("Mã scan", scan.scan_id),
            ("Target", scan.target.url),
            ("Revision / trạng thái hiện tại", f"{envelope.revision} / {scan.state}"),
            (
                "Provider / model tạo báo cáo",
                f"{envelope.provider_id} / {envelope.model}",
            ),
            ("Báo cáo được tạo", timestamp(envelope.generated_at)),
            ("PDF được xuất", timestamp(datetime.now(UTC))),
        ],
        [145, width - 145],
    )
    section(1, "TÓM TẮT ĐIỀU HÀNH")
    story.append(
        p(
            f"Phân tích ghi nhận {len(findings)} phát hiện dựa trên dữ liệu "
            f"của {len(scan.tools)} tool; đã lưu {len(evidence)} bằng chứng. "
            "Kết quả cần đối chiếu với nguồn và kiểm tra thủ công trước khi "
            "kết luận."
        )
    )
    story.append(p("Nhận định AI từ snapshot phân tích", subheading))
    story.append(
        p(
            "Các mục tiếp theo tổng hợp dữ liệu đã lưu. Phần AI có thể dựa trên "
            "snapshot thu gọn; đối chiếu kết quả thu thập và giới hạn "
            "trước khi kết luận.",
            small,
        )
    )
    story.append(p(report.summary))
    if not findings:
        story.append(
            p(
                "Chưa có phát hiện được báo cáo từ dữ liệu đã phân tích. Đây không"
                " phải xác nhận target an toàn hoặc đã được kiểm tra đầy đủ."
            )
        )
    story.append(
        p(
            (
                "Báo cáo do AI hỗ trợ, chưa phải kết luận kiểm định độc lập. Mức "
                "độ rủi ro và nhận định phải được người đánh giá xác minh."
            ),
            small,
        )
    )
    story.append(PageBreak())
    section(2, "PHẠM VI VÀ PHƯƠNG PHÁP")
    finishes = [t.finished_at for t in scan.tools.values() if t.finished_at]
    terminal = all(t.state not in {"queued", "running"} for t in scan.tools.values())
    collection = (
        f"{max(0, (max(finishes) - scan.created_at).total_seconds()):.1f}s"
        if finishes and terminal and len(finishes) == len(scan.tools)
        else "Chưa xác định"
    )
    table(
        ("Phạm vi", "Giá trị"),
        [
            ("Target / IP", f"{scan.target.url}\n{scan.target.ip}"),
            (
                "Bắt đầu / kết thúc operation",
                f"{timestamp(scan.created_at)}\n{timestamp(scan.finished_at)}",
            ),
            ("Thời gian thu thập", collection),
            (
                "Auth / security metadata",
                f"{scan.target.auth_mode} / {scan.target.security_level}",
            ),
        ],
        [145, width - 145],
    )
    story.append(
        p(
            "Auth/security metadata không chứng minh mọi module DVWA đã được "
            "kiểm tra. Scan mới yêu cầu phiên DVWA cho mọi tool web, trừ Nmap. "
            "Báo cáo đã lưu chỉ xác nhận đăng nhập/security khi có warning tương "
            "ứng; phiên có thể thay đổi hoặc hết hạn trong scan."
        )
    )
    for tool in scan.tools.values():
        story.append(
            p(
                str(tool.tool_id)
                + ": "
                + METHODS.get(
                    tool.tool_id, "Theo preset và phạm vi do server cấu hình."
                )
            )
        )
    section(3, "KẾT QUẢ THU THẬP VÀ MỨC ĐỘ")
    table(
        ("Tool", "State / parse", "Thời gian", "Quan sát / bằng chứng"),
        [
            (
                t.tool_id,
                f"{t.state}\n{t.parse_status}",
                f"{t.duration_ms / 1000:.1f}s",
                f"{len(t.observations)} / {len(t.evidence)}",
            )
            for t in scan.tools.values()
        ],
        [65, 135, 80, width - 280],
    )
    table(
        ("Mức độ", "Số phát hiện"),
        [(LABELS[s], str(sum(f.severity == s for f in findings))) for s in SEVERITIES],
        [width - 100, 100],
    )
    story.append(
        p(
            (
                "Rủi ro chưa xác định không có nghĩa là rủi ro thấp. Mức độ dưới "
                "đây phản ánh báo cáo AI đã lưu, không phải xác nhận khai thác "
                "thành công."
            ),
            small,
        )
    )
    section(4, "PHÁT HIỆN CHI TIẾT")
    if not findings:
        story.append(
            p(
                "Không có phát hiện trong báo cáo hợp lệ này. Xem quan sát kỹ "
                "thuật và giới hạn để hiểu phạm vi dữ liệu."
            )
        )
    for n, finding in enumerate(findings, 1):
        story.append(p(f"F{n:02d} · {finding.title}", subheading))
        story.append(
            p(
                f"{LABELS[finding.severity]} ({finding.severity}) · "
                f"{SCOPES[finding.scope]} · {finding.assessment}\nID: {finding.id}",
                small,
            )
        )
        if finding.scope == "other_path":
            story.append(p("Phát hiện ngoài /dvwa: không tự quy kết là lỗ hổng DVWA."))
        for label, value in [
            ("Mô tả", finding.description),
            ("Ảnh hưởng", finding.impact),
            ("Khuyến nghị khắc phục", finding.recommendation),
        ]:
            story.extend(
                [p(label, subheading), p(value or "Chưa có nội dung được ghi nhận.")]
            )
        story.append(
            p(
                "Bằng chứng: " + ", ".join(refs[eid] for eid in finding.evidence_ids),
                small,
            )
        )
    section(5, "KẾ HOẠCH KHẮC PHỤC")
    story.append(
        p(
            "Ưu tiên trình bày theo mức độ của báo cáo; xác minh tính áp dụng "
            "và ảnh hưởng vận hành trước khi thay đổi cấu hình. Không tự thực "
            "thi khuyến nghị."
        )
    )
    if not findings:
        story.append(
            p(
                "Chưa có khuyến nghị gắn với phát hiện. Bổ sung bằng chứng ở các "
                "phạm vi còn thiếu trước khi đưa ra kế hoạch xử lý lỗ hổng."
            )
        )
    for n, finding in enumerate(findings, 1):
        story.extend(
            [
                p(
                    f"F{n:02d} · {LABELS[finding.severity]} · {finding.title}",
                    subheading,
                ),
                p(finding.recommendation or "Chưa có khuyến nghị trong báo cáo."),
            ]
        )
    section(6, "QUAN SÁT KỸ THUẬT")
    story.append(
        p(
            "Cổng mở, header và fingerprint là quan sát; chúng không tự xác "
            "nhận lỗ hổng hoặc phiên bản đã cài. Phần này bao gồm dữ liệu đã "
            "thu thập, kể cả khi không có finding."
        )
    )
    for tool in scan.tools.values():
        story.append(p(str(tool.tool_id), subheading))
        if not tool.observations:
            story.append(p("Không có quan sát đã chuẩn hóa cho tool này."))
        for observation in tool.observations:
            story.append(
                p(
                    f"{observation.subject} · {SCOPES[observation.scope]} · "
                    f"{observation.kind}",
                    small,
                )
            )
            story.append(
                p(json.dumps(observation.value, ensure_ascii=False, sort_keys=True))
            )
            story.append(
                p("Evidence IDs: " + ", ".join(observation.evidence_ids), small)
            )
    section(7, "GIỚI HẠN VÀ MỨC ĐỘ BAO PHỦ")
    limits = [*report.limitations, *scan.warnings]
    for tool in scan.tools.values():
        limits.extend(f"{tool.tool_id}: {w}" for w in tool.warnings)
        if tool.error:
            limits.append(f"{tool.tool_id}: {tool.error.code} — {tool.error.message}")
    if scan.partial:
        limits.insert(
            0,
            (
                "Dữ liệu có giới hạn (partial): một số kết quả hoặc evidence có "
                "thể chưa đầy đủ."
            ),
        )
    for item in dict.fromkeys(limits):
        story.append(p("• " + item))
    story.append(
        p(
            "Không xác nhận an toàn từ scan rỗng hoặc tool thành công. AI chỉ "
            "thấy snapshot có giới hạn; phát hiện và mọi nhận định cần được "
            "đối chiếu thủ công. Raw output được giữ trong ứng dụng, không "
            "đính kèm toàn bộ vào PDF."
        )
    )
    section(8, "PHỤ LỤC BẰNG CHỨNG")
    if not cited:
        story.append(
            p(
                "Không có bằng chứng được trích dẫn bởi finding. Xem quan sát kỹ "
                "thuật và dữ liệu gốc trong ứng dụng."
            )
        )
    for eid in cited:
        story.append(p(f"{refs[eid]} · {eid}", subheading))
        item = evidence.get(eid)
        if item is None:
            story.append(
                p(
                    "Bằng chứng không còn trong snapshot; không thể xác minh "
                    "trích dẫn"
                    " này."
                )
            )
            continue
        story.extend(
            [
                p(f"{item.tool_id} · {item.source} · {item.locator}", small),
                p(item.excerpt or "Excerpt trống."),
            ]
        )

    if scan.cve_lookup is not None:
        section(9, "ĐỐI CHIẾU CVE TỪ BẰNG CHỨNG")
        lookup = scan.cve_lookup
        story.append(
            p(
                "Ứng viên CVE từ dữ liệu nguồn bên ngoài; chưa xác nhận target "
                "có lỗ hổng. Điểm CVSS thuộc bản ghi nguồn. Banner không xác minh "
                "bản vá hoặc điều kiện khai thác."
            )
        )
        story.append(
            p(f"Trạng thái: {lookup.state} · Tra cứu: {timestamp(lookup.checked_at)}")
        )
        if not lookup.matches:
            story.append(
                p("Chưa có ứng viên CVE; không chứng minh target không có lỗ hổng.")
            )
        for warning in lookup.warnings:
            story.append(p(warning, small))
        for item in lookup.matches:
            story.append(p(f"{item.cve_id} · {item.title}", subheading))
            story.append(p(item.description))
            story.append(
                p(
                    f"Nguồn: {item.source_url} · "
                    f"Lấy dữ liệu: {timestamp(item.retrieved_at)}",
                    small,
                )
            )
            story.append(
                p(
                    f"Công bố: {item.published or '—'} · "
                    f"Cập nhật: {item.modified or '—'}",
                    small,
                )
            )
            for score in item.scores:
                story.append(
                    p(
                        f"CVSS {score.version}: {score.score} · "
                        f"{score.vector} · {score.source}"
                    )
                )
            story.append(p("CWE: " + (", ".join(item.weaknesses) or "Chưa có dữ liệu")))
            for reason in item.reasons:
                story.append(
                    p(f"Cơ sở: {reason.basis} · {reason.detail} · {reason.scope}")
                )
                for eid in reason.evidence_ids:
                    evidence_item = evidence.get(eid)
                    story.append(
                        p(
                            f"Evidence {eid}: "
                            + (
                                evidence_item.excerpt
                                if evidence_item
                                else "Không còn trong snapshot"
                            ),
                            small,
                        )
                    )
            for criteria in item.affected:
                story.append(
                    p("Điều kiện CPE nguồn (chưa đánh giá độc lập): " + criteria, small)
                )
            for reference in item.references:
                story.append(p(reference, small))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("PCSans", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(50, A4[1] - 32, "PenChecker / DVWA assessment")
        canvas.drawRightString(
            A4[0] - 50,
            A4[1] - 32,
            f"Revision {envelope.revision}" + (" / BÁO CÁO TRƯỚC" if stale else ""),
        )
        canvas.drawString(50, 30, scan.scan_id)
        canvas.drawRightString(A4[0] - 50, 30, f"Trang {doc.page}")
        canvas.restoreState()

    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=50,
        rightMargin=50,
        topMargin=53,
        bottomMargin=50,
        title=f"PenChecker — DVWA — {scan.scan_id}",
        author="PenChecker",
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
