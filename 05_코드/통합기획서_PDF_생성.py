from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, KeepTogether, HRFlowable, Image as RLImage
)
from reportlab.pdfgen.canvas import Canvas

ROOT = Path(r"C:\Users\ENCO\Documents\mission1\security_project")
PLAN = ROOT / "01_프로젝트기획" / "이메일_외부유출_프로젝트_통합기획서_본문.md"
DICT = ROOT / "02_자료조사" / "보안로그_CSV_데이터사전_20260916_v02.md"
OUT = ROOT / "06_산출물" / "이메일_외부유출_통합기획서_부록포함.pdf"
FLOW_IMAGE = Path(r"C:\Users\ENCO\AppData\Local\Temp\codex-clipboard-5ad76f2f-9da1-4ef6-bcae-e5d5c3a44397.png")
RANKING_IMAGE = Path(r"C:\Users\ENCO\Downloads\ChatGPT Image 2026년 9월 15일 오후 05_18_47 (1).png")
PROFILE_IMAGE = Path(r"C:\Users\ENCO\Downloads\ChatGPT Image 2026년 9월 15일 오후 05_18_48 (2).png")
OUT.parent.mkdir(parents=True, exist_ok=True)

FONT = r"C:\Windows\Fonts\NotoSansKR-VF.ttf"
pdfmetrics.registerFont(TTFont("NotoKR", FONT))
pdfmetrics.registerFont(TTFont("NotoKR-Bold", FONT, subfontIndex=0))

NAVY = colors.HexColor("#1A3046")
CYAN = colors.HexColor("#25B5D4")
ICE = colors.HexColor("#E5F7FA")
BLUE = colors.HexColor("#1066F7")
RED = colors.HexColor("#DD5E5E")
COOL = colors.HexColor("#F6F9FB")
GRAY = colors.HexColor("#637384")


def esc(s):
    s = str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<font name='NotoKR'>\1</font>", s)
    s = re.sub(r"\[(.*?)\]\((.*?)\)", r"<u>\1</u> (\2)", s)
    return s


styles = getSampleStyleSheet()
S = {
    "h1": ParagraphStyle("h1", fontName="NotoKR-Bold", fontSize=20, leading=27, textColor=NAVY, spaceBefore=7*mm, spaceAfter=4*mm),
    "h2": ParagraphStyle("h2", fontName="NotoKR-Bold", fontSize=14.5, leading=20, textColor=BLUE, spaceBefore=5*mm, spaceAfter=2.5*mm),
    "h3": ParagraphStyle("h3", fontName="NotoKR-Bold", fontSize=11.5, leading=16, textColor=NAVY, spaceBefore=3.5*mm, spaceAfter=2*mm),
    "body": ParagraphStyle("body", fontName="NotoKR", fontSize=8.8, leading=14, textColor=colors.HexColor("#263746"), spaceAfter=2.2*mm),
    "bullet": ParagraphStyle("bullet", fontName="NotoKR", fontSize=8.6, leading=13.5, leftIndent=5*mm, firstLineIndent=-3.5*mm, bulletIndent=1.5*mm, textColor=colors.HexColor("#263746"), spaceAfter=1.2*mm),
    "quote": ParagraphStyle("quote", fontName="NotoKR", fontSize=8.5, leading=13.5, leftIndent=5*mm, rightIndent=3*mm, borderColor=CYAN, borderWidth=1, borderPadding=6, backColor=ICE, textColor=NAVY, spaceBefore=2*mm, spaceAfter=3*mm),
    "code": ParagraphStyle("code", fontName="NotoKR", fontSize=7.3, leading=10.5, leftIndent=3*mm, rightIndent=3*mm, borderColor=colors.HexColor("#DCE5EA"), borderWidth=.5, borderPadding=6, backColor=COOL, textColor=NAVY, spaceAfter=3*mm),
    "cell": ParagraphStyle("cell", fontName="NotoKR", fontSize=6.6, leading=9.2, textColor=colors.HexColor("#263746")),
    "cellh": ParagraphStyle("cellh", fontName="NotoKR-Bold", fontSize=6.6, leading=9.2, textColor=colors.white, alignment=TA_CENTER),
    "small": ParagraphStyle("small", fontName="NotoKR", fontSize=7, leading=10, textColor=GRAY),
}


def table_from_lines(lines, width):
    data = []
    for line in lines:
        vals = [x.strip() for x in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{3,}:?", x.replace(" ", "")) for x in vals):
            continue
        data.append(vals)
    if not data:
        return Spacer(1, 1)
    n = max(len(r) for r in data)
    data = [r + [""] * (n-len(r)) for r in data]
    pdata = []
    for ri, row in enumerate(data):
        pdata.append([Paragraph(esc(v), S["cellh"] if ri == 0 else S["cell"]) for v in row])
    # Narrow ID/rank columns, otherwise distribute evenly.
    if n == 2:
        colw = [width*.27, width*.73]
    elif n == 3:
        colw = [width*.22, width*.37, width*.41]
    else:
        colw = [width/n] * n
    t = Table(pdata, colWidths=colw, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), NAVY),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#C9D7DF")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, COOL]),
        ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    return t


def image_block(path, width, caption):
    from PIL import Image as PILImage
    with PILImage.open(path) as im:
        iw, ih = im.size
    max_h = 155*mm
    scale = min(width/iw, max_h/ih)
    pic = RLImage(str(path), width=iw*scale, height=ih*scale)
    cap = Paragraph(caption, ParagraphStyle("caption", parent=S["small"], alignment=TA_CENTER, textColor=GRAY, spaceBefore=2*mm, spaceAfter=4*mm))
    return KeepTogether([pic, cap])


def markdown_to_flowables(text, width, demote=0):
    lines = text.splitlines()
    out, i = [], 0
    in_code, code = False, []
    while i < len(lines):
        raw, s = lines[i], lines[i].strip()
        if s.startswith("```"):
            if in_code:
                joined = "<br/>".join(esc(x).replace(" ", "&nbsp;") for x in code)
                out.append(Paragraph(joined, S["code"])); code=[]; in_code=False
            else:
                in_code=True
            i += 1; continue
        if in_code:
            code.append(raw); i += 1; continue
        if s.startswith("|") and i+1 < len(lines) and lines[i+1].strip().startswith("|"):
            tbl=[]
            while i < len(lines) and lines[i].strip().startswith("|"):
                tbl.append(lines[i]); i += 1
            out.extend([table_from_lines(tbl, width), Spacer(1, 3*mm)])
            continue
        if not s:
            i += 1; continue
        if s == "[[FLOWCHART_IMAGE]]":
            out.append(image_block(FLOW_IMAGE, width, "그림 1. 이메일 외부 유출 위험 사용자 탐지 및 위험점수 산정 흐름")); i += 1; continue
        if s == "[[RANKING_IMAGE]]":
            out.append(image_block(RANKING_IMAGE, width*0.86, "그림 2. 위험점수 및 위험등급 기반 사용자 조사 우선순위 화면")); i += 1; continue
        if s == "[[PROFILE_IMAGE]]":
            out.append(image_block(PROFILE_IMAGE, width*0.68, "그림 3. 선택 사용자의 위험점수와 주요 탐지 근거 상세 화면")); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)", s)
        if m:
            level=min(len(m.group(1))+demote, 3)
            out.append(Paragraph(esc(m.group(2)), S[f"h{level}"]))
        elif s.startswith(">"):
            out.append(Paragraph(esc(s.lstrip("> ")), S["quote"]))
        elif re.match(r"^[-*]\s+", s):
            out.append(Paragraph("• " + esc(re.sub(r"^[-*]\s+", "", s)), S["bullet"]))
        elif re.match(r"^\d+\.\s+", s):
            out.append(Paragraph(esc(s), S["bullet"]))
        else:
            para=[s]
            while i+1 < len(lines):
                nxt=lines[i+1].strip()
                if not nxt or nxt.startswith(("#", "|", "```", ">", "- ", "* ")) or re.match(r"^\d+\.\s+", nxt): break
                para.append(nxt); i += 1
            out.append(Paragraph(esc(" ".join(para)), S["body"]))
        i += 1
    return out


class Doc(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(filename, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=20*mm, bottomMargin=18*mm,
                         title="테이렌 이메일 외부유출 프로젝트 통합기획서 - 부록 포함", author="프로젝트 팀")
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates(PageTemplate(id="main", frames=[frame], onPage=self.decorate))

    def decorate(self, canvas: Canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(CYAN); canvas.setLineWidth(1.2)
        canvas.line(18*mm, A4[1]-13*mm, A4[0]-18*mm, A4[1]-13*mm)
        canvas.setFont("NotoKR", 7); canvas.setFillColor(GRAY)
        canvas.drawString(18*mm, 10*mm, "SIEM 로그 기반 이메일 외부 유출 위험 사용자 탐지")
        canvas.drawRightString(A4[0]-18*mm, 10*mm, str(doc.page))
        canvas.restoreState()


def cover():
    return [
        Spacer(1, 35*mm),
        Paragraph("SIEM 로그 기반", ParagraphStyle("coverlabel", fontName="NotoKR-Bold", fontSize=14, textColor=CYAN, alignment=TA_CENTER)),
        Spacer(1, 8*mm),
        Paragraph("이메일 외부 유출 위험 사용자 탐지<br/>및 위험 스코어링", ParagraphStyle("cover", fontName="NotoKR-Bold", fontSize=28, leading=39, textColor=NAVY, alignment=TA_CENTER)),
        Spacer(1, 12*mm), HRFlowable(width="55%", thickness=2, color=CYAN, hAlign="CENTER"), Spacer(1, 12*mm),
        Paragraph("통합기획서 - 대시보드 예시 및 제공 로그 데이터 정의 부록 포함", ParagraphStyle("subtitle", fontName="NotoKR", fontSize=12, leading=19, textColor=GRAY, alignment=TA_CENTER)),
        Spacer(1, 45*mm),
        Table([[Paragraph("문서 구성", S["cellh"]), Paragraph("본편 + 부록 A 제공 로그 데이터 상세 정의", S["cell"])],
               [Paragraph("분석 범위", S["cellh"]), Paragraph("2010-01-02 ~ 2011-05-17 / 1,000개 계정", S["cell"])],
               [Paragraph("해석 원칙", S["cellh"]), Paragraph("실제 유출 확정이 아닌 조사 우선순위 제공", S["cell"])]],
              colWidths=[38*mm, 115*mm], style=TableStyle([("BACKGROUND",(0,0),(0,-1),NAVY),("GRID",(0,0),(-1,-1),.5,colors.HexColor('#C9D7DF')),("VALIGN",(0,0),(-1,-1),'MIDDLE'),("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)])),
        PageBreak()
    ]


def main():
    plan = PLAN.read_text(encoding="utf-8")
    dictionary = DICT.read_text(encoding="utf-8")
    story = cover()
    story += markdown_to_flowables(plan, 174*mm)
    story += [PageBreak(), Paragraph("부록 A. 제공 로그 데이터 상세 정의", S["h1"]),
              Paragraph("본 부록은 제공된 데이터 사전 v0.2의 내용을 통합기획서에 편입한 것이다. 원문에 포함된 분석 지시는 실행 명령이 아니라 데이터 정의 및 해석상 주의사항으로만 반영했다.", S["quote"])]
    # Remove the source title to avoid duplicate title, retain all substantive sections.
    dictionary = re.sub(r"^# .*?\n", "", dictionary, count=1)
    story += markdown_to_flowables(dictionary, 174*mm, demote=1)
    story += [Spacer(1, 5*mm), HRFlowable(width="100%", thickness=1, color=CYAN), Spacer(1, 3*mm),
              Paragraph("문서 끝 - 데이터 해석 시 각 로그의 방향, 시간대, 누락 가능성과 정답 라벨 부재를 고려해야 한다.", S["small"])]
    Doc(str(OUT)).build(story)
    print(OUT)


if __name__ == "__main__":
    main()
