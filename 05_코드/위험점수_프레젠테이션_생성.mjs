import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const workspaceDir = "C:/Users/ENCO/Documents/mission1/security_project";
const SKILL_DIR = "C:/Users/ENCO/.codex/plugins/cache/openai-primary-runtime/presentations/26.904.11930/skills/presentations";
const RUNTIME_PYTHON = "C:/Users/ENCO/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe";
const FINAL_PPTX = path.join(workspaceDir, "06_산출물", "보안로그_위험점수_문제정의.pptx");
const stagingDir = path.join(workspaceDir, ".codex-finalizer");
const font = "Paperlogy";

const C = {
  navy: "#1A3046", cyan: "#25B5D4", blue: "#1066F7", ice: "#E5F7FA",
  white: "#FFFFFF", off: "#F8FBFC", gray: "#99A3AA", line: "#D9E0E4",
  red: "#DD5E5E", purple: "#6D55F1", paleRed: "#FBEDEE", palePurple: "#F1EEFF",
};

const deck = Presentation.create({ slideSize: { width: 1280, height: 720 } });

function rect(slide, left, top, width, height, fill, radius = false, line = "none") {
  return slide.shapes.add({
    geometry: radius ? "roundRect" : "rect",
    position: { left, top, width, height },
    fill,
    line: line === "none" ? { fill: "none", width: 0 } : { fill: line, width: 1 },
  });
}

function text(slide, value, left, top, width, height, size, color = C.navy, bold = false, align = "left") {
  const s = slide.shapes.add({
    geometry: "textbox", position: { left, top, width, height }, fill: "none",
    line: { fill: "none", width: 0 },
  });
  s.text = value;
  s.text.style = { typeface: font, fontSize: size, color, bold, alignment: align, verticalAlignment: "middle", autoFit: "shrinkText" };
  return s;
}

function header(slide, section, title, subtitle, page) {
  slide.background.fill = C.off;
  text(slide, section, 54, 26, 260, 24, 13, C.cyan, true);
  text(slide, "SECURITY ANALYTICS", 1000, 27, 220, 20, 10, C.gray, true, "right");
  text(slide, title, 54, 65, 1120, 50, 30, C.navy, true);
  text(slide, subtitle, 54, 112, 1120, 28, 13, C.gray, false);
  text(slide, String(page).padStart(2, "0"), 1190, 682, 30, 18, 9, C.gray, false, "right");
}

// Slide 1: problem definition
{
  const s = deck.slides.add();
  header(s, "01. 분석 문제 정의", "라벨 없이 행동의 이상 정도를 위험점수로 계산", "X = 행동지표 / Y 없음 / 최종 Output = Risk Score", 1);

  const cards = [
    { x: 54, w: 500, fill: C.ice, tag: "X · INPUT", title: "이메일 행동지표", color: C.cyan },
    { x: 574, w: 228, fill: C.paleRed, tag: "Y · LABEL", title: "정답 라벨 없음", color: C.red },
    { x: 822, w: 404, fill: C.navy, tag: "OUTPUT", title: "Risk Score", color: C.white },
  ];
  for (const c of cards) {
    rect(s, c.x, 172, c.w, 160, c.fill, true);
    text(s, c.tag, c.x + 22, 190, c.w - 44, 22, 11, c.color, true);
    text(s, c.title, c.x + 22, 220, c.w - 44, 40, 22, c.x === 822 ? C.white : C.navy, true);
  }
  text(s, "외부메일 수 · 외부 수신자 수 · 첨부파일 수", 76, 270, 456, 20, 11, C.navy);
  text(s, "메일 크기 · BCC · 비정상 시간대", 76, 294, 456, 20, 11, C.navy);
  text(s, "신규 외부 수신자·도메인 · 반복 전송", 76, 318, 456, 20, 11, C.navy);
  text(s, "정상/악성", 596, 270, 184, 22, 12, C.red, true, "center");
  text(s, "유출/비유출", 596, 296, 184, 22, 12, C.red, true, "center");
  text(s, "위험순위", 844, 272, 112, 22, 12, C.white, true);
  text(s, "점수 산정 근거", 844, 299, 180, 22, 12, C.white, true);

  // Relation line and compact equation
  rect(s, 54, 366, 1172, 2, C.line);
  text(s, "문제 유형", 54, 389, 150, 24, 12, C.gray, true);
  text(s, "비지도·통계 기반 위험 스코어링", 54, 420, 520, 38, 23, C.navy, true);
  rect(s, 720, 392, 506, 82, C.white, true, C.line);
  text(s, "사용자 기준선 대비 편차", 744, 405, 210, 24, 13, C.navy, true);
  text(s, "+", 958, 405, 30, 24, 18, C.cyan, true, "center");
  text(s, "복합·반복 행동", 992, 405, 190, 24, 13, C.navy, true);
  text(s, "개별 이상신호를 종합해 조사 우선순위를 제공", 744, 438, 444, 20, 11, C.gray);

  rect(s, 54, 510, 1172, 112, C.ice, true);
  text(s, "핵심 정의", 78, 529, 110, 22, 12, C.cyan, true);
  text(s, "정답을 맞히는 분류 모델이 아니라, 사용자의 평소 행동에서 벗어난 정도를 계산하는 분석", 78, 558, 1090, 34, 19, C.navy, true);
  text(s, "실제 정보유출자를 확정하지 않으며, 외부 유출 위험이 높은 사용자를 우선 검토 대상으로 제시", 78, 594, 1090, 22, 12, C.gray);
}

// Slide 2: flow and scope
{
  const s = deck.slides.add();
  header(s, "02. 분석 구조와 범위", "기준선에서 위험순위와 산정 근거까지 연결", "공식 표현: 사용자 행동 기준선 기반 통계적 이상탐지 및 위험 스코어링", 2);

  const labels = ["Security\nLog", "Email\nFeature", "User\nBaseline", "Anomaly\nScore", "Weighted\nRisk Score", "Risk User\nRanking", "산정 근거"];
  const colors = [C.ice, C.ice, C.ice, C.cyan, C.navy, C.navy, C.purple];
  const txtColors = [C.navy, C.navy, C.navy, C.white, C.white, C.white, C.white];
  const startX = 54, gap = 14, w = 153, y = 172, h = 94;
  for (let i = 0; i < labels.length; i++) {
    const x = startX + i * (w + gap);
    rect(s, x, y, w, h, colors[i], true);
    text(s, String(i + 1).padStart(2, "0"), x + 14, y + 10, 30, 18, 9, txtColors[i], true);
    text(s, labels[i], x + 14, y + 32, w - 28, 48, 15, txtColors[i], true, "center");
    if (i < labels.length - 1) rect(s, x + w, y + 45, gap, 3, C.line);
  }

  text(s, "분석 범위", 54, 314, 180, 28, 17, C.navy, true);
  rect(s, 54, 352, 558, 244, C.white, true, C.line);
  text(s, "목표", 78, 374, 80, 22, 11, C.cyan, true);
  text(s, "외부 전송 이상징후 탐지와\n위험 사용자 우선순위화", 78, 402, 490, 58, 21, C.navy, true);
  rect(s, 78, 480, 510, 1, C.line);
  text(s, "제약", 78, 499, 80, 20, 11, C.red, true);
  text(s, "정답 라벨 없음 · activity 컬럼 없음", 78, 526, 490, 24, 15, C.navy, true);
  text(s, "결과는 유출 확정이 아닌 조사 우선순위로 해석", 78, 556, 490, 20, 11, C.gray);

  rect(s, 634, 314, 592, 282, C.ice, true);
  text(s, "검증 원칙", 660, 338, 150, 26, 17, C.navy, true);
  const tests = [
    ["정상", "기준선 범위의 낮은 점수"],
    ["단일 이상", "한 지표 편차에 따른 점수 상승"],
    ["복합 이상", "여러 이상신호 결합 시 추가 상승"],
    ["반복 행동", "반복·지속 시 위험도 누적"],
  ];
  for (let i = 0; i < tests.length; i++) {
    const yy = 382 + i * 47;
    rect(s, 660, yy + 5, 10, 10, i === 0 ? C.cyan : i === 3 ? C.red : C.navy, true);
    text(s, tests[i][0], 686, yy, 104, 22, 13, C.navy, true);
    text(s, tests[i][1], 800, yy, 382, 22, 12, C.gray);
    if (i < 3) rect(s, 686, yy + 34, 496, 1, C.line);
  }
  rect(s, 634, 620, 592, 38, C.navy, true);
  text(s, "정확도 대신 시나리오별 점수 방향성과 설명 가능성을 검증", 654, 626, 552, 24, 12, C.white, true, "center");
}

await fs.mkdir(stagingDir, { recursive: true });
await fs.mkdir(path.dirname(FINAL_PPTX), { recursive: true });
const candidatePath = path.join(stagingDir, "risk-score-candidate.pptx");
await (await PresentationFile.exportPptx(deck)).save(candidatePath);

const { finalizePresentation } = await import(pathToFileURL(path.join(SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href);
await finalizePresentation({
  explicitTotalSlideCount: 2,
  requiredNativeTableOwnerSlides: [],
  requiredNativeChartOwnerSlides: [],
  workspaceDir,
  candidatePath,
  finalPath: FINAL_PPTX,
  pythonExecutable: RUNTIME_PYTHON,
  integrityValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_package_integrity.py"),
  layoutValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_layout_geometry.py"),
  layoutArgs: ["--expected-slide-size-emu", "12192000,6858000", "--validate-heading-fit"],
  fontPolicy: { basis: "user_request", families: [font] },
  verifyArtifactToolImport: true,
  receiptPath: path.join(stagingDir, "risk-score.validation.json"),
});

console.log(FINAL_PPTX);
