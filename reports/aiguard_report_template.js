#!/usr/bin/env node
/**
 * AIGuard T1 - Report Template
 * Usage: node aiguard_report_template.js <data.json> <output.docx>
 */

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  VerticalAlign, PageNumber, PageBreak, Header, Footer, LevelFormat
} = require('docx');
const fs = require('fs');

const jsonPath   = process.argv[2];
const outputPath = process.argv[3];
if (!jsonPath || !outputPath) {
  console.error("Usage: node aiguard_report_template.js <data.json> <output.docx>");
  process.exit(1);
}

const d = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
const th = d.thresholds;

// Colors
const NAVY   = "1F3864"; const BLUE   = "2E75B6"; const LTBLUE = "D6E4F7";
const RED    = "A32D2D"; const REDLT  = "FCEBEB";
const AMBER  = "7B4F00"; const AMLT   = "FEF3E2";
const GREEN  = "2E6B2E"; const GRLT   = "EAF3DE";
const GRAY   = "555555"; const LTGRAY = "F5F5F5";
const WHITE  = "FFFFFF";

const BDR    = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const BDRS   = { top: BDR, bottom: BDR, left: BDR, right: BDR };
const MARGINS = { top: 80, bottom: 80, left: 140, right: 140 };

// Helpers
const run = (text, opts = {}) => new TextRun({ text, size: 20, font: "Arial", ...opts });
const p   = (text, opts = {}) => new Paragraph({ children: [run(text, opts)], spacing: { after: 100 } });
const sp  = ()                 => new Paragraph({ spacing: { after: 120 } });

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text, bold: true, size: 28, font: "Arial", color: NAVY })],
    spacing: { before: 320, after: 140 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: BLUE, space: 1 } }
  });
}
function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, bold: true, size: 22, font: "Arial", color: BLUE })],
    spacing: { before: 200, after: 100 }
  });
}
function headerRow(cols, widths) {
  return new TableRow({ tableHeader: true, children: cols.map((c, i) =>
    new TableCell({
      borders: BDRS, width: { size: widths[i], type: WidthType.DXA },
      shading: { fill: NAVY, type: ShadingType.CLEAR }, margins: MARGINS,
      children: [new Paragraph({ children: [new TextRun({ text: c, bold: true, color: WHITE, size: 19, font: "Arial" })] })]
    })
  )});
}
function dataRow(cols, widths, shade = false) {
  return new TableRow({ children: cols.map((c, i) =>
    new TableCell({
      borders: BDRS, width: { size: widths[i], type: WidthType.DXA },
      shading: { fill: shade ? LTGRAY : WHITE, type: ShadingType.CLEAR }, margins: MARGINS,
      children: [new Paragraph({ children: [new TextRun({ text: String(c), size: 19, font: "Arial" })] })]
    })
  )});
}
function noteBox(label, text, fill, color) {
  const b = { style: BorderStyle.SINGLE, size: 1, color };
  const brs = { top: b, bottom: b, left: b, right: b };
  return new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [1440, 7920],
    rows: [new TableRow({ children: [
      new TableCell({ borders: brs, shading: { fill: color, type: ShadingType.CLEAR }, margins: MARGINS,
        verticalAlign: VerticalAlign.CENTER,
        children: [new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: label, bold: true, color: WHITE, size: 18, font: "Arial" })] })] }),
      new TableCell({ borders: brs, shading: { fill, type: ShadingType.CLEAR }, margins: MARGINS,
        children: [new Paragraph({ children: [new TextRun({ text, size: 19, font: "Arial" })] })] })
    ]})]
  });
}
function kpiCell(value, label, fill, color) {
  return new TableCell({ borders: BDRS, shading: { fill, type: ShadingType.CLEAR }, margins: MARGINS,
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: String(value), bold: true, size: 36, font: "Arial", color })] }),
      new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: label, size: 18, font: "Arial", color: GRAY })] }),
    ]
  });
}

// Column widths
const W5  = [2600, 1400, 1400, 1200, 1160];
const W4  = [3200, 1600, 1600, 1760];
const W5C = [1400, 1600, 1800, 1000, 1560];
const W4S = [2000, 2400, 1600, 1360];
const W2  = [4680, 4680];
const W4T = [2000, 1800, 1800, 3760];

// Provider rows
const providerRows = d.by_provider.length
  ? d.by_provider.map((p, i) => dataRow(
      [p.label, p.total_events, p.active_sessions, p.pct_active, p.data_volume], W5, i % 2 === 1))
  : [dataRow(["No data for this period", "--", "--", "--", "--"], W5, false)];

// Department rows
const deptRows = d.by_dept.length
  ? d.by_dept.map((dep, i) => dataRow(
      [dep.department, dep.total_events, dep.active_sessions, dep.data_volume], W4, i % 2 === 1))
  : [dataRow(["No department data available", "--", "--", "--"], W4, false)];

// DLP summary rows
const dlpSevColor = { CRITICAL: [REDLT, RED], HIGH: [AMLT, AMBER], MEDIUM: [LTGRAY, GRAY] };
const dlpRows = d.dlp_summary.length
  ? d.dlp_summary.map(r => {
      const [fill, color] = dlpSevColor[r.severity] || [LTGRAY, GRAY];
      return new TableRow({ children: [
        new TableCell({ borders: BDRS, shading: { fill, type: ShadingType.CLEAR }, margins: MARGINS,
          children: [new Paragraph({ children: [new TextRun({ text: r.severity, bold: true, color, size: 19, font: "Arial" })] })] }),
        new TableCell({ borders: BDRS, margins: MARGINS,
          children: [new Paragraph({ children: [new TextRun({ text: r.count, size: 19, font: "Arial" })] })] }),
      ]});
    })
  : [new TableRow({ children: [
      new TableCell({ borders: BDRS, margins: MARGINS, columnSpan: 2,
        children: [p("No DLP alerts for this period.")] })
    ]})];

// DLP top rows
const dlpTopRows = d.dlp_top.length
  ? d.dlp_top.map((r, i) => dataRow([r.timestamp, r.src, r.provider, r.severity, r.dept], W5C, i % 2 === 1))
  : [dataRow(["No CRITICAL/HIGH alerts", "--", "--", "--", "--"], W5C, false)];

// Source rows
const sourceRows = d.top_sources.length
  ? d.top_sources.map((s, i) => dataRow([s.src, s.department, s.total_events, s.active_sessions], W4S, i % 2 === 1))
  : [dataRow(["No internal source data available", "--", "--", "--"], W4S, false)];

// Total for pct
const total = d.total || 1;
const pct = (n) => total ? `${(n/total*100).toFixed(1)}%` : "0%";

const doc = new Document({
  numbering: { config: [
    { reference: "nums", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.",
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }
  ]},
  styles: {
    default: { document: { run: { font: "Arial", size: 20 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Arial", color: NAVY },
        paragraph: { spacing: { before: 320, after: 140 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Arial", color: BLUE },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 1 } },
    ]
  },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
    headers: { default: new Header({ children: [
      new Paragraph({ children: [new TextRun({ text: `YOUR_ORGANIZATION_NAME -- AIGuard T1 Governance Report -- ${d.month_name}`, size: 18, font: "Arial", color: GRAY })],
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 1 } } })
    ]}) },
    footers: { default: new Footer({ children: [
      new Paragraph({ alignment: AlignmentType.CENTER,
        children: [
          new TextRun({ text: "YOUR_ORGANIZATION_NAME -- YOUR_DIVISION   |   INTERNAL   |   Page ", size: 18, font: "Arial", color: GRAY }),
          new TextRun({ children: [PageNumber.CURRENT], size: 18, font: "Arial", color: GRAY }),
          new TextRun({ text: " of ", size: 18, font: "Arial", color: GRAY }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 18, font: "Arial", color: GRAY }),
        ],
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 1 } } })
    ]}) },
    children: [

      // Cover
      sp(), sp(),
      new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "YOUR_ORGANIZATION_NAME", bold: true, size: 28, font: "Arial", color: GRAY })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
        children: [new TextRun({ text: "IT/OT Division -- AIGuard T1 Sensor", size: 24, font: "Arial", color: GRAY })] }),
      new Paragraph({ spacing: { before: 240, after: 160 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: BLUE, space: 4 } } }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 200, after: 80 },
        children: [new TextRun({ text: "AI GOVERNANCE REPORT", bold: true, size: 48, font: "Arial", color: NAVY })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 },
        children: [new TextRun({ text: d.month_name, bold: true, size: 36, font: "Arial", color: BLUE })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
        children: [new TextRun({ text: `Generated: ${d.generated}`, size: 20, font: "Arial", color: GRAY, italic: true })] }),
      new Paragraph({ spacing: { before: 200 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 4 } } }),
      sp(),

      // KPI summary
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [2340, 2340, 2340, 2340],
        rows: [new TableRow({ children: [
          kpiCell(`${d.total.toLocaleString()}`, "Total Events", LTBLUE, NAVY),
          kpiCell(`${d.active.toLocaleString()}`, "Active Sessions", GRLT, GREEN),
          kpiCell(`${d.keepalive.toLocaleString()}`, "Keepalive / Polling", AMLT, AMBER),
          kpiCell(d.total_bytes, "Total Data Volume", LTGRAY, NAVY),
        ]})]
      }),
      sp(),

      // Methodology note
      noteBox("METHODOLOGY",
        `Traffic thresholds in this report are empirically defined based on observed network behavior at YOUR_ORGANIZATION_NAME. Events under ${th.keepalive_max} bytes are classified as keepalive/polling (browser tabs, session heartbeats). Events over ${th.active_min} bytes represent meaningful AI interactions. These thresholds are not industry standards and will be refined as more data is collected.`,
        LTBLUE, BLUE),
      sp(),

      // Section 1: Traffic Classification
      h1("1.  Traffic Classification"),
      p(`The following table breaks down all detected AI traffic for ${d.month_name} by category. Active Sessions represent events with payload size >= ${th.active_min} bytes -- the threshold above which meaningful AI content exchange is likely occurring.`),
      sp(),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [3200, 1600, 1600, 1560, 1400],
        rows: [
          headerRow(["Category", "Events", "% of Total", "Interpretation", "Threshold"], [3200, 1600, 1600, 1560, 1400]),
          dataRow([`Active Sessions (>=${th.active_min}b)`,   `${d.active.toLocaleString()}`,    pct(d.active),    "Real AI interactions",               `>= ${th.active_min}b`],  [3200,1600,1600,1560,1400], false),
          dataRow([`Small Events (${th.keepalive_max}b-${th.active_min}b)`, `${d.small.toLocaleString()}`,     pct(d.small),     "Possible short queries",            `${th.keepalive_max}-${th.active_min}b`], [3200,1600,1600,1560,1400], true),
          dataRow([`Keepalive / Polling (<${th.keepalive_max}b)`, `${d.keepalive.toLocaleString()}`, pct(d.keepalive), "Browser tabs open, no interaction",  `< ${th.keepalive_max}b`],  [3200,1600,1600,1560,1400], false),
          dataRow([`Heavy Sessions (>=${th.heavy_min}b)`,     `${d.heavy.toLocaleString()}`,     pct(d.heavy),     "Intensive use / file context",       `>= ${th.heavy_min}b`],  [3200,1600,1600,1560,1400], true),
        ]
      }),
      sp(),

      // Section 2: By Provider
      h1("2.  AI Provider Usage"),
      p("Active Sessions is the primary metric for governance purposes. Total Events includes all traffic including keepalive and polling generated by open browser tabs."),
      sp(),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: W5,
        rows: [headerRow(["Provider", "Total Events", "Active Sessions", "% Active", "Data Volume"], W5), ...providerRows]
      }),
      sp(),

      // Section 3: By Department
      h1("3.  Usage by Department"),
      p("Departments are identified via VLAN tag and Active Directory lookup. Events without VLAN tag are listed as Unknown and excluded from this table."),
      sp(),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: W4,
        rows: [headerRow(["Department", "Total Events", "Active Sessions", "Data Volume"], W4), ...deptRows]
      }),
      sp(),

      // Section 4: DLP Alerts
      h1("4.  DLP Alerts"),
      p("DLP alerts are generated when AI traffic originates from sensitive network segments or exceeds defined data thresholds. CRITICAL and HIGH alerts require IT review."),
      sp(),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: W2,
        rows: [headerRow(["Severity", "Count"], W2), ...dlpRows]
      }),
      sp(),
      h2("4.1  CRITICAL and HIGH Alert Detail"),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: W5C,
        rows: [headerRow(["Timestamp", "Source", "Provider", "Severity", "Department"], W5C), ...dlpTopRows]
      }),
      sp(),

      // Section 5: Top Source Endpoints
      h1("5.  Top Source Endpoints"),
      p("Top 10 internal IP addresses by Active Sessions. High Active Session counts from a single endpoint may indicate automated or agentic AI usage and warrant investigation."),
      sp(),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: W4S,
        rows: [headerRow(["Source IP", "Department", "Total Events", "Active Sessions"], W4S), ...sourceRows]
      }),
      sp(),

      // Appendix
      new Paragraph({ children: [new PageBreak()] }),
      h1("Appendix -- Measurement Methodology"),
      p("The traffic classification thresholds applied in this report are empirically defined based on observed network traffic patterns at YOUR_ORGANIZATION_NAME. They are not derived from published industry standards, as no such standards currently exist for AI traffic classification in municipal network environments."),
      sp(),
      h2("Threshold Definitions"),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: W4T,
        rows: [
          headerRow(["Category", "Size Range", "Typical Source", "Rationale"], W4T),
          dataRow(["Keepalive / Polling", `< ${th.keepalive_max}b`, "Browser tabs, OS agents", "TCP ACK and session heartbeat packets carry no AI content. Open browser tabs generate polling requests every 30-60 seconds regardless of user activity."], W4T, false),
          dataRow(["Small Event", `${th.keepalive_max}-${th.active_min}b`, "Short queries, auth tokens", "May contain short prompts or responses but insufficient payload to confirm meaningful AI interaction."], W4T, true),
          dataRow(["Active Session", `>= ${th.active_min}b`, "User-initiated AI queries", "Payload size consistent with meaningful prompt or response content. Primary metric for governance reporting."], W4T, false),
          dataRow(["Heavy Session", `>= ${th.heavy_min}b`, "File uploads, long context", "Consistent with document submission, extended conversations, or model downloads."], W4T, true),
        ]
      }),
      sp(),
      noteBox("IMPORTANT",
        "These thresholds will be reviewed and refined quarterly as AIGuard accumulates more data. Any significant revision to thresholds will be noted in the report header and will affect comparability with prior periods. IT/OT Division retains the raw event data for retrospective re-analysis if thresholds change.",
        AMLT, AMBER),
      sp(),
      h2("Detection Methods"),
      p("AIGuard T1 uses three detection methods in priority order:"),
      new Paragraph({ numbering: { reference: "nums", level: 0 },
        children: [run("SNI (Server Name Indication) -- ", { bold: true }), run("Extracts the destination hostname from the TLS Client Hello packet. Most reliable method. Unaffected by DNS caching or DNS-over-HTTPS.")],
        spacing: { after: 80 } }),
      new Paragraph({ numbering: { reference: "nums", level: 0 },
        children: [run("DNS Cache -- ", { bold: true }), run("When a DNS query for a known AI hostname is observed, the resolved IP is cached. Subsequent HTTPS connections to that IP are attributed to the AI provider.")],
        spacing: { after: 80 } }),
      new Paragraph({ numbering: { reference: "nums", level: 0 },
        children: [run("IP Prefix Matching -- ", { bold: true }), run("For providers with stable, proprietary IP ranges (Microsoft, Anthropic, Google Cloud, Hugging Face, DeepSeek), direct IP matching is used as a fallback. Shared CDN ranges (Cloudflare) are excluded to prevent false positives.")],
        spacing: { after: 80 } }),
    ]
  }]
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(outputPath, buf);
  console.log(`Report generated: ${outputPath}`);
}).catch(e => { console.error(e); process.exit(1); });
