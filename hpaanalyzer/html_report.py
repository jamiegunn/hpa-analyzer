"""Self-contained, browsable HTML report.

One file, no external assets (inline CSS + a few lines of JS): a sticky
severity/text filter, collapsible sections, a table of contents, and colour
by severity. Keeps the plain-text report (the original requirement); this is
the navigable companion for people who would rather scroll and search than
read 1000 lines top to bottom.
"""

import html
from datetime import datetime
from typing import List, Optional

from . import __version__
from .clusterprobes import build_probes
from .models import AnalysisResult, Basis, Severity
from .report import _education
from .scoring import WEIGHTS, category_scores, grade, overall_score

_SEV_COLOR = {
    "CRITICAL": "#b3261e", "HIGH": "#c25e00", "MEDIUM": "#8a6d00",
    "LOW": "#1f5fa8", "INFO": "#5f6368",
}


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _basis_badge(b: Basis) -> str:
    color = {"observed": "#2e7d32", "derived": "#1f5fa8", "assumed": "#8a6d00"}[b.label]
    return (f'<span class="basis" style="background:{color}">{b.label}</span>')


def render_html(result: AnalysisResult, target: str, external=None) -> str:
    ctx = result.context
    findings = sorted(
        result.findings,
        key=lambda f: (-f.severity.rank, -WEIGHTS[f.category], f.rule_id))
    score = overall_score(result)
    g = grade(score) if score is not None else "-"
    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity}
    chart = ctx.chart if isinstance(ctx.chart, dict) else {}

    P: List[str] = []
    P.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    P.append("<meta name=viewport content='width=device-width,initial-scale=1'>")
    P.append(f"<title>hpa-analyzer report - {_e(chart.get('name','chart'))}</title>")
    P.append(_CSS)
    P.append("</head><body>")

    # ---- header ----------------------------------------------------------
    badge_color = ("#2e7d32" if score is not None and score >= 80 else
                   "#c25e00" if score is not None and score >= 60 else
                   "#b3261e" if score is not None else "#5f6368")
    P.append("<header>")
    P.append(f"<div class=grade style='background:{badge_color}'>"
             f"{'NOT GRADED' if score is None else g}<span>"
             f"{'' if score is None else f'{score:.0f}/100'}</span></div>")
    P.append("<div class=hmeta>")
    P.append(f"<h1>Helm / Kubernetes / JVM quality report</h1>")
    P.append(f"<div class=sub>{_e(chart.get('name','(no chart)'))} "
             f"v{_e(chart.get('version','?'))} &middot; mode: "
             f"{_e(ctx.render_mode)} &middot; hpa-analyzer v{__version__} "
             f"&middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>")
    P.append("<div class=counts>")
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
              Severity.INFO):
        P.append(f"<span class=pill style='background:{_SEV_COLOR[s.label]}'>"
                 f"{counts[s]} {s.label.lower()}</span>")
    P.append("</div></div></header>")

    # ---- controls / TOC --------------------------------------------------
    P.append("<div class=controls>")
    P.append("<input id=filter placeholder='filter findings by text…' "
             "oninput='ff()'>")
    P.append("<label><input type=checkbox id=hideinfo onchange='ff()'> "
             "hide LOW/INFO</label>")
    P.append("</div>")
    P.append("<nav class=toc>")
    toc = ["summary", "coverage", "scorecard", "findings", "proofs",
           "verify", "education", "methodology"]
    if external:
        toc.insert(5, "external")
    labels = {"summary": "Summary", "coverage": "Coverage",
              "scorecard": "Scorecard", "findings": "Findings",
              "proofs": "Proofs", "verify": "Verify on cluster",
              "external": "External", "education": "Education",
              "methodology": "Methodology"}
    P.append(" ".join(f"<a href=#{t}>{labels[t]}</a>" for t in toc))
    P.append("</nav>")

    # ---- fix first -------------------------------------------------------
    P.append("<section id=summary><h2>Fix these first</h2>")
    crit_high = [f for f in findings
                 if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if crit_high:
        P.append("<ol class=fixfirst>")
        for f in crit_high[:8]:
            loc = f" <code>{_e(f.file)}</code>" if f.file else ""
            assumed = (" <span class=warn>ASSUMED - verify</span>"
                       if f.basis is Basis.ASSUMED else "")
            P.append(f"<li><a href=#{f.rule_id}><b>{_e(f.rule_id)}</b> "
                     f"{_e(f.title)}</a>{loc}{assumed}</li>")
        P.append("</ol>")
    else:
        P.append("<p>No critical or high findings.</p>")
    P.append("</section>")

    # ---- coverage --------------------------------------------------------
    P.append("<section id=coverage><h2>Analysis coverage</h2>")
    P.append("<p class=note>Findings only come from files that were analyzed. "
             "Anything below marked failed/skipped/unknown produced no findings "
             "&mdash; missing coverage, not a clean bill of health.</p>")
    P.append(_html_table(["Input", "Coverage"],
                         [[c[0], c[1]] for c in ctx.coverage]) if ctx.coverage
             else "<p>(nothing analyzable)</p>")
    P.append("</section>")

    # ---- scorecard -------------------------------------------------------
    P.append("<section id=scorecard><h2>Scorecard</h2>")
    rows = []
    for cat, cscore, cfind in category_scores(result):
        by = ", ".join(f"{sum(1 for f in cfind if f.severity is s)}{s.label[0]}"
                       for s in (Severity.CRITICAL, Severity.HIGH,
                                 Severity.MEDIUM, Severity.LOW)
                       if any(f.severity is s for f in cfind)) or "-"
        rows.append([cat.value, "N/A" if cscore is None else f"{cscore:.1f}",
                     "N/A" if cscore is None else grade(cscore),
                     str(WEIGHTS[cat]), by])
    P.append(_html_table(["Category", "Score", "Grade", "Weight", "C/H/M/L"],
                         rows))
    P.append("</section>")

    # ---- findings --------------------------------------------------------
    P.append("<section id=findings><h2>Findings</h2>")
    if not findings:
        P.append("<p>No findings.</p>")
    for f in findings:
        sev = f.severity.label
        low = sev in ("LOW", "INFO")
        P.append(f"<div class='card {'lowinfo' if low else ''}' id={f.rule_id} "
                 f"data-text='{_e((f.rule_id+' '+f.title+' '+f.detail+' '+f.file).lower())}'>")
        P.append(f"<div class=cardhead style='border-color:{_SEV_COLOR[sev]}'>"
                 f"<span class=sev style='background:{_SEV_COLOR[sev]}'>{sev}</span>"
                 f"<b>{_e(f.rule_id)}</b> {_e(f.title)} {_basis_badge(f.basis)}"
                 f"<span class=cat>{_e(f.category.value)}"
                 f"{(' &middot; '+_e(f.file)+(':'+str(f.line) if f.line else '')) if f.file else ''}</span></div>")
        if f.basis is Basis.ASSUMED and f.assumes:
            P.append(f"<p class=assumes><b>Assumes:</b> {_e(f.assumes)} "
                     f"&mdash; if wrong, this finding does not apply.</p>")
        P.append(f"<p><b>Found:</b> {_e(f.detail)}</p>")
        P.append(f"<p><b>Why:</b> {_e(f.why)}</p>")
        if f.math:
            P.append(f"<p class=math><b>Math:</b> {_e(f.math)}</p>")
        P.append(f"<p class=fix><b>Fix:</b> {_e(f.fix)}</p>")
        P.append("</div>")
    P.append("</section>")

    # ---- proofs ----------------------------------------------------------
    P.append("<section id=proofs><h2>Mathematical proof tables</h2>")
    for p in result.proofs:
        P.append("<details><summary>" + _e(p.title) + "</summary>")
        P.append(f"<p class=note>{_e(p.intro)}</p>")
        P.append(_html_table(p.headers, p.rows))
        P.append(f"<p class=verdict><b>Verdict:</b> {_e(p.conclusion)}</p>")
        P.append("</details>")
    if not result.proofs:
        P.append("<p>(none)</p>")
    P.append("</section>")

    # ---- verify on cluster ----------------------------------------------
    probes = build_probes(result)
    if probes:
        P.append("<section id=verify><h2>Verify on your cluster</h2>")
        P.append("<p class=note>The tool reads files, not a cluster. Run each "
                 "command to close a gap static analysis cannot see.</p>")
        for pr in probes:
            P.append("<details><summary>" + _e(pr.title) + "</summary>")
            P.append(f"<p><b>Gap:</b> {_e(pr.gap)}</p>")
            P.append("<pre>" + "\n".join("$ " + _e(c) for c in pr.commands)
                     + "</pre>")
            P.append(f"<p><b>Read:</b> {_e(pr.read)}</p></details>")
        P.append("</section>")

    # ---- external --------------------------------------------------------
    if external:
        P.append("<section id=external><h2>External validators</h2>")
        P.append("<p class=note>Run verbatim; hpa-analyzer does not vouch for "
                 "their output.</p>")
        xr = []
        for e in external:
            st = ("not installed" if not e.installed else
                  "skipped" if not e.ran else "PASS" if e.ok else "FAIL")
            xr.append([e.name, st, e.summary])
        P.append(_html_table(["Tool", "Status", "Result / reason"], xr))
        P.append("</section>")

    # ---- education (collapsed) ------------------------------------------
    P.append("<section id=education><h2>Education appendix</h2>")
    P.append("<details><summary>Show the HPA / JVM-in-container primer</summary>"
             "<pre class=edu>" + _e(_education()) + "</pre></details></section>")

    # ---- methodology -----------------------------------------------------
    P.append("<section id=methodology><h2>Methodology &amp; limitations</h2>")
    P.append(f"<p class=note>Analysis mode: {_e(ctx.render_mode)}. Estimates are "
             "labelled DERIVED/ASSUMED. Complement with kubeconform, a policy "
             "engine, and a load test. See the plain-text report's methodology "
             "section for the full statement.</p></section>")

    P.append(_JS)
    P.append("</body></html>")
    return "\n".join(P)


def _html_table(headers, rows) -> str:
    h = "".join(f"<th>{_e(x)}</th>" for x in headers)
    body = []
    for r in rows:
        cells = "".join(f"<td>{_e(c)}</td>" for c in r)
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{h}</tr></thead><tbody>{''.join(body)}</tbody></table>"


_CSS = """<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5f6368;--line:#e0e0e0;--card:#fafafa}
@media(prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e6e6e6;--muted:#9aa0a6;--line:#2c2f36;--card:#1e2127}}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;gap:20px;align-items:center;padding:20px 28px;border-bottom:1px solid var(--line)}
.grade{min-width:96px;height:96px;border-radius:14px;color:#fff;display:flex;flex-direction:column;
 align-items:center;justify-content:center;font-size:34px;font-weight:700}
.grade span{font-size:13px;font-weight:500;opacity:.9}
.hmeta h1{margin:0 0 4px;font-size:20px}
.sub{color:var(--muted);font-size:13px}
.counts{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}
.pill,.sev,.basis{color:#fff;border-radius:10px;padding:2px 9px;font-size:12px;font-weight:600}
.controls{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);
 padding:10px 28px;display:flex;gap:16px;align-items:center}
#filter{flex:1;max-width:520px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;
 background:var(--card);color:var(--fg)}
.toc{padding:10px 28px;display:flex;gap:14px;flex-wrap:wrap;border-bottom:1px solid var(--line)}
.toc a{color:#1f6feb;text-decoration:none;font-size:14px}
section{padding:20px 28px;border-bottom:1px solid var(--line)}
h2{font-size:17px;margin:0 0 12px}
.fixfirst li{margin:4px 0}
.fixfirst a{color:#1f6feb;text-decoration:none}
.warn,.warn{color:#c25e00}.warn{font-size:12px;font-weight:600}
.card{background:var(--card);border-radius:10px;padding:0 14px 12px;margin:12px 0;border:1px solid var(--line)}
.cardhead{border-left:5px solid;padding:10px 12px;margin:0 -14px 8px;border-radius:10px 10px 0 0;
 display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cat{color:var(--muted);font-size:12px;margin-left:auto}
.card p{margin:6px 0}
.fix{color:#1a7f37}.math{font-family:ui-monospace,monospace;font-size:13px;color:var(--muted)}
.assumes{color:#8a6d00}
.note{color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--card)}
details{margin:8px 0;border:1px solid var(--line);border-radius:8px;padding:6px 12px;background:var(--card)}
summary{cursor:pointer;font-weight:600}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;
 font:12px/1.45 ui-monospace,monospace}
pre.edu{white-space:pre-wrap}
code{font-family:ui-monospace,monospace;font-size:12px}
.hidden{display:none}
.verdict{font-size:14px}
</style>"""

_JS = """<script>
function ff(){
 var q=document.getElementById('filter').value.toLowerCase();
 var hi=document.getElementById('hideinfo').checked;
 document.querySelectorAll('#findings .card').forEach(function(c){
  var t=c.getAttribute('data-text')||'';
  var low=c.classList.contains('lowinfo');
  var show=(t.indexOf(q)>-1)&&!(hi&&low);
  c.classList.toggle('hidden',!show);
 });
}
</script>"""
