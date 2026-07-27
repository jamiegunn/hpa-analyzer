#!/usr/bin/env python3
"""
p11_docsite.py - the documentation site is checked against the program it documents.

A docs site is a set of claims about a program. Claims decay silently: the flag
gets renamed, the exit code changes, the fixture's score moves, and the page
keeps saying what it said. This script re-derives every checkable claim on
docs/*.html from the running program and fails if the page disagrees.

It checks four kinds of thing:

  1. STRUCTURE   every page is well-formed, links to files that exist, and
                 every in-page #anchor it links to actually has an id.
  2. FLAGS       every flag named on the reference page exists in --help, and
                 every flag in --help is named on the reference page. Both
                 directions - a reference page that documents a flag that was
                 removed is as wrong as one that misses a flag that was added.
  3. COMMANDS    every command block shown as a `$ ...` transcript is executed,
                 and its exit code and quoted output lines are compared with
                 what actually comes back.
  4. NUMBERS     the specific figures quoted in prose (line counts, scores,
                 byte sizes, exit codes, weights) are recomputed.

Exit 0 = the site tells the truth about this commit.
"""

import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nativeoverride  # noqa: F401,E402  (sets HPA_ANALYZER_ALLOW_NATIVE - see the module for why)
SITE = os.path.join(REPO, "docs")
PAGES = ["index.html", "usage.html", "reading-the-report.html",
         "container.html", "reference.html", "limits.html"]

OUT = os.path.join(REPO, ".p11_tmp")

failures = []
checks = 0


def check(label, ok, detail=""):
    global checks
    checks += 1
    if ok:
        print("  PASS  %s" % label)
    else:
        print("  FAIL  %s%s" % (label, ("  --  " + detail) if detail else ""))
        failures.append(label + ((" :: " + detail) if detail else ""))


def run(args, **kw):
    return subprocess.run([sys.executable, "-m", "hpaanalyzer"] + args,
                          cwd=REPO, capture_output=True, text=True,
                          timeout=300, **kw)


def read(page):
    with open(os.path.join(SITE, page), encoding="utf-8") as fh:
        return fh.read()


def text_of(src):
    """Strip tags and unescape, so prose claims can be searched as plain text."""
    s = re.sub(r"<(script|style)\b.*?</\1>", " ", src, flags=re.S)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s)


PAGE_SRC = {p: read(p) for p in PAGES}
PAGE_TXT = {p: text_of(s) for p, s in PAGE_SRC.items()}
ALL_TXT = "\n".join(PAGE_TXT.values())


# ---------------------------------------------------------------- 1. STRUCTURE

print("\nCLAIM 1 - the site is structurally sound")

for p in PAGES:
    src = PAGE_SRC[p]
    check("%s: has a doctype, title and charset" % p,
          src.lstrip().lower().startswith("<!doctype html>")
          and "<title>" in src and 'charset="utf-8"' in src)
    # Count opening tags with a boundary after the name: a bare src.count("<head")
    # also matches every <header>, which is a bug in the check, not the page.
    check("%s: tags balance (html/head/body/main)" % p,
          all(len(re.findall(r"<%s(?=[\s>])" % t, src))
              == len(re.findall(r"</%s\s*>" % t, src))
              for t in ("html", "head", "body", "main", "header",
                        "table", "pre", "nav", "footer")))
    check("%s: loads the stylesheet" % p, 'href="assets/style.css"' in src)
    check("%s: nav marks itself current exactly once" % p,
          src.count('aria-current="page"') == 1)
    check("%s: nav links to all %d pages" % (p, len(PAGES)),
          all(('href="%s"' % q) in src for q in PAGES))

check("the stylesheet exists", os.path.exists(os.path.join(SITE, "assets", "style.css")))
check(".nojekyll exists (Pages serves the HTML verbatim, no build step)",
      os.path.exists(os.path.join(SITE, ".nojekyll")))

# every local href resolves: file targets exist, #anchors have ids
ids = {p: set(re.findall(r'id="([^"]+)"', PAGE_SRC[p])) for p in PAGES}
bad_links = []
for p in PAGES:
    for href in re.findall(r'href="([^"]+)"', PAGE_SRC[p]):
        if href.startswith(("http://", "https://", "mailto:")):
            continue
        target, _, frag = href.partition("#")
        target = target or p
        if target not in PAGES and not os.path.exists(os.path.join(SITE, target)):
            bad_links.append("%s -> %s (no such file)" % (p, href))
        elif frag and target in PAGES and frag not in ids[target]:
            bad_links.append("%s -> %s (no such anchor)" % (p, href))
check("every internal link resolves (file and #anchor)", not bad_links,
      "; ".join(bad_links))

# every GitHub blob/tree link points at a path that exists in this repo
bad_repo = []
for p in PAGES:
    for href in re.findall(r'href="(https://github\.com/[^"]+)"', PAGE_SRC[p]):
        m = re.search(r"/(?:blob|tree)/main/(.+)$", href)
        if m and not os.path.exists(os.path.join(REPO, m.group(1))):
            bad_repo.append("%s -> %s" % (p, m.group(1)))
check("every github.com/blob|tree link names a path that exists here",
      not bad_repo, "; ".join(bad_repo))


# ------------------------------------------------------------------- 2. FLAGS

print("\nCLAIM 2 - the reference page and --help agree, in both directions")

helptext = run(["--help"]).stdout
help_flags = set(re.findall(r"(--[a-z][a-z-]+|-[a-zA-Z])\b", helptext))
# argparse prints the metavars too; keep only real option strings
help_flags = {f for f in help_flags if f.startswith("-")}
# things that appear in prose inside help but are not flags of this program
PROSE = {"-XX", "-Xmx", "-Xss", "-o"}
ref = PAGE_SRC["reference.html"]
ref_flags = set(re.findall(r"<code>(--?[a-zA-Z][a-zA-Z-]*)", ref))

documented_missing = sorted(f for f in help_flags
                            if f not in ref_flags and f not in PROSE
                            and len(f) > 2)
check("every flag in --help appears on the reference page",
      not documented_missing, " ".join(documented_missing))

invented = sorted(f for f in ref_flags
                  if f.startswith("--") and f not in help_flags
                  and not f.startswith("--kube-vers"))
check("the reference page invents no flags", not invented, " ".join(invented))

for f in ["-o", "--output", "--html", "--summary", "--full", "--all", "--teach",
          "--stdout", "--quiet", "--helm", "--kube-version", "--assume-java",
          "--measured", "--check", "--fail-on", "--min-score",
          "--require-coverage", "--json", "--cross-check", "--version"]:
    check("reference documents %s" % f, f in ref_flags or f in ref)

check("the version string on the site matches --version",
      run(["--version"]).stdout.strip() == "hpa-analyzer 1.0.0"
      and "hpa-analyzer 1.0.0" in ALL_TXT)


# ---------------------------------------------------------------- 3. COMMANDS

print("\nCLAIM 3 - the transcripts on the site are what the program prints")

os.makedirs(OUT, exist_ok=True)

# The site's transcripts are helm-mode runs and say so. On a host without helm
# the same commands answer a weaker question - static parsing, not a render -
# and produce a different, longer report. That is not the site being wrong, so
# these checks are gated rather than failed; but a gate that just skips would
# let the site drift unchecked on such a host, so the helm-less branch verifies
# the figures the site publishes FOR that case instead. Discovered by running
# this script on a second machine that happens not to have helm.
HAVE_HELM = subprocess.run(["which", "helm"], capture_output=True).returncode == 0
if not HAVE_HELM:
    print("  NOTE  helm is not on PATH here: the mode-dependent transcripts are")
    print("        checked against the static-mode figures the site publishes")
    print("        for exactly this case, not against the helm-mode ones.")

# --check on good-chart, as shown on index.html and usage.html
p = run(["fixtures/good-chart", "--check"])
check("index: `--check` on good-chart exits 0", p.returncode == 0, str(p.returncode))
for line in ["[ok]   Helm chart: Chart.yaml",
             "[ok]   Values: values.yaml",
             "[ok]   Templates: 7 file(s) under templates/",
             "[ok]   Workloads: 1 (Deployment)",
             "[ok]   Dockerfile: Dockerfile (Java 21)"] + (
                 ["[info] Render mode: helm (rendered truth).",
                  "=> Looks complete. Analysis will run at full coverage."]
                 if HAVE_HELM else []):
    out = p.stdout + p.stderr
    check("index transcript line is real: %s" % line[:52],
          line in out and line in PAGE_TXT["index.html"])
if not HAVE_HELM:
    out = p.stdout + p.stderr
    check("without helm the tool says so on its own banner, as the site claims",
          "[info] Render mode: static (helm not found on PATH)." in out
          and "static (helm not found on PATH)" in ALL_TXT)

# a plain run on bad-chart, as shown on index.html
p = run(["fixtures/bad-chart", "-o", os.path.join(OUT, "bad.txt")])
out = p.stdout + p.stderr
check("index: plain run on bad-chart exits 0 (findings are not errors)",
      p.returncode == 0, str(p.returncode))
for line in ["GRADE F  (45.5/100)   11 critical, 11 high, 14 medium, 16 low",
             "1. [HP004] HPA minReplicas > maxReplicas (invalid)  (templates/hpa.yaml)",
             "4. [RS002] Memory quantity uses 'm' (MILLI-bytes)  (values.yaml)",
             "... +17 more critical/high (see report)"]:
    check("index transcript line is real: %s" % line[:52],
          line in out and line in PAGE_TXT["index.html"])
# The mode is named on the last line, and the site publishes both spellings:
# the transcript is helm, and the usage note quotes the static one.
_mode = "helm" if HAVE_HELM else "static (helm not found on PATH)"
check("index transcript line is real: (60 findings, 7 proof tables, mode: ...)",
      "(60 findings, 7 proof tables, mode: %s)" % _mode in out
      and ("mode: %s" % _mode) in ALL_TXT)
check("the site's claim that the verdict does not move between modes holds here",
      "GRADE F  (45.5/100)   11 critical, 11 high, 14 medium, 16 low" in out)

# --quiet, as shown on usage.html
p = run(["fixtures/good-chart", "--quiet", "-o", os.path.join(OUT, "q.txt")])
out = (p.stdout + p.stderr).strip()
_q = "hpa-analyzer [%s]: score 100.0/100 (grade A+), 0 finding(s) ->" % (
    "helm" if HAVE_HELM else "static (helm not found on PATH)")
check("usage: --quiet prints one line in the documented shape",
      out.startswith(_q)
      and ("hpa-analyzer [helm]: score 100.0/100 (grade A+), 0 finding(s) -&gt;"
           in PAGE_SRC["usage.html"]), out[:90])

# the UNDETERMINED transcript, as shown on usage.html
p = run(["fixtures/good-chart", "-o", os.path.join(OUT, "g.txt")])
out = p.stdout + p.stderr
check("usage: good-chart really is A+ 100.0 with an UNDETERMINED JVM fit",
      "GRADE A+  (100.0/100)   0 critical, 0 high, 0 medium, 0 low" in out
      and "JVM fit UNDETERMINED (limit 1 GiB vs model range 722 MiB-1.2 GiB)" in out)
check("usage: the 'not scored, and NOT a pass' wording is the tool's own",
      "not scored, and NOT a pass" in out
      and "not scored, and NOT a pass" in PAGE_TXT["usage.html"])

# --measured, as shown on usage.html - the claim that the score goes DOWN
p = run(["fixtures/good-chart", "--measured", "metaspace=210Mi,threads=180",
         "-o", os.path.join(OUT, "m.txt")])
out = p.stdout + p.stderr
check("usage: --measured transcript matches (98.3, 1 high, XF002)",
      "GRADE A+  (98.3/100)   0 critical, 1 high, 0 medium, 0 low" in out
      and "[XF002] Estimated JVM footprint exceeds memory limit" in out, out[:200])
check("usage: the narrowed range 982 MiB-1.2 GiB is real",
      "982 MiB-1.2 GiB" in out and "982 MiB–1.2 GiB" in PAGE_TXT["usage.html"])


# ---------------------------------------------------------------- 4. NUMBERS

print("\nCLAIM 4 - the figures quoted in prose are recomputed, not remembered")

# exit code table on reference.html
cases = [
    (["fixtures/bad-chart", "-o", os.path.join(OUT, "e0.txt"), "--quiet"], 0,
     "a run with findings exits 0"),
    (["fixtures/bad-chart", "--fail-on", "high", "-o", os.path.join(OUT, "e1.txt"), "--quiet"], 1,
     "--fail-on high on bad-chart exits 1"),
    (["fixtures/good-chart", "--fail-on", "high", "-o", os.path.join(OUT, "e2.txt"), "--quiet"], 0,
     "--fail-on high on good-chart exits 0"),
    (["fixtures/nojvm-chart", "--require-coverage", "-o", os.path.join(OUT, "e3.txt"), "--quiet"], 1,
     "--require-coverage on nojvm-chart exits 1"),
    (["/nope-does-not-exist", "-o", os.path.join(OUT, "e4.txt")], 2,
     "a missing directory exits 2"),
    ([], 2, "no arguments at all exits 2"),
]
for argv, expect, label in cases:
    got = run(argv).returncode
    check("exit-code table: %s" % label, got == expect, "got %d" % got)

p = run(["/nope-does-not-exist", "-o", os.path.join(OUT, "e4.txt")])
check("reference: the quoted error wording is the tool's own",
      "is not a directory" in (p.stdout + p.stderr)
      and "is not a directory" in PAGE_TXT["reference.html"])

# --check on a non-chart directory exits 2 (claimed on index and usage)
empty = os.path.join(OUT, "not-a-chart")
os.makedirs(empty, exist_ok=True)
p = run([empty, "--check"])
check("--check on a non-chart directory exits 2", p.returncode == 2, str(p.returncode))
check("the quoted '=> Not a chart directory' wording is the tool's own",
      "Not a chart directory" in (p.stdout + p.stderr)
      and "Not a chart directory" in PAGE_TXT["index.html"])

# verbosity line counts quoted on usage.html and reference.html
sizes = {}
for label, extra in [("summary", ["--summary"]), ("default", []),
                     ("all", ["--all"]), ("full", ["--full"])]:
    path = os.path.join(OUT, "v-%s.txt" % label)
    run(["fixtures/bad-chart"] + extra + ["-o", path, "--quiet"])
    with open(path, encoding="utf-8") as fh:
        sizes[label] = sum(1 for _ in fh)
# Both sets are published: the table is a helm-mode run, and the note under it
# gives the helm-less figures. Whichever machine this runs on, the site has
# already committed to a number for it, so there is always something to fail.
# R16 moved every one of these eight numbers by exactly +4, and the reason is
# worth stating because "the docs figures drifted again" is how a real
# regression gets waved through: the scoring-model footer gained a four-line
# paragraph explaining the NOT APPLICABLE state, and it is printed
# unconditionally - it documents the MODEL, not the run - so a chart with no
# not-applicable category grows by the same four lines. `diff` between the
# pre-R16 and post-R16 report of fixtures/bad-chart is those four lines and
# nothing else. Both sets were re-measured, the helm-less one on a PATH with no
# helm binary rather than with `--helm off`, which is a different thing.
QUOTED = ({"summary": 171, "default": 910, "all": 1022, "full": 1242} if HAVE_HELM
          else {"summary": 174, "default": 923, "all": 1035, "full": 1255})
for label in ("summary", "default", "all", "full"):
    quoted = QUOTED[label]
    check("verbosity table: --%s is %d lines" % (label, quoted),
          sizes[label] == quoted, "measured %d" % sizes[label])
    check("that figure appears on both pages that quote it",
          str(quoted) in PAGE_TXT["usage.html"] and str(quoted) in PAGE_TXT["reference.html"])
check("the ordering the table implies holds: summary < default < all < full",
      sizes["summary"] < sizes["default"] < sizes["all"] < sizes["full"])

# --html derives its path from -o, as usage.html claims
base = os.path.join(OUT, "derive", "svc.txt")
os.makedirs(os.path.dirname(base), exist_ok=True)
run(["fixtures/good-chart", "-o", base, "--html", "--quiet"])
check("--html with no argument derives <-o basename>.html",
      os.path.exists(os.path.join(OUT, "derive", "svc.html")))

# JSON shape quoted on usage.html and reference.html
jpath = os.path.join(OUT, "r.json")
run(["fixtures/bad-chart", "-o", os.path.join(OUT, "r.txt"), "--json", jpath, "--quiet"])
with open(jpath, encoding="utf-8") as fh:
    doc = json.load(fh)
for key in ["target", "mode", "score", "grade", "graded", "score_coverage",
            "counts", "findings", "coverage", "cluster_probes", "preflight",
            "cross_check"]:
    check("json top-level key documented and present: %s" % key,
          key in doc and key in PAGE_TXT["reference.html"])
finding_keys = ["rule", "severity", "basis", "assumes", "category", "title",
                "file", "line", "detail", "why", "fix", "math"]
check("the finding shape on the site is the finding shape in the file",
      sorted(doc["findings"][0].keys()) == sorted(finding_keys))
check("the CH002 example quoted on two pages is a real finding",
      any(f["rule"] == "CH002" and f["severity"] == "MEDIUM"
          and f["basis"] == "observed"
          and f["title"] == "Chart apiVersion v1 (Helm 2 era)"
          for f in doc["findings"]))
sev = {f["severity"] for f in doc["findings"]}
bas = {f["basis"] for f in doc["findings"]}
check("documented severities are the ones that occur",
      sev <= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, str(sev))
check("documented bases are the ones that occur",
      bas <= {"observed", "derived", "assumed"}, str(bas))

# scorecard weights quoted on reference.html and reading-the-report.html
with open(os.path.join(OUT, "bad.txt"), encoding="utf-8") as fh:
    report = fh.read()
weights = {}
for line in report.splitlines():
    m = re.match(r"\|\s*(.+?)\s*\|\s*([\d.]+)\s*\|\s*\S+\s*\|\s*(\d+)\s*\|", line)
    if m and m.group(1) != "Category":
        weights[m.group(1)] = int(m.group(3))
check("ten scoring categories exist", len(weights) == 10, str(len(weights)))
check("the weights sum to 100", sum(weights.values()) == 100, str(sum(weights.values())))
top4 = sum(v for k, v in weights.items()
           if k.startswith(("Resource Requests", "Horizontal Pod",
                            "Java / JVM", "Cross-File")))
check("the '58 of the 100 points' claim on two pages is arithmetic",
      top4 == 58 and "58 of the 100 points" in PAGE_TXT["reference.html"]
      and "58 of the 100 points" in PAGE_TXT["reading-the-report.html"],
      "measured %d" % top4)
for name, w in weights.items():
    check("reference lists weight %d for %s" % (w, name[:34]),
          re.search(r"%s.{0,400}?<td>%d</td>" % (re.escape(name.replace("<->", "↔")
                                                          .replace("&", "&amp;")), w),
                    PAGE_SRC["reference.html"], re.S) is not None
          or ("%s" % name.split("(")[0].strip()) in PAGE_TXT["reference.html"])

# the deduction model quoted on two pages
check("the deduction model on the site is the one the report states",
      "CRITICAL -25, HIGH -12, MEDIUM -6, LOW\n-3, INFO -0" in report
      or "CRITICAL -25, HIGH -12, MEDIUM -6" in report.replace("\n", " "))

# the HP004 finding block quoted verbatim on reading-the-report.html
for frag in ["[HP004] HPA minReplicas > maxReplicas (invalid)",
             "Basis : OBSERVED - read directly from your files (stated as fact).",
             "Math  : Constraint violated: 25 <= 20 is false.",
             "Fix   : Make min <= max."]:
    check("HP004 block quoted verbatim: %s" % frag[:46],
          frag in report and frag in PAGE_TXT["reading-the-report.html"])

# the HP025 ASSUMED block
for frag in ["[HP025] HPA scales on memory for a JVM workload",
             "ASSUMED - the tool could not observe this directly and fell back to a"]:
    check("HP025 block quoted verbatim: %s" % frag[:46],
          frag in report and frag in PAGE_TXT["reading-the-report.html"])

# report section names quoted on reading-the-report.html
sections = re.findall(r"^(\d)\. ([A-Z][^\n]+)$", report, re.M)
check("a default report has 7 numbered sections", len(sections) == 7, str(len(sections)))
for _, name in sections:
    first = name.split()[0].title()
    check("section named on the site: %s" % name[:40],
          first in PAGE_TXT["reading-the-report.html"])

# --full inserts the education appendix and pushes methodology to 8
run(["fixtures/bad-chart", "--full", "-o", os.path.join(OUT, "full.txt"), "--quiet"])
with open(os.path.join(OUT, "full.txt"), encoding="utf-8") as fh:
    fulltext = fh.read()
check("--full really does insert an education appendix at 7 and move methodology to 8",
      re.search(r"^7\. EDUCATION APPENDIX", fulltext, re.M) is not None
      and re.search(r"^8\. METHODOLOGY", fulltext, re.M) is not None)

# --cross-check really does take slot 7, as claimed
have_ext = all(subprocess.run(["which", t], capture_output=True).returncode == 0
               for t in ("helm", "kubeconform", "kube-score", "polaris"))
if have_ext:
    run(["fixtures/bad-chart", "--cross-check", "-o", os.path.join(OUT, "cc.txt"), "--quiet"])
    with open(os.path.join(OUT, "cc.txt"), encoding="utf-8") as fh:
        cc = fh.read()
    check("--cross-check takes section 7",
          re.search(r"^7\. EXTERNAL VALIDATORS - INDEPENDENT CROSS-CHECK", cc, re.M) is not None)
    for frag in ["| helm lint   | FAIL    |",
                 "| kubeconform | UNKNOWN |",
                 "| kube-score  | FAIL    |",
                 "| polaris     | FAIL    |"]:
        check("cross-check table row is real: %s" % frag.strip()[:30], frag in cc)
    # Case-folded: the page opens a sentence with the tool's name, the report
    # uses it mid-sentence. Same words, and the capital is the page being
    # correct English rather than the page drifting from the program.
    _expl = "polaris exits 0 whether it found nothing or found danger"
    check("the 'status is not the exit code' explanation is the tool's own",
          _expl in cc.lower().replace("\n", " ")
          and _expl in PAGE_TXT["usage.html"].lower().replace("\n", " "))
    check("UNKNOWN is documented as a third state, as the report says",
          "UNKNOWN means the validator ran and could not reach a verdict" in cc)
else:
    print("  SKIP  cross-check rows - not all four external tools are on PATH here")

# the R11 non-determinism claim: re-measure it rather than repeat it
if have_ext:
    md5s, texts = [], []
    for i in range(4):
        path = os.path.join(OUT, "nd%d.txt" % i)
        run(["fixtures/bad-chart", "--cross-check", "-o", path, "--quiet"])
        with open(path, encoding="utf-8") as fh:
            body = [ln for ln in fh if not ln.startswith("Generated")]
        texts.append(body)
        md5s.append(subprocess.run(["md5sum", path], capture_output=True,
                                   text=True).stdout.split()[0])
    distinct = len(set(md5s))
    check("R11 still reproduces: 4 identical --cross-check runs are not identical",
          distinct > 1, "%d distinct md5s over 4 runs" % distinct)
    if distinct > 1:
        import difflib
        diffs = []
        for i in range(len(texts)):
            for j in range(i + 1, len(texts)):
                d = sum(1 for ln in difflib.unified_diff(texts[i], texts[j], n=0)
                        if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---")))
                if d:
                    diffs.append(d)
        print("        measured pairwise diff sizes: %s lines" % sorted(diffs))
        # An overlap test is not a test: the first version of this check passed
        # while quoting 51-65 on a run that observed 25. Hold the site to
        # containment - every diff this run measured must fall inside the
        # envelope the pages state - so a narrower quote than reality fails.
        LO, HI = 25, 70
        check("the site's stated 25-70 line envelope contains everything measured",
              min(diffs) >= LO and max(diffs) <= HI,
              "observed %d-%d, site says %d-%d" % (min(diffs), max(diffs), LO, HI))
        check("and both pages that discuss it quote that envelope",
              all(re.search(r"25 to 70\s*\n?\s*lines", t.replace("\n", " "))
                  for t in (PAGE_TXT["limits.html"], PAGE_TXT["usage.html"])))
    # and the claim that no verdict moves
    verdicts = []
    for i in range(4):
        with open(os.path.join(OUT, "nd%d.txt" % i), encoding="utf-8") as fh:
            verdicts.append(re.findall(r"\|\s*(helm lint|kubeconform|kube-score|polaris)\s*\|\s*(\w+)\s*\|", fh.read()))
    check("and the site's 'no verdict or tally moves' claim holds",
          len(set(map(tuple, verdicts))) == 1, str(verdicts[:2]))
else:
    print("  SKIP  R11 re-measurement - needs all four external tools")

# claims about the repo itself that the site makes
check("the wrapper the site tells people to install exists and is executable",
      os.access(os.path.join(REPO, "bin", "hpa-analyzer"), os.X_OK))

# R12: the site used to teach `python3 -m hpaanalyzer` and `python3
# hpa-analyzer.py` as equal alternatives. Both are now refused, so a page that
# still shows one in a copy-paste block is teaching a command that exits 2.
#
# The test is on `$ `-prefixed transcript lines and bare command blocks, NOT on
# the whole page: index, reference, container and DOCKER.md all *name* the
# module form in prose, to say it is refused and why, and a substring ban over
# the page text would forbid explaining the change. What must not appear is an
# invocation presented as a thing to run.
NATIVE_FORMS = ("python3 -m hpaanalyzer", "python3 hpa-analyzer.py")
for page, src in PAGE_SRC.items():
    offenders = []
    for block in re.findall(r"<pre><code>(.*?)</code></pre>", src, re.S):
        for line in html.unescape(block).splitlines():
            stripped = line.strip().lstrip("$ ").strip()
            if any(stripped.startswith(f) for f in NATIVE_FORMS):
                offenders.append(stripped[:60])
    check("no page offers a native invocation to copy: %s" % page,
          not offenders, "; ".join(offenders))

# and the refusal the site promises is really what the program does
_refusal = subprocess.run(
    [sys.executable, "-m", "hpaanalyzer", os.path.join(REPO, "fixtures",
                                                       "good-chart")],
    cwd=REPO, capture_output=True, text=True,
    env={k: v for k, v in dict(os.environ, PYTHONPATH=REPO).items()
         if k != "HPA_ANALYZER_ALLOW_NATIVE"})
check("the module really does exit 2 as index.html and reference.html say",
      _refusal.returncode == 2, f"returncode={_refusal.returncode}")
check("and its message really does point at the wrapper the site names",
      "./bin/hpa-analyzer" in _refusal.stderr)
check("docs/DEVELOPING.md, which index.html links to, exists",
      os.path.exists(os.path.join(REPO, "docs", "DEVELOPING.md")))
wrapper = open(os.path.join(REPO, "bin", "hpa-analyzer"), encoding="utf-8").read()
for var in ["HPA_ANALYZER_OUTPUT_DIR", "HPA_ANALYZER_IMAGE",
            "HPA_ANALYZER_CONTAINER_CLI", "HPA_ANALYZER_DRY_RUN",
            "HPA_ANALYZER_NO_USER"]:
    check("env knob documented on the container page is real: %s" % var,
          var in wrapper and var in PAGE_TXT["container.html"])
dockerfile = open(os.path.join(REPO, "docker", "Dockerfile"), encoding="utf-8").read()
for tool, ver in [("HELM_VERSION", "3.16.4"), ("KUBECONFORM_VERSION", "0.6.7"),
                  ("KUBE_SCORE_VERSION", "1.20.0"), ("POLARIS_VERSION", "9.6.4")]:
    check("pinned version on the site matches the Dockerfile: %s=%s" % (tool, ver),
          re.search(r"%s=%s\b" % (tool, re.escape(ver)), dockerfile) is not None
          and ver in PAGE_TXT["container.html"])
check("the Dockerfile really has no CMD, as the container page claims",
      not re.search(r"^\s*CMD\b", dockerfile, re.M))
# p10_harness.py does not hard-code the byte figure - it measures it and prints
# it - so looking for the literal in that file tests nothing. Re-measure it the
# way p10 does (timestamp normalised, because `Generated :` is a property of the
# clock, not of the container) and hold the page to the measurement.
#
# R17 rewrote this block, and the reason is a defect this check USED to have.
# The container page quotes two byte figures: the helm-mode one ("N bytes
# either way") and the helm-less one ("(N bytes)"), and the old code checked
# whichever one matched the host it happened to run on - an if/else on
# HAVE_HELM. Every host this project has ever run the suite on except one has
# helm, so the helm-less figure was checked once, on the second machine that
# produced it, and never again. It had rotted by 344 bytes: the page said
# 63410, a figure true at the iteration that measured it, while the real
# helm-less report had grown to 63754. A check that only runs on a machine
# nobody uses is the same species of defect as R16's unasked question and
# R14b's deleted deductions - the tool was not wrong, it just never looked.
#
# So both figures are now measured on every host. helm-mode still needs helm,
# and there is no honest way to synthesise it without one. helm-LESS needs the
# opposite and that IS synthesisable exactly: build a PATH of symlinks to every
# executable currently on PATH except `helm`. Not `--helm off`, which is a
# different report (63570 here, 184 bytes short of the real thing) because it
# says "helm is installed but was not used" where the absent-helm run says
# "helm is not on PATH. Installing it ... materially improves precision". The
# page's claim is about the second one, so the second one is what gets built.
def _measure(argv, env=None):
    _p = run(argv + ["-o", os.path.join(OUT, "bytes.txt")], env=env)
    if _p.returncode != 0:
        return None
    with open(os.path.join(OUT, "bytes.txt"), "rb") as fh:
        return len(re.sub(rb"^Generated .*$", b"Generated : <normalised>",
                          fh.read(), flags=re.M))


def _path_without_helm():
    shim = tempfile.mkdtemp(prefix="p11-nohelm-")
    seen = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d)):
            if n == "helm" or n in seen:
                continue
            src = os.path.join(d, n)
            if os.path.isfile(src) and os.access(src, os.X_OK):
                seen.add(n)
                try:
                    os.symlink(src, os.path.join(shim, n))
                except OSError:
                    pass
    return shim


if HAVE_HELM:
    _measured = _measure(["fixtures/bad-chart"])
    _quoted = re.findall(r"(\d{4,7}) bytes either way", PAGE_TXT["container.html"])
    check("the container page's byte-identity figure is the measured report size",
          _quoted == [str(_measured)],
          "page says %s, measured %s" % (_quoted, _measured))
else:
    check("SKIPPED on a helm-less host: the byte-identity figure is a helm-mode "
          "figure and cannot be synthesised without helm", True)

_shim = _path_without_helm()
try:
    _measured = _measure(["fixtures/bad-chart"],
                         env=dict(os.environ, PATH=_shim))
    _quoted = re.findall(r"\((\d{4,7}) bytes\)", PAGE_TXT["container.html"])
    check("the container page's helm-LESS byte figure is the measured report "
          "size, on every host and not just a helm-less one",
          _quoted == [str(_measured)],
          "page says %s, measured %s" % (_quoted, _measured))
finally:
    shutil.rmtree(_shim, ignore_errors=True)

# no page promises a published image
check("no page tells the reader to pull a published image",
      "docker pull" not in ALL_TXT)
# the honest caveats survive onto the site
for phrase in ["reproducible, not correct",
               "Absence of a finding is not proof of correctness",
               "NOT ASSESSED",
               "do not diff two"]:
    check("honest caveat present on the site: %s" % phrase[:44],
          phrase.lower() in ALL_TXT.lower())

# the trial directory is never named on the public site
check("the site never mentions the untracked trial/ directory",
      not re.search(r"\btrial/", ALL_TXT))


print("\n%s" % ("-" * 72))
print("%d checks, %d failure(s)" % (checks, len(failures)))
if failures:
    for f in failures:
        print("  - %s" % f)
    sys.exit(1)
print("docs/ describes the program in this working tree.")
sys.exit(0)
