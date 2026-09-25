"""Import Immunefi-style Markdown reports into the tracker's vulnerability reports.

A report file is named after its ID (`SF-C02-....md`, or with --id-prefix `01-....md`, `01a-....md`, `00-1a1-....md` or
`2025-10-20-4ed28508-....md`, the fix date and commit). Files named only by fix date (`2025-10-20-....md`)
are numbered in date order. A report has a `# Title` heading, a header of `| **Label** | value |` or
`| Label | value |` table rows or `**Label:** value` lines, and `## ` sections. From the header:
- Severity: the first severity word (Critical, High, ...) is the severity. Without a Severity row, a `**Proposed severity:** ...` line in the
  body is used. The impact comes from an "Impact (Immunefi)", "Impact
  category (Immunefi)", "Immunefi impact category" or "Impact category" row, or else from the first quoted text in the Severity row.
- Target (or Component, or Asset / Component), Fixed in (or Fixed on) and Fix commit(s) fill the target,
  date and fix link; the date comes from the Fix commit(s) row when there is no Fixed in row. Without either
  row, the README index's Fix commit(s) column is used.
  A fix given only as a commit hash (or, failing that, "PR #N") is linked with --repo-url. A row starting
  "Not fixed" gives no fix link.
- An "Asset type" row starting with a report type (e.g. "Smart Contract") sets the report type instead of
  --report-type.
- Every other row becomes an extra detail row.
A README.md in the folder can add to numbered reports: columns of an index table whose first column
is `#` (or `Report`, linking to the report file) become detail rows, and `- **#01:** ...` lines become severity notes.
Sections named like Immunefi's template fill the report. "Recommendation / Fix", "Recommendation" and
"The Fix" fill the recommendation, and any other section becomes an extra section before the description
(when it comes before the first section after the brief) or after the report.

Reports whose title already exists are not created again, so the import can be re-run. A re-run adds
missing tags and fills in dates. Cross-references between reports (links to another report file, or a
bare ID such as `SF-C01`) become links to the imported report pages. The report date is the date in the file
name, or the first date in the "Fixed in"/"Fixed on" row, or else the merge date of the fix pull request (or the fix commit's
date) on GitHub (set GITHUB_TOKEN to avoid the unauthenticated rate limit).

    python scripts/import_reports.py reports --id-prefix SEI --tag Sei --program-id 353 --repository-id 148
"""
import argparse
import os
import re
from pathlib import Path
import httpx

SECTIONS = {'Brief/Intro': 'brief', 'Brief / Intro': 'brief', 'Summary': 'brief', 'Summary / Brief': 'brief', 'Vulnerability Details': 'vulnerability_details',
            'Impact Details': 'impact_details', 'Impact': 'impact_details', 'Impact (had it shipped)': 'impact_details',
            'References': 'references', 'Proof of Concept': 'proof_of_concept', 'Attack Scenario / Proof of Concept': 'proof_of_concept', 'Recommendation / Fix': 'recommendation',
            'Recommendation': 'recommendation', 'The Fix': 'recommendation'}
SEVERITIES = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'informational': 'insight', 'insight': 'insight'}
IMPACT_ROWS = ('Impact (Immunefi)', 'Impact category (Immunefi)', 'Immunefi impact category', 'Impact category')
TARGET_ROWS = ('Target', 'Component', 'Asset / Component')
KNOWN_ROWS = {'Field', 'Severity', *TARGET_ROWS, *IMPACT_ROWS}
REPORT_TYPES = ('Smart Contract', 'Blockchain/DLT', 'Websites and Applications')
ROW = re.compile(r'^\| \*\*(.+?)\*\* \| (.*) \|$|^\*\*([^*]+?):\*\* (.*?)\s*$|^\| ([^|*]+?) \| (.*) \|$')
INDEX_SKIP = {'#', 'Report', 'Bug', 'Severity', 'Proposed severity', 'Fix commit'}
PROPOSED_SEVERITY = re.compile(r'\*\*Proposed severity:\s*(?:\*\*\s*\*\*)?([^*\n]+?)\.?\*\*')
NOTE = re.compile(r'<!--\s*reviewer note:\s*(.*?)\s*-->', re.S | re.I)
NAMED_ID = re.compile(r'^(SF-[CHMLI]\d{2})')
PAIRED_ID = re.compile(r'^(\d\d-\d{1,2}[a-z]?\d?)-')
NUMBERED_ID = re.compile(r'^(\d+[a-z]?)-(?!\d\d-\d\d-)')
DATED_ID = re.compile(r'^20\d\d-\d\d-\d\d-([0-9a-f]{7,40})-')
DATED_NAME = re.compile(r'^(20\d\d-\d\d-\d\d)-')
COMMIT = re.compile(r'\b(?=[0-9a-f]*\d)([0-9a-f]{7,40})\b')
FILE_LINK = re.compile(r'\[([^\]]+)\]\((?!https?://|/|#)([^)]+)\)')
BARE_ID = re.compile(r'(?<![\[\w/`-])(SF-[CHMLI]\d{2})(?![\w\]`-])')
TEXT_FIELDS = tuple(dict.fromkeys(SECTIONS.values()))

def report_id(filename: str, prefix: str | None) -> str | None:
    if found := NAMED_ID.match(filename):
        return found.group(1)
    if prefix and (found := DATED_ID.match(filename) or PAIRED_ID.match(filename) or NUMBERED_ID.match(filename)):
        return f'{prefix}-{found.group(1)}'
    return None

def report_keys(paths: list[Path], prefix: str | None) -> dict[str, str]:
    """Report ID by file name; files named only by date are numbered in date order."""
    keys, number = {}, 0
    for path in sorted(paths):
        if key := report_id(path.name, prefix):
            keys[path.name] = key
        elif prefix and DATED_NAME.match(path.name):
            number += 1
            keys[path.name] = f'{prefix}-{number:02d}'
    return keys

def split_sections(body: str) -> list[tuple[str, str]]:
    """(heading, content) for each `## ` section, ignoring headings inside code fences."""
    sections, heading, lines, fenced = [], None, [], False
    for line in body.splitlines():
        if line.lstrip().startswith('```'):
            fenced = not fenced
        if not fenced and line.startswith('## '):
            if heading is not None:
                sections.append((heading, '\n'.join(lines).strip()))
            heading, lines = line[3:].strip(), []
        elif heading is not None:
            lines.append(line)
    if heading is not None:
        sections.append((heading, '\n'.join(lines).strip()))
    return sections

def parse(path: Path, key: str, args: argparse.Namespace) -> dict:
    text = NOTE.sub('', path.read_text())
    title = text.splitlines()[0].removeprefix('# ').strip()
    if not title.startswith(key):
        title = f'{key}: {title}'
    header = text.split('\n## ', 1)[0]
    rows = {}
    for line in header.splitlines():
        if match := ROW.match(line):
            label, value = next((match.group(i), match.group(i + 1)) for i in (1, 3, 5) if match.group(i))
            rows[label.strip()] = value.strip()
    proposed = PROPOSED_SEVERITY.search(text)
    severity_text = (rows.get('Severity') or (proposed.group(1) if proposed else '')).strip()
    # "Low–Medium" counts as its first level; the full text is kept as a severity note.
    first = re.search(r'\b(?:critical|high|medium|low|informational|insight)\b', severity_text, re.I)
    severity = SEVERITIES.get(first.group(0).lower() if first else '', 'insight')
    quoted = re.search(r'"([^"]+)"', severity_text)
    impact = next((rows[label] for label in IMPACT_ROWS if rows.get(label)), '') or (quoted.group(1) if quoted else '')
    plain = re.fullmatch(r'\w+(?: — "[^"]+")?', severity_text)
    details = [] if plain or not severity_text.split(' ', 1)[1:] else [{'label': 'Severity note', 'value': severity_text}]
    asset = rows.get('Asset type', '')
    report_type = next((kind for kind in REPORT_TYPES if asset.startswith(kind)), args.report_type)
    # Keep the asset type only when it says more than the report type.
    details += [{'label': label, 'value': value.strip()} for label, value in rows.items()
                if label not in KNOWN_ROWS and not (label == 'Asset type' and value == report_type)]
    details += [{'label': 'Reviewer note', 'value': ' '.join(note.split())} for note in NOTE.findall(path.read_text())]
    details += args.readme_details.get(key, [])
    fields = {field: '' for field in TEXT_FIELDS}
    extra, placement = [], 'before'
    for heading, content in split_sections(text):
        if heading in SECTIONS and not fields[SECTIONS[heading]]:
            fields[SECTIONS[heading]] = content
            placement = 'before' if SECTIONS[heading] == 'brief' else 'after'
        elif content:
            extra.append({'title': heading, 'body': content, 'placement': placement})
    fixed = rows.get('Fixed in') or rows.get('Fixed on') or ''
    indexed = next((row['value'] for row in args.readme_details.get(key, []) if row['label'].startswith('Fix commit')), '')
    links = (rows.get('Fix commit(s)') or rows.get('Fix commit') or indexed) + ' ' + fixed
    found = (re.search(r'https://github\.com/[\w.-]+/[\w.-]+/pull/\d+', links)
             or re.search(r'https://github\.com/[\w.-]+/[\w.-]+/commit/\w+', links))
    fix = found.group(0) if found else None
    if not fix and args.repo_url and not fixed.startswith('Not fixed'):
        # A dated file is named after the fix commit, which is not always the first one listed (e.g. after a revert).
        named = DATED_ID.match(path.name)
        pull, commit = re.search(r'\bPR #(\d+)', links), named or COMMIT.search(links)
        # Prefer the commit: PR numbers can belong to a private repository the public one was mirrored from.
        fix = f'{args.repo_url}/commit/{commit.group(1)}' if commit else f'{args.repo_url}/pull/{pull.group(1)}' if pull else None
    date = DATED_NAME.match(path.name) or re.search(r'\b(20\d\d-\d\d-\d\d)\b', fixed or links)
    return {'title': title, 'severity': severity, 'report_type': report_type,
            'target': next((rows[label] for label in TARGET_ROWS if rows.get(label)), '').replace('`', '').strip() or None,
            'impacts': [impact] if impact else [], **fields, 'details': details, 'extra_sections': extra, 'tags': args.tag,
            'fix_url': fix, 'source_url': None, 'reported_at': date.group(1) if date else None,
            'program_id': args.program_id, 'repository_id': args.repository_id}

def link_reports(report: dict, pages: dict[str, int], keys: dict[str, str]) -> dict:
    """Point links to other report files at their imported pages; drop links to files that were not imported."""
    def file_link(match: re.Match) -> str:
        label, target = match.groups()
        key = keys.get(Path(target.split('#')[0]).name)
        return f'[{label}](/vulnerabilities/{pages[key]})' if key in pages else label
    def bare(match: re.Match) -> str:
        return f'[{match.group(1)}](/vulnerabilities/{pages[match.group(1)]})' if match.group(1) in pages else match.group(1)
    def rewrite(value: str) -> str:
        # Leave code blocks alone so identifiers inside them stay literal.
        parts = re.split(r'(```.*?```)', value, flags=re.S)
        return ''.join(part if part.startswith('```') else BARE_ID.sub(bare, FILE_LINK.sub(file_link, part)) for part in parts)
    return {**report, **{field: rewrite(report[field]) for field in TEXT_FIELDS},
            'details': [{**row, 'value': rewrite(row['value'])} for row in report['details']],
            'extra_sections': [{**section, 'body': rewrite(section['body'])} for section in report['extra_sections']]}

def fix_date(github: httpx.Client, fix_url: str | None) -> str | None:
    """When the fix landed: the pull request's merge date, or the commit's date."""
    found = re.match(r'https://github\.com/([\w.-]+/[\w.-]+)/(pull|commit)/(\w+)', fix_url or '')
    if not found:
        return None
    repo, kind, ref = found.groups()
    response = github.get(f'/repos/{repo}/pulls/{ref}' if kind == 'pull' else f'/repos/{repo}/commits/{ref}')
    if not response.is_success:
        return None
    data = response.json()
    landed = data.get('merged_at') if kind == 'pull' else data.get('commit', {}).get('committer', {}).get('date')
    return landed[:10] if landed else None

def index_key(cell: str, prefix: str) -> str | None:
    """The report ID in an index table's first cell: a number, or a link to the report file."""
    if re.fullmatch(r'\d+[a-z]?', cell):
        return f'{prefix}-{cell}'
    link = re.fullmatch(r'\[[^\]]*\]\(([^)]+)\)', cell)
    return report_id(Path(link.group(1)).name, prefix) if link else None

def readme_details(folder: Path, prefix: str | None) -> dict[str, list[dict]]:
    """Detail rows for numbered reports from the folder README's index table and severity notes."""
    readme = folder / 'README.md'
    if not prefix or not readme.exists():
        return {}
    found: dict[str, list[dict]] = {}
    columns: list[str] = []
    for line in readme.read_text().splitlines():
        cells = [cell.strip() for cell in line.strip().strip('|').split('|')] if line.startswith('|') else []
        if not cells:
            columns = []
        elif cells[0] in ('#', 'Report'):
            columns = cells
        elif columns and (key := index_key(cells[0], prefix)) and len(cells) == len(columns):
            found.setdefault(key, []).extend(
                {'label': label.rstrip('?'), 'value': value} for label, value in zip(columns, cells) if label not in INDEX_SKIP and value)
        if note := re.match(r'^- \*\*(#\d+(?:(?:,| and) #\d+)*):\*\* (.+)$', line):
            for number in re.findall(r'#(\d+)', note.group(1)):
                found.setdefault(f'{prefix}-{number}', []).append({'label': 'Severity note', 'value': note.group(2)})
    return found

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--api', default='http://bug-bounty-tracker/api')
    parser.add_argument('--report-type', default='Blockchain/DLT')
    parser.add_argument('--id-prefix', help='ID for numbered files: --id-prefix SEI turns 01-....md into SEI-01')
    parser.add_argument('--tag', action='append', default=[], help='tag every report; repeat for several tags')
    parser.add_argument('--program-id', type=int)
    parser.add_argument('--repository-id', type=int)
    parser.add_argument('--repo-url', help='GitHub repository URL used to link fixes given as a bare commit hash or PR number')
    args = parser.parse_args()
    args.readme_details = readme_details(args.folder, args.id_prefix)
    keys = report_keys(list(args.folder.glob('*.md')), args.id_prefix)
    reports = {key: parse(args.folder / name, key, args) for name, key in keys.items()}
    token = os.environ.get('GITHUB_TOKEN')
    with httpx.Client(base_url='https://api.github.com', timeout=30, headers={'Authorization': f'Bearer {token}'} if token else {}) as github:
        for report in reports.values():
            report['reported_at'] = report['reported_at'] or fix_date(github, report['fix_url'])
    with httpx.Client(base_url=args.api, timeout=30) as client:
        pages, created, updated = {}, [], []
        for key, report in reports.items():
            existing = client.get('/vulnerabilities', params={'search': report['title'], 'limit': 100}).raise_for_status().json()['items']
            match = next((item for item in existing if item['title'] == report['title']), None)
            if match:
                pages[key] = match['id']
                # Fill in what an earlier run could not, keeping any edits made since.
                changes = {'tags': match['tags'] + [tag for tag in args.tag if tag not in match['tags']],
                           'reported_at': match['reported_at'] or report['reported_at']}
                if any(match[field] != value for field, value in changes.items()):
                    client.put(f'/vulnerabilities/{match["id"]}', json={**match, **changes}).raise_for_status()
                    updated.append(key)
                continue
            response = client.post('/vulnerabilities', json=report)
            if response.is_error:
                raise SystemExit(f'{key}: {response.status_code} {response.text}')
            pages[key] = response.json()['id']
            created.append(key)
        for key in created:
            linked = link_reports(reports[key], pages, keys)
            if linked != reports[key]:
                client.put(f'/vulnerabilities/{pages[key]}', json=linked).raise_for_status()
    missing = sum(1 for report in reports.values() if not report['reported_at'])
    print(f'{len(created)} imported, {len(reports) - len(created)} already present ({len(updated)} updated), '
          f'{missing} without a date, {len(reports)} reports in {args.folder}')

if __name__ == '__main__':
    main()
