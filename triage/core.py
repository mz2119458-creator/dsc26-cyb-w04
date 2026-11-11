from dataclasses import dataclass, field
from datetime import date
import json
import hashlib
import re

SEVERITIES = ["info", "low", "medium", "high", "critical"]

@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: str
    cwe: int | None
    message: str
    code: str

@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted(list({f.tool for f in self.findings}))

    @property
    def fingerprints(self) -> list[str]:
        return sorted([fingerprint(f) for f in self.findings])

@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str

def normalize_path(raw: str, project: str) -> str:
    raw = raw.replace('\\', '/')
    if raw.startswith('file://'):
        raw = raw[7:]
    segments = [s for s in raw.split('/') if s and s != '.']
    if project in segments:
        last_idx = len(segments) - 1 - segments[::-1].index(project)
        segments = segments[last_idx + 1:]
    return '/'.join(segments)

def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    key = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

def load_semgrep_sarif(path, project: str) -> list[Finding]:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    findings = []
    for run in data.get('runs', []):
        driver = run.get('tool', {}).get('driver', {})
        rules_list = driver.get('rules', [])
        rules_map = {r.get('id'): r for r in rules_list if 'id' in r}
        results = run.get('results', [])
        for res in results:
            rule_id = res.get('ruleId')
            rule = rules_map.get(rule_id, {})
            msg_text = res.get('message', {}).get('text', '')
            
            props = rule.get('properties', {})
            sec_sev = props.get('security-severity')
            severity = None
            if sec_sev is not None:
                try:
                    val = float(sec_sev)
                    if 0.0 < val <= 10.0:
                        if val >= 9.0:
                            severity = "critical"
                        elif val >= 7.0:
                            severity = "high"
                        elif val >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                except (ValueError, TypeError):
                    pass
            
            if severity is None:
                lvl = res.get('level')
                if not lvl:
                    lvl = rule.get('defaultConfiguration', {}).get('level')
                if not lvl:
                    lvl = 'warning'
                lvl_lower = str(lvl).lower()
                mapping = {'error': 'high', 'warning': 'medium', 'note': 'low', 'none': 'info'}
                severity = mapping.get(lvl_lower, 'medium')

            cwe = None
            tags = props.get('tags', [])
            for tag in tags:
                m = re.search(r'CWE-(\d+)', tag)
                if m:
                    cwe = int(m.group(1))
                    break
            
            norm_p = ''
            line = 1
            code = ''
            locations = res.get('locations', [])
            if locations:
                phys = locations[0].get('physicalLocation', {})
                artifact = phys.get('artifactLocation', {})
                uri = artifact.get('uri', '')
                norm_p = normalize_path(uri, project)
                region = phys.get('region', {})
                line = region.get('startLine', 1)
                snippet = region.get('snippet', {}).get('text', '')
                if snippet:
                    code = snippet.splitlines()[0] if snippet.splitlines() else ''

            findings.append(Finding(
                tool="semgrep",
                rule_id=rule_id or "",
                path=norm_p,
                line=line,
                severity=severity,
                cwe=cwe,
                message=msg_text,
                code=code
            ))
    return findings

def load_bandit(path, project: str) -> list[Finding]:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    findings = []
    results = data.get('results', [])
    for res in results:
        rule_id = res.get('test_id', '')
        filename = res.get('filename', '')
        norm_p = normalize_path(filename, project)
        line = res.get('line_number', 1)
        message = res.get('issue_text', '')
        
        issue_sev = str(res.get('issue_severity', '')).upper()
        sev_map = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
        base_sev = sev_map.get(issue_sev, 'info')
        
        issue_conf = str(res.get('issue_confidence', '')).upper()
        sev_idx = SEVERITIES.index(base_sev)
        if issue_conf == 'LOW':
            sev_idx = max(0, sev_idx - 1)
        severity = SEVERITIES[sev_idx]
        
        issue_cwe = res.get('issue_cwe', {})
        cwe_id = issue_cwe.get('id') if isinstance(issue_cwe, dict) else None
        cwe = int(cwe_id) if cwe_id is not None and str(cwe_id).isdigit() else None
        
        code_field = res.get('code', '')
        code = ''
        for cl in code_field.splitlines():
            m = re.match(r'^\s*(\d+)\s+(.*)$', cl)
            if m and int(m.group(1)) == line:
                code = m.group(2)
                break
        
        findings.append(Finding(
            tool="bandit",
            rule_id=rule_id,
            path=norm_p,
            line=line,
            severity=severity,
            cwe=cwe,
            message=message,
            code=code
        ))
    return findings

def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    eq_key = f"{f.tool}:{f.rule_id}"
    if equivalences and eq_key in equivalences:
        return equivalences[eq_key]
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return f"{f.tool}:{f.rule_id}"

def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    equivalences = equivalences or {}
    groups_dict = {}
    for f in findings:
        key = issue_key(f, equivalences)
        group_key = (f.path, f.line, key)
        if group_key not in groups_dict:
            groups_dict[group_key] = []
        groups_dict[group_key].append(f)
    
    groups = []
    for (path, line, key), member_findings in groups_dict.items():
        sorted_members = sorted(member_findings, key=lambda x: (x.tool, x.rule_id, x.path, x.line, x.code))
        max_sev_idx = max(SEVERITIES.index(f.severity) for f in sorted_members)
        max_sev = SEVERITIES[max_sev_idx]
        groups.append(Group(
            key=key,
            path=path,
            line=line,
            severity=max_sev,
            findings=sorted_members
        ))
    
    groups.sort(key=lambda g: (-SEVERITIES.index(g.severity), g.path, g.line, g.key))
    return groups

def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid = []
    invalid = []
    for entry in entries:
        if not isinstance(entry, dict):
            invalid.append(entry)
            continue
        fp = entry.get('fingerprint')
        reason = entry.get('reason')
        by = entry.get('by')
        expires_str = entry.get('expires')
        
        fp_ok = isinstance(fp, str) and len(fp) == 64 and all(c in '0123456789abcdef' for c in fp)
        reason_ok = isinstance(reason, str) and len(reason.strip()) >= 10
        by_ok = isinstance(by, str) and by.strip() != ''
        
        expires_date = None
        if isinstance(expires_str, str):
            try:
                expires_date = date.fromisoformat(expires_str)
            except ValueError:
                pass
        
        if fp_ok and reason_ok and by_ok and expires_date is not None:
            valid.append(Suppression(
                fingerprint=fp,
                reason=reason,
                expires=expires_date,
                by=by
            ))
        else:
            invalid.append(entry)
    return valid, invalid

def apply_suppressions(groups: list[Group], suppressions: list[Suppression], today: date) -> tuple[list[Group], list[Group]]:
    active_fps = {s.fingerprint for s in suppressions if s.expires >= today}
    active = []
    suppressed = []
    for g in groups:
        is_suppressed = any(fingerprint(f) in active_fps for f in g.findings)
        if is_suppressed:
            suppressed.append(g)
        else:
            active.append(g)
    return active, suppressed

def diff_baseline(groups: list[Group], baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]:
    new_groups = []
    existing_groups = []
    for g in groups:
        if any(fingerprint(f) in baseline for f in g.findings):
            existing_groups.append(g)
        else:
            new_groups.append(g)
    
    group_fps = {fingerprint(f) for g in groups for f in g.findings}
    fixed = sorted(list(baseline - group_fps))
    return new_groups, existing_groups, fixed

def gate(new_active: list[Group], fail_on: str) -> bool:
    fail_idx = SEVERITIES.index(fail_on.lower())
    for g in new_active:
        if SEVERITIES.index(g.severity) >= fail_idx:
            return False
    return True
