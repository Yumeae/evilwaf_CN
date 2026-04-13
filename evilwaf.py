#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import urllib3
import urwid

from core.interceptor import (
    Interceptor,
    ProxyRecord,
    create_interceptor,
    H2FingerprintRotator,
    EvilProxyPool,
)
from core.waf_detector import WAFDetector
from chemistry.origin_server_ip import OriginServerIPHunter, ReconReport, OriginResult
from chemistry.waf_vuln_scanner import (
    WAFVulnScanner,
    VulnFinding,
    VulnCategory,
    VulnSeverity,
    RequestOutcome,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION       = "2.5.0"
GITHUB_REPO   = "matrixleons/evilwaf"
BAD_CODES     = {400, 403, 405, 429, 500, 502, 503}

SEVERITY_COLOR = {
    VulnSeverity.CRITICAL: "\033[1;31m",
    VulnSeverity.HIGH:     "\033[0;31m",
    VulnSeverity.MEDIUM:   "\033[0;33m",
    VulnSeverity.LOW:      "\033[0;36m",
    VulnSeverity.INFO:     "\033[0;37m",
}
RESET = "\033[0m"


def _check_latest_version() -> Optional[str]:
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
            timeout=5,
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp.status_code == 200:
            tag = resp.json().get("tag_name", "").lstrip("v")
            return tag if tag else None
    except Exception:
        pass
    return None


def _print_version_check():
    latest = _check_latest_version()
    if latest is None:
        print(f"[*] 版本     : v{VERSION}")
        return
    if latest != VERSION:
        print(f"[*] 版本     : v{VERSION}")
        print(f"[!] 发现新版本: v{latest}")
        print(f"[!] 更新地址  : https://github.com/{GITHUB_REPO}/releases/latest")
    else:
        print(f"[*] 版本     : v{VERSION}  (已是最新)")


def _fmt_size(body: bytes) -> str:
    n = len(body) if body else 0
    if n < 1024:
        return f"{n}B"
    elif n < 1048576:
        return f"{n/1024:.1f}K"
    return f"{n/1048576:.1f}M"


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{int(seconds//60)}m{seconds%60:.0f}s"


def _detect_waf(target_url: str) -> Optional[str]:
    det = WAFDetector()
    try:
        r = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
        found = det.detect_all(
            response_body=r.text,
            headers=dict(r.headers),
            cookies={k: v for k, v in r.cookies.items()},
            status_code=r.status_code,
        )
        return ", ".join(found) if found else None
    except Exception:
        return None


def _hunt_origin_ip_verbose(target: str) -> Optional[str]:
    parsed = urlparse(target)
    domain = parsed.hostname or parsed.netloc

    print(f"\n[*] 源站 IP 探测已启动，目标: {domain}")
    print(f"[*] 并行启动以下扫描器:\n")

    scanner_names = [
        "dns_history", "ssl_certificate", "subdomain_enum", "dns_misconfig",
        "cloud_leak", "github_leak", "http_header_leak", "favicon_hash",
        "asn_range", "censys", "urlscan", "wayback", "greynoise",
    ]
    for name in scanner_names:
        print(f"    > {name}")
    print()

    seen_ips: Dict[str, Dict] = {}
    lock     = threading.Lock()
    start_ts = time.time()

    def print_ip_found(result: OriginResult, is_new: bool):
        elapsed      = time.time() - start_ts
        tag          = "NEW" if is_new else "UPD"
        verified_str = ""
        if result.verified:
            parts = []
            if result.cert_verified:
                parts.append("cert")
            if result.http_verified:
                parts.append("http")
            verified_str = f" verified={'+'.join(parts)}"
        cross_str = f" sources={result.cross_source_count}" if result.cross_source_count > 1 else ""
        print(
            f"  [{tag}] {result.ip:<18}"
            f" conf={result.confidence:.0%}"
            f" src={result.source}"
            f"{cross_str}{verified_str}"
            f" t={elapsed:.1f}s"
        )

    class VerboseHunter(OriginServerIPHunter):
        async def hunt(self) -> ReconReport:
            report_start  = time.monotonic()
            loop          = asyncio.get_event_loop()
            vendor, names = await loop.run_in_executor(None, self._waf_resolver.detect)
            self._report.waf_vendor = vendor
            self._report.waf_names  = names
            if names:
                print(f"  [WAF] 已检测到: {', '.join(names)}\n")

            async def run_scanner(scanner):
                scanner_name = type(scanner).__name__
                try:
                    results        = await scanner.scan()
                    if results:
                        print(f"  [扫描器:{scanner_name}] 发现 {len(results)} 个候选 IP")
                    newly_verified = await self._correlator.feed(results, self._report)
                    for r in results:
                        with lock:
                            is_new = r.ip not in seen_ips
                            if is_new:
                                seen_ips[r.ip] = {"conf": r.confidence, "sources": 1}
                            else:
                                seen_ips[r.ip]["sources"] += 1
                        print_ip_found(r, is_new)
                    if newly_verified:
                        print(f"\n  [交叉验证] {len(newly_verified)} 个 IP 触发了早期验证:")
                        for r in newly_verified:
                            print_ip_found(r, False)
                        print()
                except Exception as e:
                    print(f"  [扫描器:{scanner_name}] 错误: {e}")

            await asyncio.gather(*[run_scanner(s) for s in self._scanners])
            candidates = self._report.origin_candidates
            unverified = [c for c in candidates if not c.verified]

            if self._verify and unverified:
                print(f"\n  [验证] 对 {len(unverified)} 个未验证 IP 进行最终验证...")
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=20) as ex:
                    verify_results = await asyncio.gather(
                        *[loop.run_in_executor(ex, self._verifier.verify, c.ip) for c in unverified],
                        return_exceptions=True,
                    )
                for i, vr in enumerate(verify_results):
                    if not isinstance(vr, tuple):
                        continue
                    ok, cert_ok, http_ok        = vr
                    unverified[i].verified      = ok
                    unverified[i].cert_verified = cert_ok
                    unverified[i].http_verified = http_ok
                    if ok:
                        bonus = 0.0
                        if cert_ok: bonus += 0.15
                        if http_ok: bonus += 0.05
                        unverified[i].confidence = min(unverified[i].confidence + bonus, 1.0)
                        print_ip_found(unverified[i], False)

            if self._enrich and candidates:
                print(f"\n  [丰富化] 正在为 {len(candidates)} 个候选 IP 补充 ASN/组织/端口数据...")
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=10) as ex:
                    await asyncio.gather(
                        *[loop.run_in_executor(ex, self._enricher.enrich, c) for c in candidates],
                        return_exceptions=True,
                    )

            self._report.verified_ips          = [r.ip for r in candidates if r.verified]
            self._report.total_sources_checked = len(self._scanners)
            self._report.duration              = time.monotonic() - report_start
            self._report._update_best()
            return self._report

    try:
        hunter = VerboseHunter(domain=domain, verify=True, enrich=True)
        loop   = asyncio.new_event_loop()
        report: ReconReport = loop.run_until_complete(hunter.hunt())
        loop.close()

        elapsed = time.time() - start_ts
        print(f"\n{'='*60}")
        print(f"  探测完成，耗时 {elapsed:.1f}s")
        print(f"  候选 IP 总数   : {len(report.origin_candidates)}")
        print(f"  已验证 IP 数   : {len(report.verified_ips)}")
        print()

        if report.sorted_candidates:
            print("  候选 IP（按置信度排序）:")
            for r in report.sorted_candidates[:10]:
                verified_tag = ""
                if r.verified:
                    parts = []
                    if r.cert_verified: parts.append("cert")
                    if r.http_verified: parts.append("http")
                    verified_tag = f" [已验证:{'+'.join(parts)}]"
                org_str     = f" 组织={r.org}"       if r.org     else ""
                country_str = f" 国家={r.country}"   if r.country else ""
                cross_str   = f" 来源数={r.cross_source_count}"
                print(
                    f"    {r.ip:<18}"
                    f" 置信度={r.confidence:.0%}"
                    f"{verified_tag}{cross_str}{org_str}{country_str}"
                )

        if report.best_candidate:
            best = report.best_candidate
            print(f"\n  最佳候选 IP    : {best.ip}")
            print(f"  置信度         : {best.confidence:.0%}")
            print(f"  来源           : {best.source}")
            print(f"  已验证         : {best.verified}")
            if best.org:     print(f"  组织           : {best.org}")
            if best.country: print(f"  国家           : {best.country}")
            if best.ports:   print(f"  开放端口       : {best.ports}")
            print(f"{'='*60}\n")
            return best.ip

        print(f"{'='*60}\n")
        print("[!] 未找到源站 IP")
    except Exception as e:
        print(f"[!] 探测失败: {e}")
    return None


def _print_scan_finding(finding: VulnFinding):
    color = SEVERITY_COLOR.get(finding.severity, "")
    tag   = "[已验证]" if finding.verified else "[未验证]"
    fp    = " [误报]" if finding.false_positive else ""
    print(f"\n  {color}[漏洞]{RESET} {finding.severity.value.upper()} {tag}{fp}")
    print(f"  层级      : {finding.layer or finding.category.value}")
    print(f"  类别      : {finding.category.value}")
    print(f"  标题      : {finding.title}")
    print(f"  置信度    : {finding.confidence:.0%}")
    print(f"  证据      : {len(finding.evidence)} 个请求通过 WAF")
    if finding.evidence:
        e = finding.evidence[0]
        print(f"  样本      : [{e.status_code}] {e.request.payload[:80]}")
        print(f"  编码      : {e.request.encoding}")
        print(f"  响应时间  : {e.response_time * 1000:.0f}ms")
    if finding.cve:
        print(f"  CVE       : {finding.cve}")
    print(f"  修复建议  : {finding.remediation}")
    print()


def _print_scan_progress(current: int, total: int, category: str,
                          scanner: WAFVulnScanner, start_ts: float):
    elapsed    = time.time() - start_ts
    stats      = scanner.get_stats()
    conf       = scanner.get_confidence()
    total_req  = stats.get("total_requests", 0)
    pass_rate  = stats.get("pass_rate", 0.0)
    block_rate = stats.get("block_rate", 0.0)
    rt         = stats.get("response_time", {})
    mean_ms    = rt.get("mean_ms", 0.0)
    p95_ms     = rt.get("p95_ms", 0.0)
    findings   = len([f for f in scanner.get_findings() if not f.false_positive])
    print(
        f"  [{current:>2}/{total}] {category:<30}"
        f"  请求={total_req:<5}"
        f"  通过={pass_rate:.0%}"
        f"  阻断={block_rate:.0%}"
        f"  置信={conf:.0%}"
        f"  响应={mean_ms:.0f}ms(p95={p95_ms:.0f}ms)"
        f"  漏洞={findings}"
        f"  耗时={elapsed:.0f}s"
    )


def _print_scan_summary(scanner: WAFVulnScanner, findings: List[VulnFinding],
                         elapsed: float):
    stats    = scanner.get_stats()
    waf_info = scanner.waf_info
    rt       = stats.get("response_time", {})
    by_cat   = stats.get("by_category", {})

    print(f"\n{'='*70}")
    print(f"  WAF 漏洞扫描 — 完成")
    print(f"{'='*70}")
    print(f"  检测到的 WAF   : {waf_info.get('waf', '未知')} {waf_info.get('version', '')}")
    print(f"  扫描耗时       : {elapsed:.1f}s")
    print(f"  请求总数       : {stats.get('total_requests', 0)}")
    print(f"  通过率         : {stats.get('pass_rate', 0):.1%}")
    print(f"  阻断率         : {stats.get('block_rate', 0):.1%}")
    print(f"  挑战率         : {stats.get('challenge_rate', 0):.1%}")
    print(f"  错误率         : {stats.get('error_rate', 0):.1%}")

    if rt:
        print(f"  响应时间       : 均值={rt.get('mean_ms',0):.0f}ms"
              f"  p95={rt.get('p95_ms',0):.0f}ms"
              f"  p99={rt.get('p99_ms',0):.0f}ms"
              f"  标准差={rt.get('std_ms',0):.0f}ms")

    if by_cat:
        print(f"\n  各层分析:")
        print(f"  {'层级':<30} {'通过':>6} {'阻断':>7} {'样本数':>8}")
        print(f"  {'-'*30} {'-'*6} {'-'*7} {'-'*8}")
        for cat, data in sorted(by_cat.items(),
                                 key=lambda x: x[1]["pass_rate"], reverse=True):
            print(
                f"  {cat:<30}"
                f"  {data['pass_rate']:.0%}"
                f"  {data['block_rate']:.0%}"
                f"  {data['sample_size']:>6}"
            )

    real = [f for f in findings if not f.false_positive]
    if real:
        print(f"\n  发现 ({len(real)} 项已验证):")
        print(f"  {'严重性':<10} {'置信度':>6} {'V':>3}  {'层级':<25} {'标题'}")
        print(f"  {'-'*10} {'-'*6} {'-'*3}  {'-'*25} {'-'*30}")
        for f in sorted(real, key=lambda x: x.confidence, reverse=True):
            color = SEVERITY_COLOR.get(f.severity, "")
            vt    = "V" if f.verified else " "
            print(
                f"  {color}{f.severity.value.upper():<10}{RESET}"
                f"  {f.confidence:.0%}"
                f"  [{vt}]"
                f"  {(f.layer or f.category.value):<25}"
                f"  {f.title}"
            )
    else:
        print(f"\n  未发现已验证的漏洞。")

    print(f"{'='*70}\n")


def _run_vuln_scanner_verbose(target: str, rps: float = 3.0,
                               output_dir: Optional[str] = None):
    print(f"\n[*] WAF 漏洞扫描器  —  EvilWAF v{VERSION}")
    print(f"[*] 目标   : {target}")
    print(f"[*] 速率   : {rps} 请求/秒")
    print(f"[*] 输出   : {output_dir or '自动'}\n")

    start_ts = time.time()
    scanner  = WAFVulnScanner(
        target=target,
        output_dir=output_dir,
        rps=rps,
        verify_findings=True,
    )

    def on_finding(finding: VulnFinding):
        _print_scan_finding(finding)

    def on_progress(current: int, total: int, category: str):
        _print_scan_progress(current, total, category, scanner, start_ts)

    print(f"  {'步骤':>5}  {'层级':<30}  {'请求':<5}  {'通过':<5}  {'阻断':<6}  {'置信':<5}  {'响应时间':<14}  {'漏洞'}")
    print(f"  {'-'*5}  {'-'*30}  {'-'*5}  {'-'*5}  {'-'*6}  {'-'*5}  {'-'*14}  {'-'*5}")

    findings = scanner.scan(on_finding=on_finding, on_progress=on_progress)
    _print_scan_summary(scanner, findings, time.time() - start_ts)


def _ask_connect_proxy(ip: str) -> bool:
    print(f"[?] 是否使用 {ip} 作为源站 IP 进行绕过？[y/n]: ", end="", flush=True)
    try:
        return input().strip().lower() == "y"
    except Exception:
        return False


def _row_palette_for_status(status_code: int) -> str:
    if status_code == 200:
        return 'tr_200'
    if status_code == 302:
        return 'tr_302'
    if status_code == 403:
        return 'tr_403'
    if status_code == 404:
        return 'tr_404'
    return 'tr_other_err'


class TorIPTable:
    def __init__(self, max_entries: int = 1000):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._max     = max_entries
        self._counter = 0

    def add(self, ip: str, duration: float, status: str = "Running"):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "nt": self._counter, "ip": ip,
                "duration": duration, "status": status, "ts": time.time(),
            })
            if len(self._entries) > self._max:
                self._entries.pop(0)

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def get_recent(self, n: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class TechniqueTable:
    def __init__(self):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._counter = 0

    def add(self, tls_id: str, tcp_profile: str, h2_profile: str):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "rq":  self._counter,
                "tls": tls_id      or "N/A",
                "tcp": tcp_profile or "N/A",
                "h2":  h2_profile  or "N/A",
            })
            if len(self._entries) > 100:
                self._entries.pop(0)

    def get_recent(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class SportTable:
    def __init__(self, max_entries: int = 500):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._max     = max_entries
        self._counter = 0

    def add(self, port: int, profile: str, success: bool):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "rq": self._counter, "port": port,
                "profile": profile, "success": success, "ts": time.time(),
            })
            if len(self._entries) > self._max:
                self._entries.pop(0)

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def get_recent(self, n: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class EvilProxyTable:
    def __init__(self, max_entries: int = 1000):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._max     = max_entries
        self._counter = 0

    def add(self, ip: str, port: int, latency: float, anonymous: bool, success: bool):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "rq": self._counter, "ip": ip, "port": port,
                "latency": latency, "anonymous": anonymous,
                "success": success, "ts": time.time(),
            })
            if len(self._entries) > self._max:
                self._entries.pop(0)

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def get_recent(self, n: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class VulnTable:
    def __init__(self, max_entries: int = 500):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._max     = max_entries
        self._counter = 0

    def add(self, finding: VulnFinding):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "rq":         self._counter,
                "category":   finding.category.value,
                "severity":   finding.severity.value,
                "title":      finding.title,
                "layer":      finding.layer or finding.category.value,
                "confidence": finding.confidence,
                "verified":   finding.verified,
                "fp":         finding.false_positive,
                "ts":         time.time(),
            })
            if len(self._entries) > self._max:
                self._entries.pop(0)

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def get_recent(self, n: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class TorIPScrollPanel:
    def __init__(self, tor_table: TorIPTable):
        self._tor_table  = tor_table
        self._walker     = urwid.SimpleFocusListWalker([])
        self._last_count = 0
        hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' 序号'))),
                ('fixed', 18, urwid.Text(('ws_hdr', 'IP 地址'))),
                ('fixed', 8,  urwid.Text(('ws_hdr', '时间'))),
                ('weight', 1, urwid.Text(('ws_hdr', '状态'))),
            ], dividechars=1),
            'ws_hdr',
        )
        self.widget = urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([('pack', hdr), ('weight', 1, urwid.ListBox(self._walker))]),
                title=" TOR IP 轮换 ", title_align='left',
            ),
            'ws_bg',
        )

    def refresh(self):
        entries = self._tor_table.get_all()
        if len(entries) == self._last_count:
            return
        for e in entries[self._last_count:]:
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_value', f' {str(e["nt"]).rjust(3)}'))),
                ('fixed', 18, urwid.Text(('ws_ip',    (e["ip"] or "N/A")[:17]))),
                ('fixed', 8,  urwid.Text(('ws_value', _fmt_duration(e["duration"])[:7]))),
                ('weight', 1, urwid.Text(('ws_ok',    e["status"][:9]))),
            ], dividechars=1)
            self._walker.append(urwid.AttrMap(cols, 'ws_bg'))
        self._last_count = len(entries)
        if self._walker:
            try: self._walker.set_focus(len(self._walker) - 1)
            except Exception: pass


class SportScrollPanel:
    def __init__(self, sport_table: SportTable):
        self._sport_table = sport_table
        self._walker      = urwid.SimpleFocusListWalker([])
        self._last_count  = 0
        hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' RQ'))),
                ('fixed', 8,  urwid.Text(('ws_hdr', '端口'))),
                ('fixed', 14, urwid.Text(('ws_hdr', '配置'))),
                ('weight', 1, urwid.Text(('ws_hdr', '状态'))),
            ], dividechars=1),
            'ws_hdr',
        )
        self.widget = urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([('pack', hdr), ('weight', 1, urwid.ListBox(self._walker))]),
                title=" 源端口 ", title_align='left',
            ),
            'ws_bg',
        )

    def refresh(self):
        entries = self._sport_table.get_all()
        if len(entries) == self._last_count:
            return
        for e in entries[self._last_count:]:
            st_attr = 'ws_ok' if e["success"] else 'ws_ind_block'
            st_text = 'OK'    if e["success"] else 'FAIL'
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_tech_rq',  f' {str(e["rq"]).rjust(3)}'))),
                ('fixed', 8,  urwid.Text(('ws_ip',       str(e["port"])))),
                ('fixed', 14, urwid.Text(('ws_tech_tcp', (e["profile"] or "N/A")[:13]))),
                ('weight', 1, urwid.Text((st_attr,        st_text))),
            ], dividechars=1)
            self._walker.append(urwid.AttrMap(cols, 'ws_bg'))
        self._last_count = len(entries)
        if self._walker:
            try: self._walker.set_focus(len(self._walker) - 1)
            except Exception: pass


class EvilProxyScrollPanel:
    def __init__(self, proxy_table: EvilProxyTable):
        self._proxy_table = proxy_table
        self._walker      = urwid.SimpleFocusListWalker([])
        self._last_count  = 0
        hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' RQ'))),
                ('fixed', 18, urwid.Text(('ws_hdr', 'IP 地址'))),
                ('fixed', 7,  urwid.Text(('ws_hdr', '端口'))),
                ('fixed', 7,  urwid.Text(('ws_hdr', '延迟'))),
                ('fixed', 5,  urwid.Text(('ws_hdr', '匿名'))),
                ('weight', 1, urwid.Text(('ws_hdr', '状态'))),
            ], dividechars=1),
            'ws_hdr',
        )
        self.widget = urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([('pack', hdr), ('weight', 1, urwid.ListBox(self._walker))]),
                title=" 代理池 ", title_align='left',
            ),
            'ws_bg',
        )

    def refresh(self):
        entries = self._proxy_table.get_all()
        if len(entries) == self._last_count:
            return
        for e in entries[self._last_count:]:
            st_attr   = 'ws_ok'  if e["success"]   else 'ws_ind_block'
            st_text   = 'OK'     if e["success"]    else 'FAIL'
            anon_attr = 'ws_ok'  if e["anonymous"]  else 'ws_value'
            anon_txt  = 'Y'      if e["anonymous"]  else 'N'
            lat_txt   = f'{int(e["latency"]*1000)}' if e["latency"] < 9999 else '---'
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_tech_rq', f' {str(e["rq"]).rjust(3)}'))),
                ('fixed', 18, urwid.Text(('ws_ip',      (e["ip"] or "N/A")[:17]))),
                ('fixed', 7,  urwid.Text(('ws_value',   str(e["port"])))),
                ('fixed', 7,  urwid.Text(('ws_value',   lat_txt[:6]))),
                ('fixed', 5,  urwid.Text((anon_attr,    anon_txt))),
                ('weight', 1, urwid.Text((st_attr,      st_text))),
            ], dividechars=1)
            self._walker.append(urwid.AttrMap(cols, 'ws_bg'))
        self._last_count = len(entries)
        if self._walker:
            try: self._walker.set_focus(len(self._walker) - 1)
            except Exception: pass


class VulnScrollPanel:
    _SEV_ATTR = {
        "critical": 'vuln_critical',
        "high":     'vuln_high',
        "medium":   'vuln_medium',
        "low":      'vuln_low',
        "info":     'ws_inactive',
    }

    def __init__(self, vuln_table: VulnTable):
        self._vuln_table = vuln_table
        self._walker     = urwid.SimpleFocusListWalker([])
        self._last_count = 0
        hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' RQ'))),
                ('fixed', 10, urwid.Text(('ws_hdr', '严重性'))),
                ('fixed', 6,  urwid.Text(('ws_hdr', '置信度'))),
                ('fixed', 4,  urwid.Text(('ws_hdr', '验证'))),
                ('fixed', 20, urwid.Text(('ws_hdr', '层级'))),
                ('weight', 1, urwid.Text(('ws_hdr', '标题'))),
            ], dividechars=1),
            'ws_hdr',
        )
        self.widget = urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([('pack', hdr), ('weight', 1, urwid.ListBox(self._walker))]),
                title=" WAF 漏洞 ", title_align='left',
            ),
            'ws_bg',
        )

    def refresh(self):
        entries = self._vuln_table.get_all()
        if len(entries) == self._last_count:
            return
        for e in entries[self._last_count:]:
            if e["fp"]:
                continue
            sev_attr = self._SEV_ATTR.get(e["severity"], 'ws_value')
            ver_txt  = "[V]" if e["verified"] else "[ ]"
            conf_txt = f'{e["confidence"]:.0%}'
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_tech_rq', f' {str(e["rq"]).rjust(3)}'))),
                ('fixed', 10, urwid.Text((sev_attr,      e["severity"][:9]))),
                ('fixed', 6,  urwid.Text(('ws_value',    conf_txt))),
                ('fixed', 4,  urwid.Text(('ws_ok',       ver_txt))),
                ('fixed', 20, urwid.Text(('ws_tech_tcp', e["layer"][:19]))),
                ('weight', 1, urwid.Text(('ws_value',    e["title"][:38]))),
            ], dividechars=1)
            self._walker.append(urwid.AttrMap(cols, 'ws_bg'))
        self._last_count = len(entries)
        if self._walker:
            try: self._walker.set_focus(len(self._walker) - 1)
            except Exception: pass


class ScannerStatsPanel:
    def __init__(self, scanner_ref: List):
        self._scanner_ref = scanner_ref
        self._text        = urwid.Text("")
        self.widget       = urwid.AttrMap(
            urwid.LineBox(
                urwid.Padding(self._text, left=1, right=1),
                title=" 扫描器统计 ", title_align='left',
            ),
            'ws_bg',
        )

    def refresh(self):
        if not self._scanner_ref:
            return
        scanner = self._scanner_ref[0]
        try:
            stats  = scanner.get_stats()
            conf   = scanner.get_confidence()
            finds  = len([f for f in scanner.get_findings() if not f.false_positive])
            total  = stats.get("total_requests", 0)
            pr     = stats.get("pass_rate", 0.0)
            br     = stats.get("block_rate", 0.0)
            cr     = stats.get("challenge_rate", 0.0)
            rt     = stats.get("response_time", {})
            mean   = rt.get("mean_ms", 0.0)
            p95    = rt.get("p95_ms", 0.0)
            p99    = rt.get("p99_ms", 0.0)
            self._text.set_text([
                ('ws_label',      ' 请求数   : '), ('ws_value',     f'{total}\n'),
                ('ws_label',      ' 通过      : '), ('ws_ok',        f'{pr:.1%}\n'),
                ('ws_label',      ' 阻断      : '), ('ws_ind_block', f'{br:.1%}\n'),
                ('ws_label',      ' 挑战      : '), ('ws_value',     f'{cr:.1%}\n'),
                ('ws_label',      ' 置信度   : '), ('ws_value',     f'{conf:.1%}\n'),
                ('ws_label',      ' 平均响应  : '), ('ws_value',     f'{mean:.0f}ms\n'),
                ('ws_label',      ' P95响应   : '), ('ws_value',     f'{p95:.0f}ms\n'),
                ('ws_label',      ' P99响应   : '), ('ws_value',     f'{p99:.0f}ms\n'),
                ('ws_label',      ' 漏洞数    : '), ('ws_ok',        f'{finds}'),
            ])
        except Exception:
            pass


class EvilWAFTUI:
    def __init__(
        self,
        server:               Interceptor,
        target_url:           Optional[str],
        tor_table:            TorIPTable,
        tech_table:           TechniqueTable,
        sport_table:          SportTable,
        proxy_table:          EvilProxyTable,
        vuln_table:           VulnTable,
        scanner_ref:          List,
        server_ip:            Optional[str] = None,
        waf_name:             Optional[str] = None,
        enable_tor:           bool = False,
        use_evil_proxy:       bool = False,
        enable_scanner:       bool = False,
        upstream_proxy_count: int  = 0,
    ):
        self.server               = server
        self.target_url           = target_url
        self.tor_table            = tor_table
        self.tech_table           = tech_table
        self.sport_table          = sport_table
        self.proxy_table          = proxy_table
        self.vuln_table           = vuln_table
        self.scanner_ref          = scanner_ref
        self.server_ip            = server_ip
        self.waf_name             = waf_name
        self.enable_tor           = enable_tor
        self.use_evil_proxy       = use_evil_proxy
        self.enable_scanner       = enable_scanner
        self.upstream_proxy_count = upstream_proxy_count

        self.traffic_data: List[ProxyRecord] = []
        self.selected_row  = 0
        self._auto_follow  = True
        self.loop: Optional[urwid.MainLoop] = None

        self._tor_panel:     Optional[TorIPScrollPanel]     = None
        self._sport_panel:   Optional[SportScrollPanel]     = None
        self._proxy_panel:   Optional[EvilProxyScrollPanel] = None
        self._vuln_panel:    Optional[VulnScrollPanel]      = None
        self._scanner_panel: Optional[ScannerStatsPanel]    = None

        self.palette = [
            ('header',        'black,bold',       'dark cyan'),
            ('status',        'black,bold',       'dark cyan'),
            ('tr_bg',         'white',            'black'),
            ('tr_even',       'light gray',       'black'),
            ('tr_odd',        'white',            'black'),
            ('tr_follow',     'black,bold',       'light cyan'),
            ('tr_selected',   'black,bold',       'light green'),
            ('tr_hdr',        'black,bold',       'dark cyan'),
            ('tr_pass',       'light green,bold', 'black'),
            ('tr_block',      'light red,bold',   'black'),
            ('tr_unkn',       'dark gray',        'black'),
            ('tr_time',       'dark cyan',        'black'),
            ('tr_host',       'white,bold',       'black'),
            ('tr_method',     'yellow',           'black'),
            ('tr_proto',      'light blue',       'black'),
            ('tr_200',        'dark red',         'black'),
            ('tr_302',        'black',            'white'),
            ('tr_403',        'yellow',           'dark red'),
            ('tr_404',        'white',            'brown'),
            ('tr_other_err',  'light red,bold',   'black'),
            ('ws_bg',         'black,bold',       'white'),
            ('ws_hdr',        'black,bold',       'dark cyan'),
            ('ws_label',      'black,bold',       'white'),
            ('ws_value',      'black,bold',       'white'),
            ('ws_ip',         'black,bold',       'white'),
            ('ws_ok',         'black,bold',       'white'),
            ('ws_tech_rq',    'black,bold',       'white'),
            ('ws_tech_tls',   'black,bold',       'white'),
            ('ws_tech_tcp',   'black,bold',       'white'),
            ('ws_tech_h2',    'black,bold',       'white'),
            ('ws_inactive',   'dark gray',        'white'),
            ('ws_ind_pass',   'black,bold',       'white'),
            ('ws_ind_block',  'black,bold',       'white'),
            ('ws_ind_unkn',   'dark gray',        'white'),
            ('vuln_critical', 'light red,bold',   'black'),
            ('vuln_high',     'light red',        'black'),
            ('vuln_medium',   'yellow',           'black'),
            ('vuln_low',      'light cyan',       'black'),
        ]
        self._build_ui()

    def _build_ui(self):
        self.traffic_walker = urwid.SimpleFocusListWalker([])
        traffic_listbox     = urwid.ListBox(self.traffic_walker)
        traffic_hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 10, urwid.Text(('tr_hdr', ' 时间'))),
                ('fixed', 20, urwid.Text(('tr_hdr', '主机'))),
                ('fixed', 6,  urwid.Text(('tr_hdr', '方法'))),
                ('fixed', 5,  urwid.Text(('tr_hdr', '状态'))),
                ('fixed', 6,  urwid.Text(('tr_hdr', '协议'))),
                ('fixed', 7,  urwid.Text(('tr_hdr', '大小'))),
                ('weight', 1, urwid.Text(('tr_hdr', '结果'))),
            ], dividechars=1),
            'tr_hdr',
        )
        self.follow_text = urwid.Text(('ws_ok', ' [跟踪] '))
        traffic_panel = urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([
                    ('pack',      traffic_hdr),
                    ('weight', 1, urwid.AttrMap(traffic_listbox, 'tr_bg')),
                    ('pack',      urwid.AttrMap(urwid.Padding(self.follow_text, left=1), 'tr_bg')),
                ]),
                title=" 流量监控 ", title_align='left',
            ),
            'tr_bg',
        )
        right = self._build_right()
        body  = urwid.Columns([
            ('weight', 3, traffic_panel),
            ('weight', 2, urwid.Pile(right)),
        ])
        self.status_text = urwid.Text("")
        footer = urwid.AttrMap(
            urwid.Padding(self.status_text, left=1, right=1),
            'status',
        )
        self.frame = urwid.Frame(
            header=self._make_header(),
            body=body,
            footer=footer,
        )
        self.loop = urwid.MainLoop(
            self.frame,
            palette=self.palette,
            unhandled_input=self._handle_input,
            handle_mouse=True,
        )
        self.loop.set_alarm_in(0.3, self._refresh)

    def _build_right(self) -> list:
        panels = []

        if self.enable_tor:
            self._tor_panel = TorIPScrollPanel(self.tor_table)
            panels.append(('weight', 2, self._tor_panel.widget))

        self.tech_walker = urwid.SimpleFocusListWalker([])
        tech_hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' RQ'))),
                ('fixed', 14, urwid.Text(('ws_hdr', 'TLS'))),
                ('fixed', 10, urwid.Text(('ws_hdr', 'TCP'))),
                ('weight', 1, urwid.Text(('ws_hdr', 'H2'))),
            ], dividechars=1),
            'ws_hdr',
        )
        panels.append(('weight', 1, urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([
                    ('pack',      tech_hdr),
                    ('weight', 1, urwid.ListBox(self.tech_walker)),
                ]),
                title=" 当前技术 ", title_align='left',
            ),
            'ws_bg',
        )))

        self.server_ip_text = urwid.Text("")
        if self.server_ip:
            panels.append(('pack', urwid.AttrMap(
                urwid.LineBox(
                    urwid.Padding(self.server_ip_text, left=1, right=1),
                    title=" 服务器 IP ", title_align='left',
                ),
                'ws_bg',
            )))

        self._sport_panel = SportScrollPanel(self.sport_table)
        panels.append(('weight', 2, self._sport_panel.widget))

        self._proxy_panel = EvilProxyScrollPanel(self.proxy_table)
        panels.append(('weight', 2, self._proxy_panel.widget))

        if self.enable_scanner:
            self._vuln_panel = VulnScrollPanel(self.vuln_table)
            panels.append(('weight', 3, self._vuln_panel.widget))
            self._scanner_panel = ScannerStatsPanel(self.scanner_ref)
            panels.append(('pack', self._scanner_panel.widget))

        return panels

    def _make_header(self) -> urwid.Widget:
        parsed  = urlparse(self.target_url or "")
        h       = parsed.netloc or "N/A"
        waf_p   = f" | WAF: {self.waf_name}"               if self.waf_name             else ""
        ip_p    = f" | 来源: {self.server_ip}"              if self.server_ip            else ""
        tor_p   = " | TOR: 开"                              if self.enable_tor           else ""
        proxy_p = f" | 代理: {self.upstream_proxy_count}"   if self.upstream_proxy_count else ""
        ep_p    = " | EvilProxy: 开"                        if self.use_evil_proxy       else ""
        scan_p  = " | 扫描器: 开"                           if self.enable_scanner       else ""
        return urwid.AttrMap(
            urwid.Text(
                ('header',
                 f" EvilWAF v{VERSION} | {h}{waf_p}{ip_p}{tor_p}{proxy_p}{ep_p}{scan_p}"
                 f"   q=退出  f=跟踪  上下键=浏览 "),
                align='center',
            ),
            'header',
        )

    def _update_traffic(self):
        self.traffic_walker.clear()
        records           = self.server.get_records()[-60:]
        self.traffic_data = records
        if not records:
            return
        if self._auto_follow:
            self.selected_row = len(records) - 1
        self.selected_row = max(0, min(self.selected_row, len(records) - 1))

        for idx, rec in enumerate(records):
            req    = rec.request
            resp   = rec.response
            ts     = time.strftime('%H:%M:%S', time.localtime(req.timestamp))
            host   = (req.host or 'N/A')[:19]
            meth   = (req.method or 'N/A')[:5]
            code   = resp.status_code or 0
            st     = str(code) if code else '---'
            proto  = 'HTTPS' if req.is_https else 'HTTP'
            sz     = _fmt_size(resp.body)
            res    = '通过' if rec.passed else ('阻断' if rec.blocked else '未知')

            is_follow = self._auto_follow and idx == self.selected_row
            is_manual = not self._auto_follow and idx == self.selected_row

            if is_follow:
                attr = 'tr_follow'
                cols = urwid.Columns([
                    ('fixed', 10, urwid.Text((attr, f' {ts}'))),
                    ('fixed', 20, urwid.Text((attr, host))),
                    ('fixed', 6,  urwid.Text((attr, meth))),
                    ('fixed', 5,  urwid.Text((attr, st))),
                    ('fixed', 6,  urwid.Text((attr, proto))),
                    ('fixed', 7,  urwid.Text((attr, sz))),
                    ('weight', 1, urwid.Text((attr, res))),
                ], dividechars=1)
                self.traffic_walker.append(urwid.AttrMap(cols, attr))

            elif is_manual:
                attr = 'tr_selected'
                cols = urwid.Columns([
                    ('fixed', 10, urwid.Text((attr, f' {ts}'))),
                    ('fixed', 20, urwid.Text((attr, host))),
                    ('fixed', 6,  urwid.Text((attr, meth))),
                    ('fixed', 5,  urwid.Text((attr, st))),
                    ('fixed', 6,  urwid.Text((attr, proto))),
                    ('fixed', 7,  urwid.Text((attr, sz))),
                    ('weight', 1, urwid.Text((attr, res))),
                ], dividechars=1)
                self.traffic_walker.append(urwid.AttrMap(cols, attr))

            else:
                row_attr = _row_palette_for_status(code)
                cols = urwid.Columns([
                    ('fixed', 10, urwid.Text((row_attr, f' {ts}'))),
                    ('fixed', 20, urwid.Text((row_attr, host))),
                    ('fixed', 6,  urwid.Text((row_attr, meth))),
                    ('fixed', 5,  urwid.Text((row_attr, st))),
                    ('fixed', 6,  urwid.Text((row_attr, proto))),
                    ('fixed', 7,  urwid.Text((row_attr, sz))),
                    ('weight', 1, urwid.Text((row_attr, res))),
                ], dividechars=1)
                self.traffic_walker.append(urwid.AttrMap(cols, row_attr))

        if self.traffic_walker:
            try: self.traffic_walker.set_focus(self.selected_row)
            except Exception: pass

        if self._auto_follow:
            self.follow_text.set_text(('ws_ok', ' [跟踪] f=暂停 '))
        else:
            self.follow_text.set_text(('tr_block',
                f' [暂停] 行={self.selected_row+1}/{len(records)}  f=继续 '))

    def _update_tech_panel(self):
        self.tech_walker.clear()
        entries = self.tech_table.get_recent(6)
        if not entries:
            self.tech_walker.append(
                urwid.AttrMap(urwid.Text(('ws_inactive', ' 等待中...')), 'ws_bg'))
            return
        for e in reversed(entries):
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_tech_rq',  f' {str(e["rq"]).rjust(3)}'))),
                ('fixed', 14, urwid.Text(('ws_tech_tls', (e["tls"] or "N/A")[:13]))),
                ('fixed', 10, urwid.Text(('ws_tech_tcp', (e["tcp"] or "N/A")[:9]))),
                ('weight', 1, urwid.Text(('ws_tech_h2',  (e["h2"]  or "N/A")[:14]))),
            ], dividechars=1)
            self.tech_walker.append(urwid.AttrMap(cols, 'ws_bg'))

    def _update_server_ip_panel(self):
        if not self.server_ip:
            return
        self.server_ip_text.set_text([
            ('ws_label', ' 来源 IP   : '), ('ws_ip',    self.server_ip),
            ('ws_bg',    '\n'),
            ('ws_label', ' 模式      : '), ('ws_value', '直接绕过'),
        ])

    def _update_status(self):
        records    = self.server.get_records()
        total      = len(records)
        passed     = sum(1 for r in records if r.passed)
        blocked    = sum(1 for r in records if r.blocked)
        rate       = (passed / total * 100) if total else 0.0
        tor_ips    = self.tor_table.get_all()
        tor_cnt    = len(tor_ips)
        cur_ip     = tor_ips[-1]["ip"] if tor_ips else "N/A"
        tor_str    = f"开 ip={cur_ip} 轮换={tor_cnt}" if self.enable_tor else "关"
        ip_str     = f" | 来源:{self.server_ip}" if self.server_ip else ""
        mode_str   = " 跟踪" if self._auto_follow else " 暂停"
        sport_e    = self.sport_table.get_all()
        sport_last = sport_e[-1]["port"] if sport_e else "N/A"
        proxy_e    = self.proxy_table.get_all()
        proxy_pool = self.server._evil_proxy.pool_size() if self.server._evil_proxy else 0
        proxy_last = proxy_e[-1]["ip"] if proxy_e else "N/A"
        proxy_str  = f" | EvilProxy 池={proxy_pool} 最近={proxy_last}" if self.use_evil_proxy else ""
        vuln_e     = self.vuln_table.get_all()
        vuln_cnt   = len([v for v in vuln_e if not v["fp"]])
        scan_str   = f" | 漏洞:{vuln_cnt}" if self.enable_scanner else ""
        self.status_text.set_text([
            ('status', f' 总计:{total} 通过:{passed} 阻断:{blocked} 比率:{rate:.1f}%'),
            ('status', f' TOR:{tor_str}'),
            ('status', ip_str),
            ('status', f' 源端口:{sport_last}'),
            ('status', proxy_str),
            ('status', scan_str),
            ('status', f' |{mode_str} '),
            ('status', f' {time.strftime("%H:%M:%S")} '),
        ])

    def _refresh(self, loop: urwid.MainLoop, _: Any):
        try:
            self._update_traffic()
            if self.enable_tor and self._tor_panel:
                self._tor_panel.refresh()
            self._update_tech_panel()
            self._update_server_ip_panel()
            if self._sport_panel:   self._sport_panel.refresh()
            if self._proxy_panel:   self._proxy_panel.refresh()
            if self._vuln_panel:    self._vuln_panel.refresh()
            if self._scanner_panel: self._scanner_panel.refresh()
            self._update_status()
        except Exception:
            pass
        loop.set_alarm_in(0.3, self._refresh)

    def _handle_input(self, key: Any):
        if isinstance(key, tuple):
            ev = key[0]
            if ev == 'mouse press':
                btn = key[1]
                if btn == 4:
                    self._auto_follow = False
                    self.selected_row = max(0, self.selected_row - 1)
                    self._update_traffic()
                elif btn == 5:
                    self._auto_follow = False
                    self.selected_row = min(len(self.traffic_data) - 1, self.selected_row + 1)
                    self._update_traffic()
            return
        if key in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        elif key in ('f', 'F', 'end'):
            self._auto_follow = not self._auto_follow
            if self._auto_follow and self.traffic_data:
                self.selected_row = len(self.traffic_data) - 1
            self._update_traffic()
        elif key == 'up':
            self._auto_follow = False
            if self.selected_row > 0:
                self.selected_row -= 1
            self._update_traffic()
        elif key == 'down':
            self._auto_follow = False
            if self.selected_row < len(self.traffic_data) - 1:
                self.selected_row += 1
            self._update_traffic()
        elif key == 'page up':
            self._auto_follow = False
            self.selected_row = max(0, self.selected_row - 10)
            self._update_traffic()
        elif key == 'page down':
            self._auto_follow = False
            self.selected_row = min(len(self.traffic_data) - 1, self.selected_row + 10)
            self._update_traffic()
        elif key == 'home':
            self._auto_follow = False
            self.selected_row = 0
            self._update_traffic()

    def start(self):
        self.loop.run()


class EvilWAFOrchestrator:
    def __init__(
        self,
        listen_host:      str,
        listen_port:      int,
        enable_tor:       bool,
        tor_control_port: int,
        tor_password:     str,
        tor_rotate_every: int,
        server_ip:        Optional[str]       = None,
        target_host:      Optional[str]       = None,
        upstream_proxies: Optional[List[str]] = None,
        use_evil_proxy:   bool                = False,
        h2_strategy:      str                 = "weighted_random",
        enable_scanner:   bool                = False,
        scanner_target:   Optional[str]       = None,
        scanner_rps:      float               = 3.0,
        scanner_output:   Optional[str]       = None,
    ):
        self._enable_tor     = enable_tor
        self._use_evil_proxy = use_evil_proxy
        self._enable_scanner = enable_scanner
        self._scanner_target = scanner_target
        self._scanner_rps    = scanner_rps
        self._scanner_output = scanner_output
        self._running        = False

        self._server = create_interceptor(
            listen_host=listen_host,
            listen_port=listen_port,
            intercept_https=True,
            tor_control_port=tor_control_port,
            tor_password=tor_password,
            tor_rotate_every=tor_rotate_every,
            override_ip=server_ip,
            target_host=target_host,
            upstream_proxies=upstream_proxies,
            use_evil_proxy=use_evil_proxy,
            h2_strategy=h2_strategy,
        )

        self._tor_table:   TorIPTable     = TorIPTable()
        self._tech_table:  TechniqueTable = TechniqueTable()
        self._sport_table: SportTable     = SportTable()
        self._proxy_table: EvilProxyTable = EvilProxyTable()
        self._vuln_table:  VulnTable      = VulnTable()
        self._scanner_ref: List           = []

        self._tor_thread:     Optional[threading.Thread] = None
        self._tech_thread:    Optional[threading.Thread] = None
        self._sport_thread:   Optional[threading.Thread] = None
        self._proxy_thread:   Optional[threading.Thread] = None
        self._scanner_thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._server.start()
        self._tor_thread   = threading.Thread(target=self._watch_tor,   daemon=True)
        self._tech_thread  = threading.Thread(target=self._watch_tech,  daemon=True)
        self._sport_thread = threading.Thread(target=self._watch_sport, daemon=True)
        self._proxy_thread = threading.Thread(target=self._watch_proxy, daemon=True)
        self._tor_thread.start()
        self._tech_thread.start()
        self._sport_thread.start()
        self._proxy_thread.start()

        if self._enable_scanner and self._scanner_target:
            self._scanner_thread = threading.Thread(
                target=self._run_scanner, daemon=True
            )
            self._scanner_thread.start()

    def stop(self):
        self._running = False
        if self._scanner_ref:
            try:
                self._scanner_ref[0].stop()
            except Exception:
                pass
        try:
            self._server.stop()
        except Exception:
            pass

    def _run_scanner(self):
        scanner = WAFVulnScanner(
            target=self._scanner_target,
            output_dir=self._scanner_output,
            rps=self._scanner_rps,
            verify_findings=True,
        )
        self._scanner_ref.append(scanner)

        def on_finding(finding: VulnFinding):
            if not finding.false_positive:
                self._vuln_table.add(finding)

        def on_progress(current: int, total: int, category: str):
            pass

        scanner.scan(on_finding=on_finding, on_progress=on_progress)

    def _watch_tor(self):
        last_ip = None
        last_ts = time.time()
        while self._running:
            try:
                if self._enable_tor and self._server._tor.is_tor_alive():
                    self._server._tor.rotate_and_verify()
                    ip = getattr(self._server._tor, '_current_ip', None)
                    if not ip:
                        try:
                            ip = self._server._tor.get_current_ip()
                        except Exception:
                            ip = None
                    if ip and ip != last_ip:
                        self._tor_table.add(ip, time.time() - last_ts, "Running")
                        last_ip = ip
                        last_ts = time.time()
            except Exception:
                pass
            time.sleep(1)

    def _watch_tech(self):
        last_count = 0
        while self._running:
            try:
                records = self._server.get_records()
                if len(records) > last_count:
                    tls_id   = getattr(self._server._tls_fp,     '_last_identifier', 'N/A') or 'N/A'
                    tcp_prof = getattr(self._server._tcp_manip,  '_last_profile',    'N/A') or 'N/A'
                    h2_prof  = getattr(self._server._h2_rotator, '_last_profile', None)
                    h2_name  = h2_prof.name if h2_prof else (
                        getattr(self._server._magic, '_last_h2_profile', 'N/A') or 'N/A'
                    )
                    self._tech_table.add(tls_id, tcp_prof, h2_name)
                    last_count = len(records)
            except Exception:
                pass
            time.sleep(0.5)

    def _watch_sport(self):
        last_count = 0
        while self._running:
            try:
                records = self._server.get_records()
                if len(records) > last_count:
                    stats   = self._server._sport_manip.get_stats()
                    port    = stats.get("current_port", 0)
                    profile = stats.get("profile", "N/A")
                    if port:
                        self._sport_table.add(port, profile, port > 0)
                    last_count = len(records)
            except Exception:
                pass
            time.sleep(0.5)

    def _watch_proxy(self):
        last_count = 0
        while self._running:
            try:
                if self._use_evil_proxy and self._server._evil_proxy:
                    records = self._server.get_records()
                    if len(records) > last_count:
                        assigned = getattr(self._server._evil_proxy, '_assigned', {})
                        if assigned:
                            entry = list(assigned.values())[-1]
                            self._proxy_table.add(
                                ip=entry.host, port=entry.port,
                                latency=entry.latency, anonymous=entry.anonymous,
                                success=entry.success_count > 0,
                            )
                        last_count = len(records)
            except Exception:
                pass
            time.sleep(0.5)

    @property
    def server(self) -> Interceptor:
        return self._server

    @property
    def tor_table(self)   -> TorIPTable:     return self._tor_table
    @property
    def tech_table(self)  -> TechniqueTable: return self._tech_table
    @property
    def sport_table(self) -> SportTable:     return self._sport_table
    @property
    def proxy_table(self) -> EvilProxyTable: return self._proxy_table
    @property
    def vuln_table(self)  -> VulnTable:      return self._vuln_table
    @property
    def scanner_ref(self) -> List:           return self._scanner_ref


def signal_handler(signum: int, frame: Any):
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        prog="evilwaf",
        description=f"EvilWAF v{VERSION} — 透明 WAF 绕过代理",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "参数说明:\n"
            "  -t / --target           目标 URL（必填）\n"
            "  --listen-host           代理监听地址（默认: 127.0.0.1）\n"
            "  --listen-port           代理监听端口（默认: 8080）\n"
            "  --enable-tor            通过 TOR 路由流量\n"
            "  --tor-control-port      TOR 控制端口（默认: 9051）\n"
            "  --tor-password          TOR 控制密码\n"
            "  --tor-rotate-every      每 N 次请求轮换 TOR IP\n"
            "  --server-ip             强制指定源站 IP（WAF 绕过）\n"
            "  --auto-hunt             自动发现 WAF 后方源站 IP\n"
            "  --upstream-proxy URL    上游代理\n"
            "  --proxy-file FILE       代理 URL 列表文件\n"
            "  --no-evil-proxy         禁用 EvilProxy 代理池\n"
            "  --h2-strategy           H2 指纹策略: weighted_random|round_robin|random\n"
            "  --scan-vulns            启用 WAF 漏洞扫描器（后台运行）\n"
            "  --scan-target URL       扫描器目标（默认: 与 --target 相同）\n"
            "  --scan-rps FLOAT        扫描器请求速率（默认: 3.0）\n"
            "  --scan-output DIR       扫描器输出目录\n"
            "  --scan-only             仅运行扫描器，不启动代理\n"
            "  --no-tui                无头模式\n"
            "\n"
            
            "始终有新版本可用 (https://github.com/matrixleons/evilwaf)\n"
            
            "\n"
            "示例:\n"
            "  evilwaf -t https://target.com --scan-only\n"
            "  sqlmap -u 'https://target.com/?id=1' --proxy=http://127.0.0.1:8080\n"
        ),
    )

    parser.add_argument("-t",  "--target",        type=str, required=True)
    parser.add_argument("--listen-host",          type=str, default="127.0.0.1")
    parser.add_argument("--listen-port",          type=int, default=8080)
    parser.add_argument("--enable-tor",           action="store_true")
    parser.add_argument("--tor-control-port",     type=int, default=9051)
    parser.add_argument("--tor-password",         type=str, default="")
    parser.add_argument("--tor-rotate-every",     type=int, default=1)
    parser.add_argument("--server-ip",            type=str, default=None)
    parser.add_argument("--auto-hunt",            action="store_true")
    parser.add_argument("--upstream-proxy",       type=str, default=None)
    parser.add_argument("--proxy-file",           type=str, default=None)
    parser.add_argument("--no-evil-proxy",        action="store_true")
    parser.add_argument("--h2-strategy",          type=str, default="weighted_random",
                        choices=["weighted_random", "round_robin", "random"])
    parser.add_argument("--scan-vulns",           action="store_true")
    parser.add_argument("--scan-target",          type=str, default=None)
    parser.add_argument("--scan-rps",             type=float, default=3.0)
    parser.add_argument("--scan-output",          type=str, default=None)
    parser.add_argument("--scan-only",            action="store_true")
    parser.add_argument("--no-tui",               action="store_true")

    args = parser.parse_args()
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] 无效目标: {args.target}")
        sys.exit(1)

    if args.server_ip and args.auto_hunt:
        print("[!] --server-ip 与 --auto-hunt 不能同时使用")
        sys.exit(1)

    _print_version_check()

    if args.scan_only:
        _run_vuln_scanner_verbose(
            target=args.scan_target or args.target,
            rps=args.scan_rps,
            output_dir=args.scan_output,
        )
        return

    upstream_proxies = None
    if args.upstream_proxy:
        upstream_proxies = [args.upstream_proxy]
    if args.proxy_file:
        with open(args.proxy_file) as f:
            file_proxies = [ln.strip() for ln in f
                            if ln.strip() and not ln.startswith('#')]
        upstream_proxies = (upstream_proxies or []) + file_proxies

    print(f"[*] 目标   : {args.target}")
    print("[*] 正在检测 WAF...", end="", flush=True)
    waf_name = _detect_waf(args.target)
    print(f"\r[*] WAF    : {waf_name or '未检测到'}")

    server_ip: Optional[str] = None
    if args.server_ip:
        server_ip = args.server_ip
        print(f"[*] 模式   : 手动 IP 绕过 -> {server_ip}")
    elif args.auto_hunt:
        found = _hunt_origin_ip_verbose(args.target)
        if found:
            if _ask_connect_proxy(found):
                server_ip = found
                print(f"[+] 流量路由至 -> {server_ip}")
            else:
                print(f"[*] 提示: 可使用 --server-ip {found}")
                sys.exit(0)
        else:
            print("[!] 未找到源站 IP — 使用标准代理模式")
    else:
        print("[*] 模式   : 标准代理")

    if args.enable_tor:
        print("[*] TOR       : 已启用")
    if not args.no_evil_proxy:
        print("[*] EvilProxy : 已启用 — 每请求轮换一个 IP")
    if args.scan_vulns:
        scan_tgt = args.scan_target or args.target
        print(f"[*] 扫描器    : 已启用 — 目标={scan_tgt} 速率={args.scan_rps}")
    if upstream_proxies:
        print(f"[*] 代理      : {len(upstream_proxies)} 个上游代理")
    print(f"[*] H2        : 策略={args.h2_strategy}")
    print(f"[*] 监听地址  : {args.listen_host}:{args.listen_port}")

    orchestrator = EvilWAFOrchestrator(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        enable_tor=args.enable_tor,
        tor_control_port=args.tor_control_port,
        tor_password=args.tor_password,
        tor_rotate_every=args.tor_rotate_every,
        server_ip=server_ip,
        target_host=parsed.hostname,
        upstream_proxies=upstream_proxies,
        use_evil_proxy=not args.no_evil_proxy,
        h2_strategy=args.h2_strategy,
        enable_scanner=args.scan_vulns,
        scanner_target=args.scan_target or args.target,
        scanner_rps=args.scan_rps,
        scanner_output=args.scan_output,
    )

    orchestrator.start()
    time.sleep(0.8)

    if not args.no_evil_proxy and orchestrator.server._evil_proxy:
        print("[*] EvilProxy : 预热中...", end="", flush=True)
        orchestrator.server._evil_proxy.wait_until_ready(min_proxies=5, timeout=30.0)
        print(f"\r[+] EvilProxy : {orchestrator.server._evil_proxy.pool_size()} 个代理就绪")

    print(f"[+] 代理就绪 : http://{args.listen_host}:{args.listen_port}")
    if server_ip:
        print(f"[+] 流量路由  : {parsed.hostname} -> {server_ip}")
    if args.enable_tor:
        alive = orchestrator.server._tor.is_tor_alive()
        cur   = orchestrator.server._tor.get_current_ip() if alive else None
        print(f"[+] TOR 状态  : {'活跃 — IP=' + (cur or 'N/A') if alive else '无法连接'}")

    try:
        if args.no_tui:
            print("[*] 无头模式 — 按 Ctrl+C 停止\n")
            print(f"{'请求':<6} {'主机':<20} {'时间':<10} {'状态':<5} {'协议':<6} {'结果':<6} {'技术'}")
            print("-" * 80)
            last = 0
            rq   = 0
            while True:
                time.sleep(1)
                records = orchestrator.server.get_records()
                if len(records) > last:
                    for rec in records[last:]:
                        rq   += 1
                        ts    = time.strftime('%H:%M:%S', time.localtime(rec.request.timestamp))
                        host  = (rec.request.host or "N/A")[:19]
                        st    = str(rec.response.status_code) if rec.response.status_code else "---"
                        proto = 'HTTPS' if rec.request.is_https else 'HTTP'
                        res   = "PASS" if rec.passed else ("BLCK" if rec.blocked else "UNKN")
                        tech  = rec.technique_applied or "N/A"
                        print(f"{str(rq):<6} {host:<20} {ts:<10} {st:<5} {proto:<6} {res:<6} {tech}")
                    last = len(records)

                if args.scan_vulns and orchestrator.scanner_ref:
                    vulns = orchestrator.vuln_table.get_recent(3)
                    for v in vulns:
                        if not v["fp"]:
                            print(f"  [漏洞] {v['severity'].upper():<8}"
                                  f" 层={v['layer']:<25}"
                                  f" 置信={v['confidence']:.0%}"
                                  f" {v['title']}")
        else:
            tui = EvilWAFTUI(
                server=orchestrator.server,
                target_url=args.target,
                tor_table=orchestrator.tor_table,
                tech_table=orchestrator.tech_table,
                sport_table=orchestrator.sport_table,
                proxy_table=orchestrator.proxy_table,
                vuln_table=orchestrator.vuln_table,
                scanner_ref=orchestrator.scanner_ref,
                server_ip=server_ip,
                waf_name=waf_name,
                enable_tor=args.enable_tor,
                use_evil_proxy=not args.no_evil_proxy,
                enable_scanner=args.scan_vulns,
                upstream_proxy_count=len(upstream_proxies) if upstream_proxies else 0,
            )
            tui.start()
    except KeyboardInterrupt:
        pass
    finally:
        orchestrator.stop()


if __name__ == "__main__":
    main()