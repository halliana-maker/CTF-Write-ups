#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from evtx import PyEvtxParser

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def iter_evtx(path: Path):
    for rec in PyEvtxParser(str(path)).records():
        try:
            root = ET.fromstring(rec["data"])
        except Exception:
            continue

        t_el = root.find('.//e:TimeCreated', NS)
        time = t_el.attrib.get('SystemTime', '') if t_el is not None else ''
        eid = root.findtext('.//e:EventID', default='', namespaces=NS)

        data = {}
        for d in root.findall('.//e:EventData/e:Data', NS):
            data[d.attrib.get('Name', '')] = d.text or ''

        text = ' '.join(t for t in root.itertext() if t)
        yield {
            'time': time,
            'eid': eid,
            'data': data,
            'text': text,
        }


def earliest_process_hits(sysmon_path: Path):
    targets = ['Резюме.docm', 'Certify.exe', 'Rubeus.exe', 'mimikatz.exe', 'wlmss.exe']
    found = {}

    for rec in iter_evtx(sysmon_path):
        if rec['eid'] != '1':
            continue
        image = rec['data'].get('Image', '')
        cmd = rec['data'].get('CommandLine', '')
        for target in targets:
            if target.lower() in image.lower() or target.lower() in cmd.lower():
                prev = found.get(target)
                item = {
                    'time': rec['time'],
                    'image': image,
                    'command_line': cmd,
                }
                if prev is None or item['time'] < prev['time']:
                    found[target] = item
                break

    ordered = [(t, found[t]) for t in targets if t in found]
    return ordered


def detect_privesc(sysmon_path: Path):
    for rec in iter_evtx(sysmon_path):
        if rec['eid'] != '1':
            continue
        cmd = rec['data'].get('CommandLine', '')
        if 'VulnerableUserSAN' in cmd and '/altname:admin' in cmd:
            return {
                'name': 'ESC1',
                'time': rec['time'],
                'command_line': cmd,
            }
    return None


def first_exfil(ps_path: Path, port: int):
    port_pattern = f"TcpClient('192.168.100.54',{port})"
    alt_port_pattern = f"TcpClient('192.168.100.54', {port})"

    for rec in iter_evtx(ps_path):
        text = rec['text']
        if port_pattern in text or alt_port_pattern in text:
            m = re.search(r'\$file="([^"]+)"', text)
            file_path = m.group(1) if m else ''
            return {
                'time': rec['time'],
                'file_path': file_path,
                'basename': __import__('ntpath').basename(file_path) if file_path else '',
                'snippet': re.sub(r'\s+', ' ', text)[:500],
            }
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Recover the flag for the KubSTU "We have an incident!" challenge from the extracted evidence tree.'
    )
    parser.add_argument(
        'root',
        nargs='?',
        default='incident',
        help='Path to the extracted evidence root. Expected layout: <root>/HR/... and <root>/AD/...',
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        alt = Path('/mnt/data/incident')
        if alt.exists():
            root = alt
        else:
            print(f'[-] Evidence root not found: {args.root}', file=sys.stderr)
            return 1

    hr_sysmon = root / 'HR/C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx'
    hr_ps = root / 'HR/C/Windows/System32/winevt/logs/Windows PowerShell.evtx'
    ad_ps = root / 'AD/C/Windows/System32/winevt/logs/Windows PowerShell.evtx'

    for path in (hr_sysmon, hr_ps, ad_ps):
        if not path.exists():
            print(f'[-] Missing required artifact: {path}', file=sys.stderr)
            return 1

    malware_hits = earliest_process_hits(hr_sysmon)
    privesc = detect_privesc(hr_sysmon)
    exfil_1 = first_exfil(hr_ps, 9000)
    exfil_2 = first_exfil(ad_ps, 9001)

    if not malware_hits:
        print('[-] Could not recover malware execution order from HR Sysmon.', file=sys.stderr)
        return 1
    if privesc is None:
        print('[-] Could not recover the privilege-escalation method.', file=sys.stderr)
        return 1
    if exfil_1 is None or exfil_2 is None:
        print('[-] Could not recover the exfiltration sequence.', file=sys.stderr)
        return 1

    malware_list = '_'.join(name for name, _ in malware_hits)
    exfil_list = '_'.join(x['basename'] for x in sorted([exfil_1, exfil_2], key=lambda x: x['time']))
    flag = f'KubSTU{{{privesc["name"]}:{malware_list}:{exfil_list}}}'

    print('[+] Privilege escalation')
    print(f'    {privesc["name"]}')
    print(f'    {privesc["time"]}')
    print(f'    {privesc["command_line"]}')
    print()

    print('[+] Malware / tool execution order')
    for name, hit in malware_hits:
        print(f'    {hit["time"]}  {name}')
        print(f'        Image: {hit["image"]}')
        print(f'        Cmd  : {hit["command_line"]}')
    print()

    print('[+] Exfiltration order')
    for hit in sorted([exfil_1, exfil_2], key=lambda x: x['time']):
        print(f'    {hit["time"]}  {hit["basename"]}')
        print(f'        Path : {hit["file_path"]}')
        print(f'        Snip : {hit["snippet"]}')
    print()

    print('[+] Flag')
    print(flag)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
