#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LAN traffic report: native tshark decoder, streaming Python aggregation."""
import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
import webbrowser
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from traffic_core import METRICS, TZ, analyze_records, tshark_records

BASE = Path(__file__).resolve().parent
DEMO_SHA256 = '97753c2f08a25b9d730a77dbf81185acaa7da693e9fc7465f8de1887fe33ed69'
SOURCES = {'router-lan': '路由器 LAN 导出（用户声明）', 'mirror': '端口镜像（用户声明）',
           'host': '本机抓包，仅代表本机可见流量', 'unknown': '来源未确认', 'demo': '示例数据，不能代表实际网络'}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def is_demo(path, digest=None):
    return (bool(re.search(r'(^|[_\- ])(demo|sample|test)([_\- .]|$)', Path(path).name, re.I))
            or (digest or sha256(path)) == DEMO_SHA256)


def find_tshark(explicit=None):
    """优先用显式参数，其次本目录 Wireshark，最后系统 PATH（跳过本项目的 tshark.bat 包装）。"""
    if explicit:
        return Path(explicit)
    local = BASE / 'Wireshark' / ('tshark.exe' if os.name == 'nt' else 'tshark')
    if local.is_file():
        return local
    for name in (('tshark.exe', 'tshark') if os.name == 'nt' else ('tshark',)):
        found = shutil.which(name)
        if not found:
            continue
        candidate = Path(found).resolve()
        # Windows 的 which 会把当前目录算进搜索范围，会命中本项目的 tshark.bat
        if BASE == candidate.parent or BASE in candidate.parents:
            continue
        return candidate
    return None


def latest_capture(directory):
    candidates = sorted((p for p in directory.iterdir() if p.is_file() and
                         p.suffix.lower() in ('.pcap', '.pcapng', '.cap')),
                        key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True) if directory.exists() else []
    for candidate in candidates:
        if not is_demo(candidate):
            return candidate
    raise ValueError('尚无真实 LAN 抓包。请把路由器 LAN 导出的 .pcap/.pcapng 放到：\n    ' +
                     str(directory) + '\n    不会自动使用示例数据；演示请运行 analyze.bat --demo')


def load_names(path):
    if not path.exists():
        return {}
    text = path.read_text(encoding='utf-8-sig').strip()
    if not text:
        return {}
    if text[0] in '{[':
        result = json.loads(text)
        if not isinstance(result, dict):
            raise ValueError('设备名称文件必须是 IP 到名称的 JSON 对象')
        return {str(ip): name.strip() for ip, name in result.items() if isinstance(name, str)}
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        for separator in ('=', '\t', ','):
            if separator in line:
                ip, name = line.split(separator, 1)
                result[ip.strip()] = name.strip()
                break
    return result


def human(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return '{:.2f} {}'.format(value, unit)
        value /= 1024


def write_csv(path, rows, fields):
    def cell(value):
        # Quoting alone does not prevent spreadsheet formula evaluation.
        if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
            return "'" + value
        return value
    with path.open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows({key: cell(row.get(key, '')) for key in fields} for row in rows)


def render_console(data, conv_limit):
    summary = data['summary']
    lines = ['文件：' + data['source']['filename'], '来源：' + data['source']['label'],
             '时间：{} → {}（北京时间）'.format(summary['start'], summary['end']),
             '数据包：{}；IPv4：{}；IPv6：{}；内网地址：{}'.format(
                 summary['captured_packets'], summary['ipv4_packets'], summary['ipv6_packets'], summary['device_count']),
             '公网收发：{}；内网互传（每包一次）：{}；其他网段：{}；广播/组播等：{}'.format(
                 human(summary['total_bytes']), human(summary['lan_bytes']),
                 human(summary['other_bytes']), human(summary['service_bytes'])), '']
    if summary['average_mbps'] is not None:
        lines.append('公网平均合计：{:.3f} Mbps；{:.3g} 秒窗口峰值：{:.3f} Mbps'.format(
            summary['average_mbps'], data['timeline']['interval_seconds'], summary['peak_mbps']))
    lines += ['公网流量排行（占比不是宽带利用率）：', 'IP | 名称 | 公网上行 | 公网下行 | 公网占比 | 内网发送 / 接收']
    for row in data['devices']:
        lines.append('{} | {} | {} | {} | {:.2f}% | {} / {}'.format(
            row['ip'], row['name'] or '未命名', human(row['up_bytes']), human(row['down_bytes']),
            row['share_percent'], human(row['lan_tx_bytes']), human(row['lan_rx_bytes'])))
    if conv_limit:
        lines += ['', '公网对端排行：本地地址 | 名称 | 对端地址 | 上行 / 下行']
        for row in data['conversations'][:conv_limit]:
            lines.append('{} | {} | {} | {} / {}'.format(row['local_ip'], row['name'] or '未命名',
                         row['remote_ip'], human(row['up_bytes']), human(row['down_bytes'])))
    lines += ['', '注意：按最外层 IP 长度计数；包含重传。名称来自 devices.json，地址不等于物理设备。']
    lines += ['[提示] ' + warning for warning in data['warnings']]
    return '\n'.join(lines)


def save_report(data, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'report.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    fields = ['ip', 'name', 'up_bytes', 'down_bytes', 'total_bytes', 'packets', 'share_percent',
              'up_mbps', 'down_mbps', 'lan_tx_bytes', 'lan_rx_bytes',
              'other_up_bytes', 'other_down_bytes', 'service_bytes']
    write_csv(output / 'devices.csv', data['devices'], fields)
    write_csv(output / 'conversations.csv', data['conversations'],
              ['local_ip', 'name', 'remote_ip', 'up_bytes', 'down_bytes', 'total_bytes', 'packets'])
    curve = data['timeline']
    def timeline_rows():
        for ip, points in curve['series'].items():
            for point in points:
                row = dict(zip(METRICS, point[1:]))
                row.update(ip=ip, offset_seconds=point[0] * curve['interval_seconds'],
                           interval_seconds=curve['interval_seconds'],
                           up_mbps=point[1] * 8 / curve['interval_seconds'] / 1e6,
                           down_mbps=point[2] * 8 / curve['interval_seconds'] / 1e6)
                yield row
    write_csv(output / 'timeline.csv', timeline_rows(),
              ['ip', 'offset_seconds', 'interval_seconds'] + METRICS + ['up_mbps', 'down_mbps'])
    encoded = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('&', '\\u0026')
    template = (BASE / 'report_template.html').read_text(encoding='utf-8')
    (output / 'report.html').write_text(template.replace('__REPORT_DATA__', encoded), encoding='utf-8')
    return fields


def main(argv=None):
    ap = argparse.ArgumentParser(description='分析路由器 LAN 抓包，生成设备排行和离线流量曲线；不传文件时读取 captures 中最新的非示例文件。')
    ap.add_argument('pcap', nargs='?', help='pcap/pcapng/cap 文件，可包含空格或中文')
    ap.add_argument('--demo', action='store_true', help='明确使用示例数据演示')
    ap.add_argument('--config', type=Path, default=BASE / 'analysis_config.json')
    ap.add_argument('-n', '--net', action='append', help='IPv4 LAN 网段，可多次指定；替换配置中的 IPv4 网段')
    ap.add_argument('--net6', action='append', help='IPv6 LAN 前缀，可多次指定')
    ap.add_argument('--source', choices=SOURCES, help='声明采集位置；不能验证抓包是否完整')
    ap.add_argument('--interval', help='曲线窗口秒数，默认 1 秒；范围 0.001–3600')
    ap.add_argument('--interface-id', type=int, help='只分析指定的 pcapng 接口编号')
    ap.add_argument('--names', type=Path, default=BASE / 'devices.json')
    ap.add_argument('--no-names', action='store_true')
    ap.add_argument('--conv', type=int, default=10, help='终端展示的公网对端数量')
    ap.add_argument('--csv', type=Path, help='额外导出设备 CSV，兼容旧用法')
    ap.add_argument('--output-dir', type=Path, help='输出目录，须不存在或为空')
    ap.add_argument('--tshark', type=Path, help='tshark 路径，默认找本目录 Wireshark/，再找系统 PATH')
    ap.add_argument('--open', action='store_true', help='完成后用浏览器打开离线 HTML')
    args = ap.parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding='utf-8-sig'))
        if not isinstance(config, dict):
            raise ValueError('配置必须是 JSON 对象')
        root = args.config.resolve().parent
        if args.demo and args.pcap:
            raise ValueError('--demo 和抓包文件不能同时指定')
        if args.conv < 0 or (args.interface_id is not None and args.interface_id < 0):
            raise ValueError('对端数量、接口编号不能为负数')
        interval = Decimal(str(args.interval if args.interval is not None else config.get('interval_seconds', 1)))
        if not interval.is_finite() or not Decimal('0.001') <= interval <= 3600:
            raise ValueError('时间窗口须在 0.001–3600 秒之间')
        networks = []
        for version, values in ((4, args.net if args.net is not None else config.get('networks', [])),
                                (6, args.net6 if args.net6 is not None else config.get('networks6', []))):
            if not isinstance(values, list):
                raise ValueError('网段配置必须是列表')
            for value in values:
                net = ipaddress.ip_network(value, strict=False)
                if net.version != version or net.prefixlen == 0:
                    raise ValueError('网段类型不正确或范围过宽：' + str(value))
                networks.append(net)
        if not networks:
            raise ValueError('请配置 LAN 网段或通过 -n / --net6 指定')
        path = (BASE / 'demo_capture.pcap' if args.demo else Path(args.pcap) if args.pcap else
                latest_capture(root / config.get('capture_dir', 'captures'))).resolve()
        if not path.is_file():
            raise ValueError('抓包文件不存在：' + str(path))
        tshark = find_tshark(args.tshark)
        if tshark is None or not tshark.is_file():
            raise ValueError('找不到 tshark。请安装 Wireshark（winget install WiresharkFoundation.Wireshark），'
                             '或把安装目录放到本项目的 Wireshark/ 下，或用 --tshark 指定完整路径')
        before = path.stat()
        digest = sha256(path)
        source = 'demo' if args.demo or is_demo(path, digest) else args.source or config.get('source', 'unknown')
        if source not in SOURCES:
            raise ValueError('无效的来源配置：' + str(source))
        output = (args.output_dir if args.output_dir else root / config.get('report_dir', 'reports') /
                  (path.stem + '_' + datetime.now(TZ).strftime('%Y%m%d_%H%M%S_%f'))).resolve()
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError('输出目录不是空目录，避免覆盖已有报告：' + str(output))
        if args.csv and args.csv.suffix.lower() != '.csv':
            raise ValueError('--csv 输出文件必须使用 .csv 扩展名')
        names = {} if args.no_names else load_names(args.names)
        print('[i] 正在分析：' + str(path), flush=True)
        data = analyze_records(tshark_records(tshark.resolve(), path, args.interface_id), networks, interval)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('抓包文件在分析期间发生变化；请停止抓包并完整导出后重试')
        data['source'] = {'filename': path.name, 'path': str(path), 'sha256': digest,
                          'kind': source, 'label': SOURCES[source], 'size_bytes': after.st_size,
                          'interface_filter': args.interface_id}
        data['generated_at'] = datetime.now(TZ).isoformat()
        data['schema_version'] = 2
        for row in data['devices']:
            row['name'] = names.get(row['ip'], '')
        for row in data['conversations']:
            row['name'] = names.get(row['local_ip'], '')
        if source == 'demo':
            data['warnings'].insert(0, '这是示例数据，只演示功能，不能用于实际网络诊断。')
        if source in ('unknown', 'host'):
            data['warnings'].insert(0, '本次来源不能证明覆盖整个 LAN，请勿据此判断其他设备没有流量。')
        console = render_console(data, args.conv)
        fields = save_report(data, output)
        (output / 'summary.txt').write_text(console + '\n', encoding='utf-8')
        if args.csv:
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            write_csv(args.csv, data['devices'], fields)
        print(console)
        print('\n[+] 离线报告：' + str(output / 'report.html'))
        print('[+] 原始统计：' + str(output / 'report.json'))
        if args.open:
            webbrowser.open((output / 'report.html').as_uri())
        return 0
    except (OSError, ValueError, InvalidOperation, TypeError, OverflowError) as error:
        print('[!] ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main())
