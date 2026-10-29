#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_lan.py —— 局域网在线设备枚举

抓包只能看到本机流量和广播/组播，看不到别的设备之间在聊什么。
想知道"一共连了几台设备"，得主动探测：ping 扫全网段 → 读 ARP 表 → 反查厂商。

用法:
    python scan_lan.py                     # 用 analysis_config.json 里的网段
    python scan_lan.py -n 192.168.110.0/24
    python scan_lan.py --no-ping           # 只读现有 ARP 表，不发包
    python scan_lan.py --json out.json
"""
import argparse
import ipaddress
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = Path(__file__).resolve().parent


def load_config(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except Exception:
        return {}


def load_names(path):
    """IP -> 名称，兼容 JSON 与 ip=名称 两种写法。"""
    path = Path(path)
    if not path.exists():
        return {}
    text = path.read_text(encoding='utf-8-sig').strip()
    if not text:
        return {}
    if text[0] in '{[':
        try:
            data = json.loads(text)
        except Exception:
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    names = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for sep in ('=', '\t', ','):
            if sep in line:
                ip, _, name = line.partition(sep)
                names[ip.strip()] = name.strip()
                break
    return names


def ping(ip, timeout_ms):
    if sys.platform == 'win32':
        cmd = ['ping', '-n', '1', '-w', str(timeout_ms), str(ip)]
    else:
        cmd = ['ping', '-c', '1', '-W', str(max(1, timeout_ms // 1000)), str(ip)]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout_ms / 1000 + 2).returncode == 0
    except Exception:
        return False


def read_arp():
    """读系统 ARP 表，返回 {ip: mac}。Windows 输出是 GBK，但 IP/MAC 都是 ASCII。"""
    cmd = ['arp', '-a'] if sys.platform == 'win32' else ['arp', '-an']
    try:
        raw = subprocess.run(cmd, capture_output=True, timeout=15).stdout
    except Exception:
        return {}
    text = raw.decode('ascii', errors='ignore')
    table = {}
    for line in text.splitlines():
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})', line)
        if m:
            table[m.group(1)] = m.group(2).replace(':', '-').lower()
    return table


def load_oui(tshark):
    """从 tshark 内置 manuf 库取 OUI -> 厂商名。"""
    if not tshark or not Path(tshark).is_file():
        return {}
    try:
        raw = subprocess.run([str(tshark), '-G', 'manuf'], capture_output=True, timeout=60).stdout
    except Exception:
        return {}
    oui = {}
    for line in raw.decode('utf-8', errors='replace').splitlines():
        parts = line.split('\t')
        if len(parts) >= 3 and re.fullmatch(r'[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2}', parts[0].strip()):
            oui[parts[0].strip().replace(':', '').lower()] = parts[2].strip()
    return oui


def is_random(mac):
    """MAC 首字节的本地管理位为 1 → 随机/虚拟地址，查不到厂商。"""
    try:
        return bool(int(mac.split('-')[0], 16) & 0x02)
    except Exception:
        return False


def is_group(mac):
    """首字节组播位为 1 → 广播/组播地址，不是一台设备。"""
    try:
        return bool(int(mac.split('-')[0], 16) & 0x01)
    except Exception:
        return False


def local_ip():
    """取本机在默认路由上的地址，不会真的发包。"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('223.5.5.5', 53))
        return sock.getsockname()[0]
    except Exception:
        return None
    finally:
        sock.close()


def find_tshark():
    local = BASE / 'Wireshark' / ('tshark.exe' if sys.platform == 'win32' else 'tshark')
    return local if local.is_file() else None


def main():
    ap = argparse.ArgumentParser(description='扫描局域网在线设备（ping 扫段 + ARP 表 + OUI 反查）')
    ap.add_argument('-n', '--net', help='网段，如 192.168.110.0/24；默认取 analysis_config.json')
    ap.add_argument('--config', type=Path, default=BASE / 'analysis_config.json')
    ap.add_argument('--names', type=Path, default=BASE / 'devices.json')
    ap.add_argument('--timeout', type=int, default=300, help='单个 ping 超时毫秒，默认 300')
    ap.add_argument('--workers', type=int, default=64, help='并发数，默认 64')
    ap.add_argument('--no-ping', action='store_true', help='不扫描，只读现有 ARP 表')
    ap.add_argument('--json', type=Path, help='结果导出为 JSON')
    args = ap.parse_args()

    net_text = args.net or (load_config(args.config).get('networks') or [''])[0]
    if not net_text:
        print('[!] 没有网段。用 -n 指定，或先在 analysis_config.json 里配 networks', file=sys.stderr)
        return 1
    try:
        net = ipaddress.ip_network(net_text, strict=False)
    except ValueError as error:
        print('[!] 网段格式不对：' + str(error), file=sys.stderr)
        return 1
    if net.num_addresses > 4096:
        print('[!] 网段太大（{} 个地址），请缩小到 /20 以内'.format(net.num_addresses), file=sys.stderr)
        return 1

    hosts = [str(h) for h in net.hosts()]
    names = load_names(args.names)
    oui = load_oui(find_tshark())

    scanned = 0
    if not args.no_ping:
        print('[i] 扫描 {} 个地址，并发 {}，超时 {} ms'.format(len(hosts), args.workers, args.timeout),
              flush=True)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            list(pool.map(lambda ip: ping(ip, args.timeout), hosts))
        scanned = len(hosts)

    table = read_arp()
    self_ip = local_ip()
    rows = []
    for ip in sorted(table, key=lambda s: ipaddress.ip_address(s)):
        addr = ipaddress.ip_address(ip)
        if addr not in net or addr == net.broadcast_address or addr == net.network_address:
            continue
        mac = table[ip]
        if is_group(mac):
            continue
        vendor = '随机地址' if is_random(mac) else oui.get(mac.replace('-', '')[:6], '未知厂商')
        rows.append({'ip': ip, 'name': names.get(ip, ''), 'mac': mac,
                     'random_mac': is_random(mac), 'vendor': vendor})

    total = len(rows) + (1 if self_ip and ipaddress.ip_address(self_ip) in net
                         and self_ip not in table else 0)
    print()
    print('网段      : {}'.format(net))
    print('扫描地址  : {} 个{}'.format(scanned, '（未扫描，仅读 ARP）' if args.no_ping else ''))
    print('在线设备  : {} 台'.format(total))
    if self_ip and self_ip not in table:
        print('本机      : {}（自己的地址不会出现在自己的 ARP 表里）'.format(self_ip))
    print()
    if not rows:
        print('ARP 表里没有该网段的记录。先不加 --no-ping 跑一次，或确认网段。')
        return 0

    name_w = max([8] + [len(r['name']) for r in rows]) + 2
    vendor_w = max([8] + [len(r['vendor']) for r in rows])
    head = '{:<16}{:<{nw}}{:<18}{:<8}{}'.format('IP', '名称', 'MAC', '类型', '厂商', nw=name_w)
    print(head)
    print('-' * (16 + name_w + 18 + 8 + vendor_w))
    for r in rows:
        kind = '随机' if r['random_mac'] else '固定'
        print('{:<16}{:<{nw}}{:<18}{:<8}{}'.format(
            r['ip'], r['name'], r['mac'], kind, r['vendor'], nw=name_w))
    print('-' * (16 + name_w + 18 + 8 + vendor_w))
    random_count = sum(1 for r in rows if r['random_mac'])
    if random_count:
        print('{} 台用随机 MAC（手机的私有 WiFi 地址、虚拟网卡等），查不到厂商。'.format(random_count))
    print('\n注意：ARP 只能看到"此刻回应过的"设备；关机、休眠、不响应 ICMP 的设备不会出现。')
    print('      完整清单请看路由器 DHCP 客户端列表。')

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({'network': str(net), 'self_ip': self_ip,
                                         'count': total, 'devices': rows},
                                        ensure_ascii=False, indent=2), encoding='utf-8')
        print('\n[+] JSON 已导出: ' + str(args.json))
    return 0


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main())
