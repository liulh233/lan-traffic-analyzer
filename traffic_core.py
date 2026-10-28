"""Streaming packet decoding and traffic accounting. Python standard library only."""
import ipaddress
import subprocess
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal

TZ = timezone(timedelta(hours=8))
FIELDS = [
    'frame.time_epoch', 'frame.len', 'frame.cap_len', 'frame.protocols',
    'frame.interface_id', 'ip.src', 'ip.dst', 'ip.len',
    'ipv6.src', 'ipv6.dst', 'ipv6.plen', 'ipv6.opt.jumbo',
]
METRICS = ['up_bytes', 'down_bytes', 'lan_tx_bytes', 'lan_rx_bytes',
           'other_up_bytes', 'other_down_bytes', 'service_bytes']


def iso_time(ns):
    return datetime.fromtimestamp(ns / 1e9, TZ).isoformat() if ns is not None else None


def tshark_records(executable, path, interface_id=None):
    """Decode outermost IP only; native Wireshark handles link types/time resolution."""
    cmd = [str(executable), '-n', '-l', '-r', str(path), '-M', '100000',
           '-o', 'ip.defragment:FALSE', '-o', 'ipv6.defragment:FALSE',
           '-o', 'tcp.desegment_tcp_streams:FALSE', '-T', 'fields',
           '-E', 'occurrence=f', '-E', 'separator=/t', '-E', 'quote=n']
    if interface_id is not None:
        cmd += ['-Y', 'frame.interface_id=={}'.format(interface_id)]
    for field in FIELDS:
        cmd += ['-e', field]
    # A file for stderr prevents a blocked stderr pipe on large/corrupt captures.
    with tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errors,
                                text=True, encoding='utf-8', errors='replace')
        try:
            for line in proc.stdout:
                values = line.rstrip('\r\n').split('\t')
                if len(values) != len(FIELDS):
                    raise ValueError('tshark 返回了无法识别的字段行')
                yield dict(zip(FIELDS, values))
            code = proc.wait()
            errors.seek(0)
            detail = errors.read(12000).decode('utf-8', errors='replace').strip()
            if code:
                raise ValueError('tshark 读取失败，未生成报告：' + detail)
        finally:
            proc.stdout.close()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


class Timeline:
    """Fixed-width wall-clock bins, adaptively coarsened to at most 4096 windows."""
    def __init__(self, interval):
        self.width = int(Decimal(str(interval)) * 1_000_000_000)
        if self.width <= 0:
            raise ValueError('时间窗口必须大于 0')
        self.first = self.last = None
        self.bins = {}

    def observe(self, ns):
        if ns is None:
            return
        self.first = ns if self.first is None else min(ns, self.first)
        self.last = ns if self.last is None else max(ns, self.last)
        while self.last // self.width - self.first // self.width >= 4096:
            self.width *= 2
            merged = {}
            for (index, host), values in self.bins.items():
                dest = merged.setdefault((index // 2, host), [0] * len(METRICS))
                for i, value in enumerate(values):
                    dest[i] += value
            self.bins = merged

    def add(self, ns, host, metric, length):
        if ns is not None:
            values = self.bins.setdefault((ns // self.width, host), [0] * len(METRICS))
            values[METRICS.index(metric)] += length

    def export(self, valid):
        width = self.width / 1e9
        if self.first is None or not valid:
            return {'interval_seconds': width, 'count': 0, 'series': {}, 'start': None}
        start = self.first // self.width
        series = defaultdict(list)
        for (index, host), values in sorted(self.bins.items()):
            series[host].append([index - start] + values)
        return {'interval_seconds': width, 'count': self.last // self.width - start + 1,
                'start': iso_time(start * self.width), 'series': dict(series)}


def analyze_records(records, networks, interval=1):
    net4 = [net for net in networks if net.version == 4]
    net6 = [net for net in networks if net.version == 6]
    # Link-local and unique-local IPv6 can be classified without the ISP prefix.
    implicit6 = [ipaddress.ip_network('fe80::/10'), ipaddress.ip_network('fc00::/7')]
    devices = defaultdict(lambda: dict.fromkeys(METRICS + ['packets'], 0))
    conv = defaultdict(lambda: {'up_bytes': 0, 'down_bytes': 0, 'packets': 0})
    totals = dict.fromkeys(['captured_packets', 'ip_packets', 'ipv4_packets', 'ipv6_packets',
                           'non_ip_packets', 'invalid_ip_packets', 'truncated_packets',
                           'untimed_packets', 'frame_bytes', 'ip_bytes', 'up_bytes',
                           'down_bytes', 'lan_bytes', 'other_bytes', 'service_bytes',
                           'unassigned_bytes', 'unassigned_packets'], 0)
    timeline = Timeline(interval)
    interfaces = set()

    def local(address):
        nets = net4 if address.version == 4 else net6 + implicit6
        return any(address in net for net in nets)

    def service(address):
        return (address.is_multicast or address.is_unspecified or address.is_loopback or
                str(address) == '255.255.255.255' or
                any(net.prefixlen < 31 and address in (net.network_address, net.broadcast_address)
                    for net in net4))

    for record in records:
        totals['captured_packets'] += 1
        flen = int(record['frame.len'])
        totals['frame_bytes'] += flen
        totals['truncated_packets'] += int(record['frame.cap_len']) < flen
        raw_ts = record.get('frame.time_epoch', '')
        ns = int(Decimal(raw_ts) * 1_000_000_000) if raw_ts else None
        totals['untimed_packets'] += ns is None
        timeline.observe(ns)
        if record.get('frame.interface_id'):
            interfaces.add(record['frame.interface_id'])
        layers = record.get('frame.protocols', '').split(':')
        outer = next((layer for layer in layers if layer in ('ip', 'ipv6')), None)
        if not outer:
            totals['non_ip_packets'] += 1
            continue
        try:
            src = ipaddress.ip_address(record[outer + '.src'])
            dst = ipaddress.ip_address(record[outer + '.dst'])
            length = (int(record['ip.len']) if outer == 'ip' else
                      40 + int(record['ipv6.plen'] or 0))
            if outer == 'ipv6' and record.get('ipv6.opt.jumbo') and length == 40:
                length = 40 + int(record['ipv6.opt.jumbo'])
            if length < (20 if outer == 'ip' else 40) or length > flen:
                raise ValueError('invalid length')
        except (ValueError, KeyError):
            totals['invalid_ip_packets'] += 1
            continue
        totals['ip_packets'] += 1
        totals['ipv4_packets' if outer == 'ip' else 'ipv6_packets'] += 1
        totals['ip_bytes'] += length
        src_service, dst_service = service(src), service(dst)
        sl, dl = local(src) and not src_service, local(dst) and not dst_service
        src_s, dst_s = str(src), str(dst)

        def credit(host, metric):
            devices[host][metric] += length
            timeline.add(ns, host, metric, length)

        for host in set(([src_s] if sl else []) + ([dst_s] if dl else [])):
            devices[host]['packets'] += 1
        if src_service or dst_service:
            totals['service_bytes'] += length
            timeline.add(ns, '*', 'service_bytes', length)
            for host in set(([src_s] if sl else []) + ([dst_s] if dl else [])):
                credit(host, 'service_bytes')
        elif sl and dl:
            totals['lan_bytes'] += length  # The aggregate counts this packet once.
            timeline.add(ns, '*', 'lan_tx_bytes', length)
            credit(src_s, 'lan_tx_bytes')
            credit(dst_s, 'lan_rx_bytes')
        elif sl or dl:
            host, remote = (src_s, dst) if sl else (dst_s, src)
            if remote.is_global:
                metric = 'up_bytes' if sl else 'down_bytes'
                totals[metric] += length
                timeline.add(ns, '*', metric, length)
                credit(host, metric)
                entry = conv[(host, str(remote))]
                entry[metric] += length
                entry['packets'] += 1
            else:
                metric = 'other_up_bytes' if sl else 'other_down_bytes'
                totals['other_bytes'] += length
                timeline.add(ns, '*', metric, length)
                credit(host, metric)
        else:
            totals['unassigned_bytes'] += length
            totals['unassigned_packets'] += 1

    if not totals['captured_packets']:
        raise ValueError('文件中没有数据包，或接口筛选后为空')
    valid_time = totals['untimed_packets'] == 0 and timeline.first is not None
    duration = ((timeline.last - timeline.first) / 1e9 if valid_time else None)
    rates_valid = duration is not None and duration > 0
    total_internet = totals['up_bytes'] + totals['down_bytes']
    rows = []
    for ip, data in devices.items():
        total = data['up_bytes'] + data['down_bytes']
        rows.append(dict(data, ip=ip, total_bytes=total,
                         share_percent=100 * total / total_internet if total_internet else 0,
                         up_mbps=data['up_bytes'] * 8 / duration / 1e6 if rates_valid else None,
                         down_mbps=data['down_bytes'] * 8 / duration / 1e6 if rates_valid else None))
    rows.sort(key=lambda row: (-row['total_bytes'], row['ip']))
    curve = timeline.export(valid_time and rates_valid)
    peak = max((sum(item[1:3]) * 8 / curve['interval_seconds'] / 1e6
                for item in curve['series'].get('*', [])), default=0) if curve['count'] else None
    warnings = []
    if not devices:
        warnings.append('没有识别到指定网段内的设备；检查 LAN/WAN 抓包位置、网段和 IPv6 前缀。')
    if not rates_valid:
        warnings.append('时间戳缺失或没有正的观测时长，平均速率和曲线不可用；字节数仍保留。')
    if len(interfaces) > 1:
        warnings.append('抓包包含多个接口，可能重复观察到同一个包；未自动去重，可用 --interface-id 选定接口。')
    if totals['truncated_packets']:
        warnings.append('部分包被截短；完整 IP 头可读时按声明的原始 IP 长度计数。')
    if totals['invalid_ip_packets']:
        warnings.append('部分 IP 头或长度无效，已跳过并计入 invalid_ip_packets。')
    if totals['ipv6_packets'] and not net6:
        warnings.append('未配置公网 IPv6 LAN 前缀；公网 IPv6 设备流量可能未归属，请用 --net6 指定。')
    if totals['unassigned_packets']:
        warnings.append('部分 IP 包无法归属到配置的内网地址，未计入设备公网排行。')
    if curve['interval_seconds'] != float(interval):
        warnings.append('抓包跨度较长，曲线已自动合并时间窗口，以限制报告大小。')
    totals.update(duration_seconds=duration, start=iso_time(timeline.first),
                  end=iso_time(timeline.last), total_bytes=total_internet,
                  average_mbps=total_internet * 8 / duration / 1e6 if rates_valid else None,
                  peak_mbps=peak, device_count=len(rows), interfaces=sorted(interfaces))
    conversations = [dict(data, local_ip=host, remote_ip=remote,
                          total_bytes=data['up_bytes'] + data['down_bytes'])
                     for (host, remote), data in conv.items()]
    conversations.sort(key=lambda row: (-row['total_bytes'], row['local_ip'], row['remote_ip']))
    return {'summary': totals, 'devices': rows, 'conversations': conversations,
            'timeline': curve, 'warnings': warnings, 'networks': [str(net) for net in networks],
            'metrics': METRICS}
