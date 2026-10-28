import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import pcap_traffic_rank as app
from traffic_core import Timeline, analyze_records, tshark_records

TSHARK = BASE / 'Wireshark/tshark.exe'
NETS = [ipaddress.ip_network('192.168.110.0/24')]


def ipv4(src, dst, size=60, proto=17):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, size, 1, 0, 64, proto, 0,
                         ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    payload = struct.pack('!HHHH', 40000, 40001, size - 20, 0) + b'x' * (size - 28)
    return header + payload


def ipv6(src, dst, payload=None, nxt=17):
    payload = payload if payload is not None else struct.pack('!HHHH', 40000, 40001, 16, 0) + b'x' * 8
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), nxt, 64,
                       ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + payload


def ethernet(packet, version=4):
    return bytes.fromhex('0011223344550066778899aa') + struct.pack('!H', 0x0800 if version == 4 else 0x86dd) + packet


def pcap(path, packets, link=1, endian='<', nano=False):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    body = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 65535, link)
    for seconds, fraction, packet in packets:
        body += struct.pack(endian + 'IIII', seconds, fraction, len(packet), len(packet)) + packet
    path.write_bytes(body)


def block(kind, body, endian):
    body += b'\0' * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


def section(endian='<', interfaces=((1, 9, 0),)):
    result = block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    for link, resolution, offset in interfaces:
        options = struct.pack(endian + 'HH', 9, 1) + bytes([resolution, 0, 0, 0])
        options += struct.pack(endian + 'HHq', 14, 8, offset) + b'\0' * 4
        result += block(1, struct.pack(endian + 'HHI', link, 0, 65535) + options, endian)
    return result


def enhanced(packet, timestamp, iface=0, endian='<'):
    return block(6, struct.pack(endian + 'IIIII', iface, timestamp >> 32, timestamp & 0xffffffff,
                               len(packet), len(packet)) + packet, endian)


class TrafficTests(unittest.TestCase):
    def setUp(self):
        root = BASE / 'output/tests'
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='traffic-', dir=str(root))
        self.folder = Path(self.temp.name).resolve()
        assert root.resolve() in self.folder.parents

    def tearDown(self):
        self.temp.cleanup()

    def analyze(self, path, nets=None, interval=1, interface=None):
        return analyze_records(tshark_records(TSHARK, path, interface), nets or NETS, interval)

    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = app.main(args)
        return code, out.getvalue() + err.getvalue()

    def test_demo_regression_and_conservation(self):
        data = self.analyze(BASE / 'demo_capture.pcap')
        s = data['summary']
        self.assertEqual((s['captured_packets'], s['up_bytes'], s['down_bytes']), (5310, 2501320, 2567520))
        self.assertAlmostEqual(s['duration_seconds'], 60.009675, places=8)
        self.assertEqual(sum(row['total_bytes'] for row in data['devices']), 5068840)
        points = data['timeline']['series']['*']
        self.assertEqual(sum(sum(point[1:3]) for point in points), 5068840)

    def test_categories_are_mutually_exclusive(self):
        pairs = [('192.168.110.2', '8.8.8.8'), ('8.8.8.8', '192.168.110.2'),
                 ('192.168.110.2', '192.168.110.3'), ('192.168.110.3', '192.168.110.2'),
                 ('192.168.110.2', '192.168.110.255'), ('192.168.110.2', '224.0.0.251'),
                 ('192.168.110.2', '10.0.0.1'), ('8.8.8.8', '1.1.1.1'),
                 ('192.168.110.0', '8.8.8.8')]
        path = self.folder / 'categories.pcap'
        pcap(path, [(100+i, 0, ethernet(ipv4(a,b))) for i,(a,b) in enumerate(pairs)])
        data = self.analyze(path)
        s = data['summary']
        self.assertEqual([s[k] for k in ['up_bytes','down_bytes','lan_bytes','service_bytes','other_bytes','unassigned_bytes']],
                         [60,60,120,180,60,60])
        self.assertEqual(s['ip_bytes'], sum(s[k] for k in ['up_bytes','down_bytes','lan_bytes','service_bytes','other_bytes','unassigned_bytes']))
        self.assertEqual({r['ip'] for r in data['devices']}, {'192.168.110.2','192.168.110.3'})
        self.assertEqual(sum(r['lan_tx_bytes'] for r in data['devices']), 120)
        self.assertEqual(sum(r['lan_rx_bytes'] for r in data['devices']), 120)
        self.assertEqual(sum(r['total_bytes'] for r in data['devices']), 120)

    def test_raw_ipv6_and_public_prefix(self):
        path = self.folder / 'raw6.pcap'
        host, remote = '2408:8207:1234::2', '2606:4700:4700::1111'
        packet = ipv6(host,remote)
        pcap(path, [(100,0,packet),(102,0,ipv6(remote,host))], link=229)
        data = self.analyze(path, NETS+[ipaddress.ip_network('2408:8207:1234::/48')])
        self.assertEqual((data['summary']['up_bytes'],data['summary']['down_bytes']), (56,56))
        unconfigured = self.analyze(path)
        self.assertEqual(unconfigured['summary']['unassigned_bytes'],112)
        self.assertTrue(any('IPv6 LAN' in w for w in unconfigured['warnings']))

    def test_raw_mixed_ip_and_outer_tunnel_only(self):
        path = self.folder / 'raw.pcap'
        inner = ipv4('192.168.110.8','8.8.8.8')
        tunnel = ipv6('2408:8207:1234::2','2606:4700:4700::1111',inner,nxt=4)
        pcap(path, [(100,0,inner),(101,0,tunnel)],link=101)
        data = self.analyze(path,NETS+[ipaddress.ip_network('2408:8207:1234::/48')])
        self.assertEqual(data['summary']['ip_bytes'],160)
        self.assertEqual(data['summary']['up_bytes'],160)
        self.assertEqual(data['summary']['device_count'],2)

    def test_nanosecond_pcap_big_endian_and_zero_timestamp(self):
        path=self.folder/'nano.pcap'
        pkt=ethernet(ipv4('192.168.110.2','8.8.8.8'))
        pcap(path,[(0,0,pkt),(0,250000001,pkt)],endian='>',nano=True)
        data=self.analyze(path,interval=.1)
        self.assertAlmostEqual(data['summary']['duration_seconds'],.250000001,places=9)
        self.assertEqual(data['timeline']['count'],3)

    def test_pcapng_sections_interfaces_resolutions_offsets(self):
        path=self.folder/'sections.pcapng'
        pkt=ethernet(ipv4('192.168.110.2','8.8.8.8'))
        pkt6=ipv6('2408:8207:1234::2','2606:4700:4700::1111')
        raw=section('>',((1,9,10),(229,0x8a,10)))
        raw+=enhanced(pkt,100_000_000_000,endian='>') # 110 seconds
        raw+=enhanced(pkt6,101*1024,iface=1,endian='>') # 111 seconds
        raw+=section('<',((1,6,20),))
        raw+=enhanced(pkt,92_000_000) # 112 seconds after section reset
        path.write_bytes(raw)
        data=self.analyze(path,NETS+[ipaddress.ip_network('2408:8207:1234::/48')])
        self.assertEqual(data['summary']['ip_bytes'],176)
        self.assertEqual(data['summary']['duration_seconds'],2)
        self.assertTrue(any('多个接口' in w for w in data['warnings']))
        selected=self.analyze(path,NETS+[ipaddress.ip_network('2408:8207:1234::/48')],interface=1)
        self.assertEqual(selected['summary']['captured_packets'],1)
        self.assertEqual(selected['summary']['ipv6_packets'],1)

    def test_untimed_simple_packet_block_disables_rates(self):
        path=self.folder/'untimed.pcapng'
        pkt=ethernet(ipv4('192.168.110.2','8.8.8.8'))
        path.write_bytes(section()+block(3,struct.pack('<I',len(pkt))+pkt,'<'))
        data=self.analyze(path)
        self.assertEqual(data['summary']['up_bytes'],60)
        self.assertIsNone(data['summary']['average_mbps'])
        self.assertEqual(data['timeline']['count'],0)
        self.assertEqual(data['summary']['untimed_packets'],1)
        path.write_bytes(section()+enhanced(pkt,1761667200000000000)+
                         block(3,struct.pack('<I',len(pkt))+pkt,'<'))
        mixed=self.analyze(path)
        self.assertEqual(mixed['summary']['up_bytes'],120)
        self.assertIsNone(mixed['summary']['duration_seconds'])
        self.assertEqual(mixed['timeline']['count'],0)

    def test_truncated_capture_fails_without_report(self):
        path=self.folder/'broken.pcap'
        pcap(path,[(100,0,ethernet(ipv4('192.168.110.2','8.8.8.8')))])
        path.write_bytes(path.read_bytes()[:-5])
        output=self.folder/'broken-report'
        code,text=self.invoke([str(path),'--output-dir',str(output)])
        self.assertEqual(code,1)
        self.assertIn('tshark',text)
        self.assertFalse(output.exists())

    def test_non_ip_time_extends_observation_and_no_division_by_zero(self):
        path=self.folder/'nonip.pcap'
        arp=bytes.fromhex('ffffffffffff0011223344550806')+b'\0'*46
        pkt=ethernet(ipv4('192.168.110.2','8.8.8.8'))
        pcap(path,[(100,0,arp),(102,0,pkt),(110,0,arp)])
        data=self.analyze(path)
        self.assertEqual(data['summary']['duration_seconds'],10)
        self.assertAlmostEqual(data['summary']['average_mbps'],60*8/10/1e6)
        self.assertEqual(data['summary']['non_ip_packets'],2)

    def test_large_timeline_coarsening_preserves_bytes(self):
        timeline=Timeline(.001)
        for ns in [0, 1_000_000, 100_000_000_000, 5_000_000, 4_000_000_000_000]:
            timeline.observe(ns)
            timeline.add(ns,'*','up_bytes',10)
        result=timeline.export(True)
        self.assertLessEqual(result['count'],4096)
        self.assertEqual(sum(p[1] for p in result['series']['*']),50)

    def test_import_skips_renamed_demo_and_empty_directory(self):
        with self.assertRaisesRegex(ValueError,'尚无真实'):
            app.latest_capture(self.folder)
        shutil.copyfile(BASE/'demo_capture.pcap',self.folder/'router.pcap')
        self.assertTrue(app.is_demo(self.folder/'router.pcap'))
        with self.assertRaisesRegex(ValueError,'尚无真实'):
            app.latest_capture(self.folder)
        pcap(self.folder/'lan.pcap',[(100,0,ethernet(ipv4('192.168.110.2','8.8.8.8')))])
        self.assertEqual(app.latest_capture(self.folder).name,'lan.pcap')

    def test_csv_roundtrip_html_escaping_and_source_label(self):
        output=self.folder/'中文 空格 report'
        names=self.folder/'names.json'
        label='=SUM(1,2), "电脑"\n</script><script>alert(1)</script>'
        names.write_text(json.dumps({'192.168.110.133':label}),encoding='utf-8')
        code,text=self.invoke(['--demo','--names',str(names),'--output-dir',str(output)])
        self.assertEqual(code,0,text)
        report=json.loads((output/'report.json').read_text(encoding='utf-8'))
        self.assertEqual(report['source']['kind'],'demo')
        self.assertEqual(report['devices'][0]['name'],label)
        with (output/'devices.csv').open(encoding='utf-8-sig',newline='') as f:
            rows=list(csv.DictReader(f))
        self.assertEqual(rows[0]['name'],"'"+label)
        html=(output/'report.html').read_text(encoding='utf-8')
        self.assertNotIn(label,html)
        self.assertIn('\\u003c/script>',html)

    def test_batch_exit_codes_and_paths_with_spaces(self):
        if os.name != 'nt':
            self.skipTest('Windows batch integration')
        help_result=subprocess.run([str(BASE/'analyze.bat'),'--help'],capture_output=True)
        self.assertEqual(help_result.returncode,0,help_result.stderr)
        self.assertIn(b'--net6',help_result.stdout)
        missing=subprocess.run([str(BASE/'analyze.bat'),str(self.folder/'missing file.pcap')],capture_output=True)
        self.assertEqual(missing.returncode,1)
        path=self.folder/'中文 空格.pcap'
        pcap(path,[(100,0,ethernet(ipv4('192.168.110.2','8.8.8.8'))),
                   (101,0,ethernet(ipv4('8.8.8.8','192.168.110.2')))])
        report=self.folder/'中文 输出'
        ok=subprocess.run([str(BASE/'analyze.bat'),str(path),'--output-dir',str(report)],capture_output=True,cwd=str(self.folder))
        self.assertEqual(ok.returncode,0,ok.stderr)
        self.assertTrue((report/'report.html').exists())

    def test_invalid_inputs_and_existing_report_preserved(self):
        for interval in ['0','-1','nan','inf']:
            code,text=self.invoke(['--demo','--interval',interval])
            self.assertEqual(code,1,text)
        code,_=self.invoke(['--demo','--net6','192.168.0.0/16'])
        self.assertEqual(code,1)
        output=self.folder/'existing'
        output.mkdir()
        (output/'keep.txt').write_text('keep')
        code,text=self.invoke(['--demo','--output-dir',str(output)])
        self.assertEqual(code,1,text)
        self.assertEqual((output/'keep.txt').read_text(),'keep')

    def test_latest_router_import_end_to_end(self):
        capture=self.folder/'router-lan.pcap'
        pcap(capture,[(100,0,ethernet(ipv4('192.168.110.2','8.8.8.8'))),
                      (101,0,ethernet(ipv4('8.8.8.8','192.168.110.2')))])
        config=self.folder/'config.json'
        config.write_text(json.dumps({'networks':['192.168.110.0/24'],'capture_dir':'.',
                                      'report_dir':'reports','source':'router-lan'}))
        code,text=self.invoke(['--config',str(config)])
        self.assertEqual(code,0,text)
        outputs=list((self.folder/'reports').glob('*/report.json'))
        self.assertEqual(len(outputs),1)
        data=json.loads(outputs[0].read_text(encoding='utf-8'))
        self.assertEqual(data['source']['kind'],'router-lan')
        self.assertEqual(data['summary']['total_bytes'],120)


if __name__=='__main__':
    unittest.main()
