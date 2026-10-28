# 发现

- 工作区包含 Wireshark 4.6.9、Python 3.11.9、纯 Python 分析脚本和示例 pcap。
- 原脚本把内网互访计入上下行，同一包在设备合计中重复；pcapng 固定微秒和小端；Raw IPv6 被当作 IPv4。
- demo_capture.pcap：5310 包，IP 字节 5068840，约 60.009675 秒，5 个本地 IPv4 地址，0 IPv6。
- 本机存在 WLAN/Npcap 接口，但用户选择路由器导出，不使用本机流量替代全 LAN。
- 路由器真实抓包尚未提供。
- 采用 Wireshark 原生解析替代自写 pcap/pcapng 读取；Python 按最外层 IP 流式聚合，禁止解析时 DNS 查询。
- 用实际二进制测试确认大端 pcapng、多 section、逐接口十进制/二进制时间精度和时间偏移有效。
- 示例新旧公网统计一致（5068840 字节），1 秒窗口公网合计峰值为约 0.718 Mbps。
- 官方参考：https://www.wireshark.org/docs/man-pages/tshark.html （字段输出、occurrence、禁用名称解析和会话重置）。
