# LAN 流量分析工具

分析路由器 LAN 导出的抓包文件，生成设备公网流量排行、内网互传统计和可切换设备的流量曲线。报告在本地生成，不需要上传数据或安装 Python 第三方包。

## 安装

仓库里不含 `Wireshark/`（269 MB 第三方二进制）。分析需要 Wireshark 的 `tshark.exe`，按下面的方式自己装一份：

```powershell
git clone https://github.com/<你的账号>/lan-traffic-analyzer.git "D:\auto_ai\tsshark tool"
cd "D:\auto_ai\tsshark tool"
winget install --id WiresharkFoundation.Wireshark --location "D:\auto_ai\tsshark tool\Wireshark"
```

- 只用到 `tshark.exe`，不需要重启；Npcap 抓包驱动只在实时抓包时用得上，分析 pcap 文件不需要。
- 脚本查找 tshark 的顺序：`--tshark` 参数 → 本目录 `Wireshark/` → 系统 `PATH`。装在默认位置（`C:\Program Files\Wireshark`）并加入 PATH 也能直接用。
- Python 3.8+ 即可，不需要 `pip install` 任何东西。

## 开始使用真实数据

1. 在路由器管理页进入抓包功能，选择 **LAN / LAN bridge、NAT 之前的接口**。本网络网关为 `192.168.110.1`。不要抓 WAN，否则 NAT 会把多个设备合成同一个地址。
2. 先抓 60 秒，保持需要排查的业务正常运行。过滤留空，文件上限应足以覆盖这段时间；导出前停止抓包。
3. 将 `.pcap`、`.pcapng` 或 `.cap` 文件放进本项目的 `captures` 文件夹。
4. 在项目目录的 PowerShell 中执行：

```powershell
.\analyze.bat --open
```

自动读取 `captures` 中修改时间最新的非示例文件，并打开生成的离线 HTML 报告。不会合并多个文件。目录为空时会明确提示，不会偷偷改用示例数据。

也可以把抓包文件拖到 `analyze.bat`，或明确指定路径：

```powershell
.\analyze.bat "D:\captures\路由器 LAN.pcapng" --open
```

每次运行都会在 `reports` 下建立独立目录，保留旧报告。显式指定 `--output-dir` 时，该目录必须不存在或为空。

**当前仓库只有示例抓包。** 如尚未导出真实数据，使用下面的命令演示功能：

```powershell
.\analyze.bat --demo --open
```

文件名含 demo/sample/test 标记或内容与已知示例 SHA256 相同的文件会标为示例；即使改名也不会把已知示例当成真实数据。任意未知文件的真实性无法由工具自动证明，来源标签是用户声明。

## 配置 LAN 网段

编辑 `analysis_config.json`：

```json
{
  "networks": ["192.168.110.0/24"],
  "networks6": [],
  "source": "router-lan",
  "capture_dir": "captures",
  "report_dir": "reports",
  "interval_seconds": 1
}
```

- `networks`：实际 LAN 的 IPv4 网段。多 VLAN 可填写多个前缀。
- `networks6`：路由器分配给 LAN 的实际 IPv6 前缀。有公网 IPv6 时应填写，否则该部分可能无法归属到内网设备。IPv6 链路本地和 ULA 地址默认识别为本地。
- `source`：`router-lan`、`mirror`、`host`、`unknown` 或 `demo`。普通电脑 WLAN 抓包只表示该网卡可见的流量，不代表全 LAN。
- 配置中的相对路径相对于配置文件所在目录；命令行的文件路径相对于当前工作目录。

命令行覆盖配置：

```powershell
.\analyze.bat capture.pcapng -n 192.168.110.0/24 --net6 2408:8207:1234::/48 --open
# 上面的 IPv6 前缀仅为写法示例，必须替换为路由器的实际前缀。
.\analyze.bat capture.pcapng -n 192.168.110.0/24 -n 192.168.120.0/24
```

指定 `-n` 会替换配置中的 IPv4 列表，`--net6` 会替换 IPv6 列表；两者可重复使用。请勿将远端服务器网段或 `0.0.0.0/0` 当作 LAN。

## 报告内容

每个运行目录包含：

| 文件 | 内容 |
|---|---|
| `report.html` | 完全离线的交互报告，支持设备/流量类型切换、时间窗口数值、搜索与排序 |
| `devices.csv` | 每个内网 IP 的公网上下行、内网收发、其他网段及服务流量 |
| `conversations.csv` | 每个内网 IP 与公网对端的上行、下行及包数 |
| `timeline.csv` | 时间曲线的稀疏窗口数据，含每个地址及汇总 |
| `report.json` | 全部统计、来源 SHA256、时间范围、配置和解析提示 |
| `summary.txt` | 终端摘要的 UTF-8 文本副本 |

报告顶部的平均值与峰值是所有内网地址的**公网收发合计**；切换设备只改变下方曲线。设备名称来自 `devices.json`。IPv4 与 IPv6 地址暂不自动合并为同一物理设备。

## 统计口径

- **公网收发**：配置的本地地址与公网单播地址之间的最外层 IP 数据。公网发送为上行，接收为下行。
- **内网互传**：两端均属于本地网段。总量每包只计一次；设备明细分别记录发送者的 `lan_tx_bytes` 和接收者的 `lan_rx_bytes`，不能把这两列跨设备相加当成唯一传输量。
- **其他网段**：本地地址与其他非公网单播地址之间的数据，例如其他私网或运营商共享地址；不混入公网上下行。
- **广播/组播等**：广播、组播、未指定地址及不可作普通主机的地址相关流量，单独统计，不产生虚假设备排行。
- **未归属**：已解析到 IP，但无法归到本地地址的单播流量。常见原因是网段或公网 IPv6 前缀未配置。
- IP 分类字节守恒：公网上行 + 公网下行 + 内网互传 + 其他网段 + 广播/组播等 + 未归属 = 已统计 IP 字节。
- 使用 IP 声明长度，包含重传和 IP 头，不含 Ethernet 头；不等于业务文件大小或运营商账单。ARP 等非 IP/未解码帧单独计包数，不纳入 IP 字节。
- 首末包时间（含非 IP 包）决定观测时长。时间戳缺失或没有正时长时，速率和曲线显示不可用，不编造值。
- 默认曲线使用对齐时钟的 **1 秒固定窗口**。边缘不足一窗也使用完整窗口作分母，所以曲线峰值不是瞬时速率；其窗口平均与首末包时长平均可能不同。
- 超过 4096 个窗口时自动扩大窗口并明确提示。解析流式进行，不把全部原始包放入 Python 内存；内存仍随地址数和对端组合数增加。
- pcapng 多接口可能在不同接口观察到同一个包，程序提示但不猜测去重规则。可用 `--interface-id` 选择一个观测接口。
- **公网流量占比不是宽带利用率**。没有链路容量、覆盖范围和丢包证据，不能仅凭本报告判断网络拥堵。

`timeline.csv` 是稀疏格式：没有记录的窗口表示该指标在抓包中观测到 0；`ip=*` 是汇总。汇总行 `lan_tx_bytes` 为内网传输单次计数，`lan_rx_bytes` 为 0。窗口起点、总窗口数和实际宽度见 JSON 的 `timeline`。区间为左闭右开，单位 KiB/MiB 为 1024 进制，Mbps 为十进制。

## 参数与兼容用法

```powershell
.\analyze.bat --help
.\analyze.bat capture.pcap --conv 20 --csv report.csv
.\analyze.bat capture.pcapng --interval 5 --interface-id 0 --open
.\analyze.bat capture.pcap --no-names
.\analyze.bat capture.pcap --names other-devices.json --source mirror
.\mark.bat 192.168.110.211 ljj电脑
.\mark.bat --list
```

`--csv` 是额外导出，可覆盖该显式指定的 CSV；自动生成的报告目录不会覆盖。CSV 带 UTF-8 BOM，并处理逗号、引号、换行和以公式符号开头的名称。

## 运行环境与验证

- Windows；Python **3.8+**。入口依次探测 `py -3`、`python`、`python3`，传递实际退出码。
- 解码交给 Wireshark 的 `tshark`（开发时用 4.6.9），路径查找顺序见上文「安装」。**分析器不再使用旧的自写 pcap/pcapng 解码器，也不再是脱离 Wireshark 的单文件脚本。** Python 代码仍只使用标准库。
- tshark 处理 pcap/pcapng、不同字节序、逐接口时间精度、IPv6、VLAN 等格式。读取时关闭 DNS 名称解析和重组，周期性重置会话；不会主动联网查询对端。
- 损坏文件、写入中的文件和无效参数会报错；多接口、截短包、未归属流量和缺失 IPv6 前缀会出提示。
- 自动化验证：

```powershell
python -m unittest discover -s tests -v
```

协议测试使用明确构造的测试包，不能作为真实网络抓包。官方字段与命令说明：[TShark 手册](https://www.wireshark.org/docs/man-pages/tshark.html)。
