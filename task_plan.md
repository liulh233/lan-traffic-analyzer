# LAN 流量工具改造

目标：修复 Windows 入口，接入路由器 LAN 导出的真实抓包，校正流量口径，提供可筛选的流量曲线。

## 阶段
- [complete] 修复入口，整理命令行与自动输出约定。
- [complete] 增加 captures 导入目录、来源标签和路由器导入流程；真实文件尚待用户导出提供。
- [complete] 通过本地 tshark 流式解析，区分公网、内网、其他网段和广播/组播；验证 IPv6 与时间精度。
- [complete] 生成离线 HTML 报告、每设备曲线与 CSV/JSON 数据。
- [complete] 15 项回归测试通过；浏览器交互、CSV 下载及 390px 手机布局验证通过；文档已更新。

## 交付状态
代码改造和导入流程完成。真实 LAN 实测仍等待用户从路由器导出文件到 captures；当前只交付明确标记的示例预览。

## 约束与决策
- 用户选择从路由器导出 LAN 抓包；无需启动本机实时抓包。
- 目前仅存在 demo_capture.pcap。真实数据需用户导出后提供，不能把示例或本机抓包当作全 LAN 流量。
- 使用已安装的 Wireshark 工具处理格式，Python 保持标准库实现。
- 保留设备名称配置与现有 demo 报告。

## 已知错误
- analyze.bat 在条件块中 echo 未转义括号，导致传入文件也提前退出。
- 首次 apply_patch 尝试对同一文件同时删除与新增被拒绝；已改为 Update File，无文件丢失。
- Playwright CLI 默认阻止 file URL；改用仅绑定 127.0.0.1 的临时 HTTP 服务器验证，完成后已停止。
- Windows npx.cmd 传递多行 JS 时解析失败；改用 run-code --filename，验证通过。
