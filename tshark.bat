@echo off
rem tshark quick launcher - run tshark without full path
rem example: tshark -r capture.pcap -q -z endpoints,ip
"%~dp0Wireshark\tshark.exe" %*
