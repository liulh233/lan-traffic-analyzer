#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mark_device.py —— 给内网 IP 打上设备名，写进 devices.json

用法:
    python mark_device.py 192.168.110.211 ljj电脑      # 新增 / 改名
    python mark_device.py 192.168.110.211 --remove     # 删掉标记
    python mark_device.py --list                       # 看现有标记
    python mark_device.py --path other.json --list     # 指定文件
"""

import os
import sys
import json
import argparse

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def default_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "devices.json")


def load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            text = f.read().strip()
    except Exception:
        return {}
    if not text:
        return {}
    try:
        obj = json.loads(text)
    except Exception:
        print(f"[!] {path} 不是合法 JSON，先修好再动它")
        sys.exit(1)
    if not isinstance(obj, dict):
        return {}
    return {str(k).strip(): str(v).strip() for k, v in obj.items() if str(v).strip()}


def save(path, data):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser(description="给内网 IP 打设备名（写 devices.json）")
    ap.add_argument("ip", nargs="?", help="设备 IP")
    ap.add_argument("name", nargs="?", help="设备名，如 ljj电脑")
    ap.add_argument("--remove", action="store_true", help="删除该 IP 的标记")
    ap.add_argument("--list", action="store_true", help="列出所有标记")
    ap.add_argument("--path", default=default_path(), help="映射文件路径")
    args = ap.parse_args()

    data = load(args.path)

    if args.list or not args.ip:
        if not data:
            print(f"（{args.path} 里还没有任何标记）")
        else:
            print(f"{args.path}  共 {len(data)} 条：")
            w = max(len(k) for k in data)
            for k in sorted(data, key=lambda s: tuple(int(p) for p in s.split(".") if p.isdigit())):
                print(f"  {k:<{w}}  {data[k]}")
        return 0

    if args.remove:
        if args.ip in data:
            del data[args.ip]
            save(args.path, data)
            print(f"[-] 已删除标记: {args.ip}")
        else:
            print(f"[i] 本来就没有 {args.ip} 的标记")
        return 0

    if not args.name:
        print("[!] 缺设备名。用法: mark_device.py <ip> <name>")
        return 1

    old = data.get(args.ip)
    data[args.ip] = args.name
    save(args.path, data)
    if old and old != args.name:
        print(f"[+] {args.ip}: {old} -> {args.name}")
    else:
        print(f"[+] {args.ip} = {args.name}")
    print(f"    {args.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
