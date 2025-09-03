#!/usr/bin/env python3
import csv
import os
import sys
import xml.etree.ElementTree as ET
import argparse

def load_known_issues(filename="known_issues.txt"):
    """Load known issues from a file into a set"""
    if not os.path.exists(filename):
        print(f"[!] {filename} not found. Skipping filtering.")
        return set()
    with open(filename, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def sanitize_filename(name):
    """Replace spaces and illegal filesystem characters"""
    for ch in [' ', '/', '\\', ':', '*', '?', '"', '<', '>', '|']:
        name = name.replace(ch, "_")
    return name

def nessus_to_csv(nessus_file, csv_file):
    """Convert Nessus XML to flat CSV"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Risk", "Host", "Port", "Name", "Service", "Plugin Output"])

        for report_host in root.findall(".//ReportHost"):
            host = report_host.attrib.get("name", "")

            for item in report_host.findall("ReportItem"):
                port = item.attrib.get("port", "")
                name = item.attrib.get("pluginName", "")
                svc_name = item.attrib.get("svc_name", "")
                risk = item.attrib.get("severity", "")

                severity_map = {"0":"None","1":"Low","2":"Medium","3":"High","4":"Critical"}
                risk_label = severity_map.get(risk, risk)

                plugin_output_elem = item.find("plugin_output")
                plugin_output = plugin_output_elem.text.strip() if plugin_output_elem is not None and plugin_output_elem.text else ""

                writer.writerow([risk_label, host, port, name, svc_name, plugin_output])

    print(f"[+] CSV saved as {csv_file}")

def nessus_to_files(nessus_file, out_dir, known_issues_set=None):
    """Generate per-port text files from Nessus XML (optionally filtered)"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    ports = {}

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.attrib.get("name", "")
        for item in report_host.findall("ReportItem"):
            port = item.attrib.get("port", "")
            plugin_title = item.attrib.get("pluginName", "")
            if not ip or not port or port == "0":
                continue
            # If filtering, skip unknown plugins
            if known_issues_set and plugin_title not in known_issues_set:
                continue
            ports.setdefault(port, set()).add(ip)

    os.makedirs(out_dir, exist_ok=True)
    for port, ips in ports.items():
        with open(os.path.join(out_dir, f"{port}.txt"), "w") as f:
            f.write("\n".join(sorted(ips)))
    print(f"[+] Per-port files written to {out_dir}/")

def nessus_to_files_lookup(nessus_file, out_dir, known_issues_set):
    """Generate per-plugin files (host:port) from Nessus XML filtered by known_issues.txt"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    plugins = {}

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.attrib.get("name", "")
        for item in report_host.findall("ReportItem"):
            port = item.attrib.get("port", "")
            plugin_title = item.attrib.get("pluginName", "")
            if not ip or not port or port == "0":
                continue
            if plugin_title in known_issues_set:
                plugins.setdefault(plugin_title, set()).add(f"{ip}:{port}")

    os.makedirs(out_dir, exist_ok=True)
    for plugin, entries in plugins.items():
        filename = sanitize_filename(plugin) + ".txt"
        with open(os.path.join(out_dir, filename), "w") as f:
            f.write("\n".join(sorted(entries)))

    print(f"[+] Per-plugin files written to {out_dir}/")

def csv_to_files(csv_file, out_dir, known_issues_set=None):
    """Generate per-port text files from CSV"""
    ports = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("Host", "").strip()
            port = row.get("Port", "").strip()
            plugin_title = row.get("Name", "").strip()
            if not ip or not port or port == "0":
                continue
            if known_issues_set and plugin_title not in known_issues_set:
                continue
            ports.setdefault(port, set()).add(ip)

    os.makedirs(out_dir, exist_ok=True)
    for port, ips in ports.items():
        with open(os.path.join(out_dir, f"{port}.txt"), "w") as f:
            f.write("\n".join(sorted(ips)))
    print(f"[+] Per-port files written to {out_dir}/")

def csv_to_files_lookup(csv_file, out_dir, known_issues_set):
    """Generate per-plugin files (host:port) from CSV filtered by known_issues.txt"""
    plugins = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("Host", "").strip()
            port = row.get("Port", "").strip()
            plugin_title = row.get("Name", "").strip()
            if not ip or not port or port == "0":
                continue
            if plugin_title in known_issues_set:
                plugins.setdefault(plugin_title, set()).add(f"{ip}:{port}")

    os.makedirs(out_dir, exist_ok=True)
    for plugin, entries in plugins.items():
        filename = sanitize_filename(plugin) + ".txt"
        with open(os.path.join(out_dir, filename), "w") as f:
            f.write("\n".join(sorted(entries)))

    print(f"[+] Per-plugin files written to {out_dir}/")

def nessus_to_service_files(nessus_file, out_dir):
    """Generate per-service host:port files"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    services = {}

    for report_host in root.findall(".//ReportHost"):
        host = report_host.attrib.get("name", "")
        for item in report_host.findall("ReportItem"):
            svc_name = item.attrib.get("svc_name", "")
            port = item.attrib.get("port", "")
            if not host or not port or not svc_name:
                continue
            services.setdefault(svc_name, set()).add(f"{host}:{port}")

    os.makedirs(out_dir, exist_ok=True)
    for svc, entries in services.items():
        with open(os.path.join(out_dir, f"{svc}.txt"), "w") as f:
            f.write("\n".join(sorted(entries)))
    print(f"[+] Service files written to {out_dir}/")

def csv_to_service_files(csv_file, out_dir):
    """Generate per-service host:port files from CSV"""
    services = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = row.get("Host", "").strip()
            port = row.get("Port", "").strip()
            svc_name = row.get("Service", "").strip() or row.get("Name", "").strip()
            if not host or not port or not svc_name:
                continue
            services.setdefault(svc_name, set()).add(f"{host}:{port}")

    os.makedirs(out_dir, exist_ok=True)
    for svc, entries in services.items():
        with open(os.path.join(out_dir, f"{svc}.txt"), "w") as f:
            f.write("\n".join(sorted(entries)))
    print(f"[+] Service files written to {out_dir}/")

def main():
    parser = argparse.ArgumentParser(description="NessusParser - Parse Nessus XML/CSV into CSV, per-port, per-service, or per-plugin files.")
    parser.add_argument("input_file", help="Input .nessus or .csv file (use input/ folder)")
    parser.add_argument("--to-csv", action="store_true", help="Convert Nessus XML to CSV")
    parser.add_argument("--to-files", action="store_true", help="Generate per-port files")
    parser.add_argument("--to-files-lookup", action="store_true", help="Generate per-plugin files filtered by known_issues.txt")
    parser.add_argument("--to-service", action="store_true", help="Generate per-service files")
    parser.add_argument("--output-dir", default="targets", help="Output directory (default: targets/)")

    args = parser.parse_args()
    known_issues_set = None
    if args.to_files_lookup:
        known_issues_set = load_known_issues("known_issues.txt")

    input_file = args.input_file
    out_dir = args.output_dir

    if not os.path.exists(input_file):
        print(f"[-] Input file {input_file} not found.")
        sys.exit(1)

    if input_file.endswith(".nessus"):
        if args.to_csv:
            csv_file = os.path.join(out_dir, "results.csv")
            nessus_to_csv(input_file, csv_file)
        if args.to_files:
            nessus_to_files(input_file, out_dir)
        if args.to_files_lookup:
            nessus_to_files_lookup(input_file, out_dir, known_issues_set)
        if args.to_service:
            nessus_to_service_files(input_file, out_dir)
    elif input_file.endswith(".csv"):
        if args.to_files:
            csv_to_files(input_file, out_dir)
        if args.to_files_lookup:
            csv_to_files_lookup(input_file, out_dir, known_issues_set)
        if args.to_service:
            csv_to_service_files(input_file, out_dir)
    else:
        print("[-] Unsupported file format. Please provide a .nessus or .csv file.")
        sys.exit(1)

if __name__ == "__main__":
    main()

