#!/usr/bin/env python3
import argparse
import csv
import os
import xml.etree.ElementTree as ET

# ----------------------------
# CSV Conversion
# ----------------------------
def nessus_to_csv(filename, output_file):
    tree = ET.parse(filename)
    root = tree.getroot()

    headers = ["Host", "Port", "Service", "Protocol", "Plugin ID", "Name", "Severity"]
    rows = []

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.attrib.get("name")
        for item in report_host.findall("ReportItem"):
            port = item.attrib.get("port")
            service = item.attrib.get("svc_name")
            protocol = item.attrib.get("protocol")
            plugin_id = item.attrib.get("pluginID")
            plugin_name = item.attrib.get("pluginName")
            severity = item.attrib.get("severity")

            rows.append([ip, port, service, protocol, plugin_id, plugin_name, severity])

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"[+] CSV report written to {output_file}")


# ----------------------------
# Per-Port Target Files
# ----------------------------
def parse_csv_to_ports(filename, output_dir):
    with open(filename, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        ports = {}

        for row in reader:
            ip = row.get("Host", "").strip()
            port = row.get("Port", "").strip()
            if not ip or not port or port == "0":
                continue
            ports.setdefault(port, set()).add(ip)

    os.makedirs(output_dir, exist_ok=True)
    for port, ips in ports.items():
        with open(os.path.join(output_dir, f"{port}.txt"), "w") as f:
            f.write("\n".join(sorted(ips)))
    print(f"[+] Per-port target files saved in '{output_dir}'.")


def parse_nessus_to_ports(filename, output_dir):
    tree = ET.parse(filename)
    root = tree.getroot()
    ports = {}

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.attrib.get("name")
        for item in report_host.findall("ReportItem"):
            port = item.attrib.get("port")
            if not ip or not port or port == "0":
                continue
            ports.setdefault(port, set()).add(ip)

    os.makedirs(output_dir, exist_ok=True)
    for port, ips in ports.items():
        with open(os.path.join(output_dir, f"{port}.txt"), "w") as f:
            f.write("\n".join(sorted(ips)))
    print(f"[+] Per-port target files saved in '{output_dir}'.")


# ----------------------------
# Per-Service Target Files
# ----------------------------
def parse_csv_to_services(filename, output_dir):
    with open(filename, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        services = {}

        for row in reader:
            ip = row.get("Host", "").strip()
            port = row.get("Port", "").strip()
            service = row.get("Service", "").strip()
            if not ip or not port or port == "0":
                continue
            key = service if service else f"port_{port}"
            services.setdefault(key, set()).add(f"{ip}:{port}")

    os.makedirs(output_dir, exist_ok=True)
    for service, entries in services.items():
        filename = service.replace(" ", "_") + ".txt"
        with open(os.path.join(output_dir, filename), "w") as f:
            f.write("\n".join(sorted(entries)))
    print(f"[+] Per-service target files saved in '{output_dir}'.")


def parse_nessus_to_services(filename, output_dir):
    tree = ET.parse(filename)
    root = tree.getroot()
    services = {}

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.attrib.get("name")
        for item in report_host.findall("ReportItem"):
            port = item.attrib.get("port")
            service = item.attrib.get("svc_name", "")
            if not ip or not port or port == "0":
                continue
            key = service if service else f"port_{port}"
            services.setdefault(key, set()).add(f"{ip}:{port}")

    os.makedirs(output_dir, exist_ok=True)
    for service, entries in services.items():
        filename = service.replace(" ", "_") + ".txt"
        with open(os.path.join(output_dir, filename), "w") as f:
            f.write("\n".join(sorted(entries)))
    print(f"[+] Per-service target files saved in '{output_dir}'.")


# ----------------------------
# Per-Known-Issue Target Files
# ----------------------------
def load_known_issues(filename="known_issues.txt"):
    with open(filename, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


def parse_csv_to_known(filename, known_issues, output_dir):
    with open(filename, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        findings = {}

        for row in reader:
            ip = row.get("Host", "").strip()
            port = row.get("Port", "").strip()
            plugin_title = row.get("Name", "").strip()

            if not ip or not port or port == "0":
                continue
            if plugin_title in known_issues:
                findings.setdefault(plugin_title, set()).add(f"{ip}:{port}")

    os.makedirs(output_dir, exist_ok=True)
    for plugin_title, entries in findings.items():
        filename = plugin_title.replace(" ", "_") + ".txt"
        with open(os.path.join(output_dir, filename), "w") as f:
            f.write("\n".join(sorted(entries)))
    print(f"[+] Per-known-issue target files saved in '{output_dir}'.")


def parse_nessus_to_known(filename, known_issues_file, output_dir):
    known_issues = load_known_issues(known_issues_file)
    tree = ET.parse(filename)
    root = tree.getroot()
    findings = {}

    for report_host in root.findall(".//ReportHost"):
        ip = report_host.attrib.get("name")
        for item in report_host.findall("ReportItem"):
            port = item.attrib.get("port")
            plugin_title = item.attrib.get("pluginName") or item.attrib.get("svc_name", "")

            if not ip or not port or port == "0":
                continue
            if plugin_title in known_issues:
                findings.setdefault(plugin_title, set()).add(f"{ip}:{port}")

    os.makedirs(output_dir, exist_ok=True)
    for plugin_title, entries in findings.items():
        filename = plugin_title.replace(" ", "_") + ".txt"
        with open(os.path.join(output_dir, filename), "w") as f:
            f.write("\n".join(sorted(entries)))
    print(f"[+] Per-known-issue target files saved in '{output_dir}'.")


# ----------------------------
# Main
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Nessus Parser - Convert Nessus scan files into different formats")
    parser.add_argument("input", help="Input .nessus or .csv file")
    parser.add_argument("--to-csv", action="store_true", help="Convert Nessus file to CSV report")
    parser.add_argument("--to-files", action="store_true", help="Generate per-port target files")
    parser.add_argument("--to-files-service", action="store_true", help="Generate per-service target files")
    parser.add_argument("--to-files-known", action="store_true", help="Generate per-known-issue target files (uses known_issues.txt)")
    parser.add_argument("--outdir", default="targets", help="Output directory (default: targets)")
    args = parser.parse_args()

    if args.to_csv:
        nessus_to_csv(args.input, os.path.join("reporting", "results.csv"))

    if args.to_files:
        if args.input.endswith(".nessus"):
            parse_nessus_to_ports(args.input, args.outdir)
        else:
            parse_csv_to_ports(args.input, args.outdir)

    if args.to_files_service:
        if args.input.endswith(".nessus"):
            parse_nessus_to_services(args.input, args.outdir)
        else:
            parse_csv_to_services(args.input, args.outdir)

    if args.to_files_known:
        if args.input.endswith(".nessus"):
            parse_nessus_to_known(args.input, "known_issues.txt", args.outdir)
        else:
            parse_csv_to_known(args.input, load_known_issues("known_issues.txt"), args.outdir)


if __name__ == "__main__":
    main()

