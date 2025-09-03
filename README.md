# NessusParser

A **unified Python script** to parse **Nessus scan outputs** (`.nessus` XML or CSV) for vulnerability data, per-port/service reporting, and optional filtering via `known_issues.txt`.

---

## Features

* Convert Nessus `.nessus` XML to **flat CSV** (`Risk, Host, Port, Name, Service, Plugin Output`)
* Generate **per-port IP files**
* Generate **per-port IP files filtered by `known_issues.txt`**
* Generate **per-service IP files** (`host:port`)
* Supports both `.nessus` and `.csv` input formats
* Deduplicates IPs automatically
* Robust XML/CSV parsing with error handling
* Help menu included via `--help`

---

## Requirements

* Python 3.9+
* Standard libraries only (`xml.etree.ElementTree`, `csv`, `os`, `sys`)

No external dependencies required.

---

## Folder Structure

```
NessusParser/
├── NessusParser.py          # Main script
├── known_issues.txt         # Optional, for --to-files-lookup
├── README.md                # This README
├── targets/                 # Output directory
│   ├── 22.txt
│   ├── 80.txt
│   ├── https.txt
│   └── results.csv
├── reporting/               # Optional folder to store aggregated reports
└── input/                   # Folder for input files
    ├── sample.nessus
    └── sample.csv
```

* `NessusParser.py` – the main script handling all parsing modes
* `known_issues.txt` – list of plugins to filter for `--to-files-lookup`
* `targets/` – output directory (user-defined via `--output-dir`)
* `reporting/` – optional folder to store aggregated or formatted reports
* `input/` – place example `.nessus` or `.csv` files for testing

---

## Getting Started

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/NessusParser.git
cd NessusParser
```

2. **Prepare your input files** in the `input/` folder

* `.nessus` XML export from Nessus
* or `.csv` export from Nessus

3. **Optional:** create a `known_issues.txt` file in the same directory for filtered outputs:

```
SSLv3 Protocol Detection
Weak Cipher Suites
Outdated Software Versions
```

4. **Run the parser**

```bash
# Show help menu
python3 NessusParser.py --help

# Convert Nessus XML to CSV
python3 NessusParser.py input/sample.nessus --to-csv --output-dir targets/

# Generate per-port IP files
python3 NessusParser.py input/sample.nessus --to-files --output-dir targets/

# Generate per-port IP files filtered by known issues
python3 NessusParser.py input/sample.nessus --to-files-lookup --output-dir targets/

# Generate per-service files
python3 NessusParser.py input/sample.csv --to-service --output-dir targets/

# Combine multiple outputs in a single run
python3 NessusParser.py input/sample.nessus --to-csv --to-files --to-service --output-dir targets/
```

---

## Example Output

### 1. Flat CSV (`--to-csv`)

```csv
Risk,Host,Port,Name,Service,Plugin Output
High,192.168.1.10,443,SSL Certificate Expired,https,Certificate expired on 2025-08-01
Medium,192.168.1.15,22,SSH Weak Algorithms,ssh,Supports weak key exchange algorithms
Low,192.168.1.20,80,HTTP Security Headers,http,Missing X-Frame-Options header
```

---

### 2. Per-Port Files (`--to-files`)

```
targets/
├── 22.txt
├── 80.txt
└── 443.txt
```

Example content of `22.txt`:

```
192.168.1.15
192.168.1.18
```

---

### 3. Filtered Per-Port Files (`--to-files-lookup`)

```
targets/
├── 443.txt
```

Example content of `443.txt`:

```
192.168.1.10
```

---

### 4. Per-Service Files (`--to-service`)

```
targets/
├── https.txt
├── ssh.txt
└── http.txt
```

Example content of `https.txt`:

```
192.168.1.10:443
192.168.1.25:443
```

---

## Notes

* `known_issues.txt` should be placed in the same directory as the script for filtered outputs
* Outputs are **deduplicated automatically**
* Supports flexible organization via `--output-dir`
* Combine switches to generate multiple outputs in a single run
* Input files should be placed in the `input/` folder, outputs will go to `targets/`

---

## License

MIT License

---


