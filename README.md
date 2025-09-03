# NessusParser

**NessusParser** is a unified Python tool for parsing Nessus `.nessus` XML or `.csv` reports into different useful formats:

* **CSV** summary (`--to-csv`)
* **Per-port target files** (`--to-files`)
* **Per-plugin lookup files** (`--to-files-lookup`)
* **Per-service files** (`--to-service`)

It’s designed to support vulnerability validation, service enumeration, and reporting workflows.

---

## Features

* Supports **Nessus XML (`.nessus`)** and **CSV exports**
* Convert Nessus reports into:

  * Flat CSV files for analysis
  * Per-port IP lists
  * Per-plugin host\:port lists (filtered by `known_issues.txt`)
  * Per-service host\:port lists
* Configurable output directory (default: `targets/`)
* Uses `known_issues.txt` for targeted validation

---

## Repository Layout

```
.
├── NessusParser.py        # Main script (all-in-one)
├── known_issues.txt       # List of plugin titles to track (for lookup mode)
├── input/                 # Example Nessus/CSV input files
├── targets/               # Default output directory for parsing results
└── reporting/             # Placeholder for reporting scripts or exports
```

---

## Installation

Clone the repo and install Python dependencies (only standard library required):

```bash
git clone https://github.com/yourusername/NessusParser.git
cd NessusParser
```

Python 3.7+ is recommended. No external packages required.

---

## Usage

### Help Menu

```bash
python3 NessusParser.py --help
```

Example output:

```
usage: NessusParser.py [-h] [--to-csv] [--to-files] [--to-files-lookup] [--to-service] [--output-dir OUTPUT_DIR] input_file

NessusParser - Parse Nessus XML/CSV into CSV, per-port, per-service, or per-plugin files.

positional arguments:
  input_file            Input .nessus or .csv file (use input/ folder)

options:
  -h, --help            show this help message and exit
  --to-csv              Convert Nessus XML to CSV
  --to-files            Generate per-port files
  --to-files-lookup     Generate per-plugin files filtered by known_issues.txt
  --to-service          Generate per-service files
  --output-dir OUTPUT_DIR
                        Output directory (default: targets/)
```

---

### 1. Convert Nessus XML to CSV

```bash
python3 NessusParser.py input/scan.nessus --to-csv --output-dir targets/
```

Output:

```
targets/results.csv
```

---

### 2. Generate Per-Port Target Files

```bash
python3 NessusParser.py input/scan.csv --to-files --output-dir targets/
```

Output:

```
targets/80.txt
targets/443.txt
targets/3389.txt
...
```

Each file contains a list of IPs with that port open.

---

### 3. Generate Per-Plugin Lookup Files

This mode uses **known\_issues.txt** to track specific plugin titles.
Each output file is named after the plugin (spaces replaced with `_`) and contains `host:port` pairs.

Example `known_issues.txt`:

```
SSL Certificate Expiry
Apache HTTPD Multiple Vulnerabilities
Weak SSH Algorithms Supported
```

Run:

```bash
python3 NessusParser.py input/scan.nessus --to-files-lookup --output-dir targets/
```

Output:

```
targets/SSL_Certificate_Expiry.txt
targets/Apache_HTTPD_Multiple_Vulnerabilities.txt
targets/Weak_SSH_Algorithms_Supported.txt
```

Each file looks like:

```
10.0.0.5:443
10.0.0.8:22
```

---

### 4. Generate Per-Service Files

```bash
python3 NessusParser.py input/scan.csv --to-service --output-dir targets/
```

Output:

```
targets/ssh.txt
targets/http.txt
targets/https.txt
targets/smb.txt
```

Each file contains host\:port pairs for that service.

---

## Example Workflow

1. Export a `.nessus` or `.csv` file from Nessus
2. Place it in the `input/` folder
3. Run one of the parsing commands above
4. Collect results from the `targets/` folder
5. Use `reporting/` for custom analysis

---

## Future Ideas

* HTML reporting in `reporting/`
* Integration with **Validator** app
* JSON export for pipelines

---

## License

MIT License. Use at your own risk.

---

