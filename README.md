# NessusParser

**NessusParser** is a collection of Python utilities to convert, filter, and extract information from Nessus `.nessus` and `.csv` scan files.  
It helps penetration testers and security engineers quickly generate CSV reports, per-port/service target lists, and identify hosts affected by specific plugins.

---

## Features
- Convert `.nessus` XML exports into clean CSV reports.
- Extract hosts by port or service into text files for further validation.
- Match findings against a known list of issues (`known_issues.txt`) and generate targeted output.
- Simple command-line interface with subcommands.
- Lightweight, pure Python (no external dependencies).

---

## Repository Structure

```

NessusParser/
├── input/                # Example Nessus and CSV files
├── reporting/            # Example reports and CSV outputs
├── targets/              # Generated target files (per-port/service/known issues)
├── known_issues.txt      # List of plugin names to match against
├── NessusParser.py       # Main script (with subcommands)
└── README.md             # This file

````

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/NessusParser.git
cd NessusParser
````

No external dependencies are required — everything uses the Python standard library.
Requires **Python 3.7+**.

---

## Usage

The tool is run from the command line:

```bash
python3 NessusParser.py <subcommand> [options]
```

### Subcommands

#### 1. `to-csv`

Convert a `.nessus` file into a structured CSV report.

```bash
python3 NessusParser.py to-csv input/example.nessus reporting/report.csv
```

Output example (`report.csv`):

| Risk     | Host     | Port | Name                                | Plugin Output        |
| -------- | -------- | ---- | ----------------------------------- | -------------------- |
| High     | 10.0.0.1 | 443  | SSL/TLS Certificate Expired         | Certificate expired… |
| Critical | 10.0.0.2 | 22   | OpenSSH User Enumeration Vulnerable | Affected version…    |

---

#### 2. `to-files`

Split hosts into per-port target files (`targets/`).

```bash
python3 NessusParser.py to-files input/report.csv targets/
```

Example output files:

```
targets/
├── 22.txt
├── 80.txt
└── 443.txt
```

Each file contains one IP per line.

---

#### 3. `services`

Split hosts into per-service target files (`targets/`).

```bash
python3 NessusParser.py services input/report.csv targets/
```

Example output files:

```
targets/
├── ssh.txt
├── http.txt
└── https.txt
```

Each file contains `host:port` entries.

---

#### 4. `known-issues`

Match Nessus findings against a list of known plugin names stored in `known_issues.txt`.
Generates per-plugin output files in `targets/`.

```bash
python3 NessusParser.py known-issues input/example.nessus targets/
```

Example `known_issues.txt`:

```
SSL/TLS Certificate Expired
Linux Kernel TCP Sequence Number Generation Weakness
ICMP Timestamp Response
```

Example output files:

```
targets/
├── SSL_TLS_Certificate_Expired.txt
├── Linux_Kernel_TCP_Sequence_Number_Generation_Weakness.txt
└── ICMP_Timestamp_Response.txt
```

Each file contains:

```
10.0.0.1:443
10.0.0.2:80
```

---

## Example Workflow

1. Export a `.nessus` file from Nessus.

2. Convert it into CSV:

   ```bash
   python3 NessusParser.py to-csv input/example.nessus reporting/report.csv
   ```

3. Extract hosts by port:

   ```bash
   python3 NessusParser.py to-files reporting/report.csv targets/
   ```

4. Extract hosts by service:

   ```bash
   python3 NessusParser.py services reporting/report.csv targets/
   ```

5. Identify hosts with known issues:

   ```bash
   python3 NessusParser.py known-issues input/example.nessus targets/
   ```

---

## Contributing

Pull requests and feature suggestions are welcome.
If you encounter an issue, please open a GitHub Issue with details and example input.

---

## License

This project is licensed under the MIT License.

```

---

