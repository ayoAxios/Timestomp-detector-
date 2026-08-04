# Timestomp Detector 


A cross‑platform command‑line tool for detecting timestomping anomalies in **MFTECmd** CSV exports (or live MFT parsing). It flags files where the `$STANDARD_INFORMATION` (SI) creation timestamp is older than the `$FILE_NAME` (FN) creation timestamp, optionally considering modification timestamps and various filters to reduce false positives.

---

## Features
- **Fast CSV parsing** – works on large MFT exports (hundreds of thousands of records).
- **Configurable drift threshold** – set the minimum time‑difference (in seconds) to treat as an anomaly.
- **Strict mode** – require both creation **and** modification timestamps to be older.
- **Cluster filtering** – ignore large contiguous blocks of records (e.g., Windows Update batches).
- **Directory ignore list** – built‑in regex patterns for system folders that naturally exhibit timestamp drift.
- **Binary‑only filter** – `--only-binaries` limits analysis to typical executable extensions (`.exe`, `.dll`, `.sys`, `.bat`, `.ps1`).
- **Deduplication** – removes duplicate entries based on the full OS path.
- **Export to CSV** – results can be saved for further investigation.
- **Standalone EXE** – build with PyInstaller for zero‑dependency distribution.

---

## Installation (Python)
```powershell
# Clone / download the repository folder
cd "C:\Path\To\timestomp_fucker"

# Install required packages (if not already present)
python -m pip install -r requirements.txt   # optional – script only uses the standard library
```
The script works with the bundled Python interpreter on Windows, macOS, and Linux.

---

## Building a Standalone Windows Executable
```powershell
# Install PyInstaller (once)
python -m pip install --upgrade pyinstaller

# Build the EXE (creates `dist\timestomp_detector.exe`)
python -m pyinstaller --onefile --windowed --name timestomp_detector timestomp_detector.py
```
The resulting `timestomp_detector.exe` runs on any Windows machine without requiring Python.

---

## Usage
```bash
# Basic analysis (default 5‑second threshold)
python timestomp_detector.py -f <path-to-csv>

# High‑drift threshold, strict mode, cluster filter, binary‑only, export results
python timestomp_detector.py \
    -f "C:\Users\ayo24\Downloads\H.D9OVMPU7Q6L1E-summary\results\All Custom.Windows.NTFS.MFT.csv" \
    -t 86400.0 \
    --strict \
    --cluster-threshold 5 \
    --only-binaries \
    -o "detected_strict.csv"
```

### Command‑Line Options
| Option | Description |
|--------|-------------|
| `-f`, `--csv-file` | Path to the MFTECmd‑generated CSV file (required). |
| `-t`, `--threshold` | Time‑drift threshold in **seconds** (default `5.0`). |
| `-o`, `--output` | Export detected anomalies to the given CSV file. |
| `--strict` | Flag an entry only when **both** creation **and** modification timestamps are older than FN timestamps. |
| `--cluster-threshold N` | Discard clusters of `N` or more consecutive MFT entries that share similar timestamps (helps remove OS/installer bulk updates). |
| `--only-binaries` | Analyse only files with extensions `.exe`, `.dll`, `.sys`, `.bat`, `.ps1`. |
| `--temp-csv <name>` | Temporary file name used for live‑disk parsing (`-live` mode). |
| `-live` | Parse the live C: drive using MFTECmd (requires admin rights and `MFTECmd.exe` in the PATH). |

---

## Reducing False Positives
1. **Increase the threshold** (`-t`) – larger values ignore minor clock‑skew.
2. **Enable strict mode** (`--strict`) – both creation and modification must be older.
3. **Raise the cluster threshold** (`--cluster-threshold`) – filters out bulk installer or update blocks.
4. **Use the binary filter** (`--only-binaries`) – focuses on executables where timestomping is most suspicious.
5. **Add custom ignore patterns** – edit `DEFAULT_IGNORE_PATTERNS` in the script to exclude additional folders (e.g., `C:\Windows\System32`).

---

## Output
The tool prints a concise table (first 50 rows) to the console and writes a CSV with the following columns (if `-o` is used):
- `File Name`
- `Full OSPath`
- `Entry Number`
- `SI_Created`
- `FN_Created`
- `CreatedDeltaSeconds`
- `SI_Lt_FN`
- `ZeroedMillis`
- `Reason`

---

## License & Credits
- Written by **Senior DFIR Engineer** – © 2026.
- Based on Eric Zimmerman's **MFTECmd** output format.
- Binary‑only filter and deduplication are custom enhancements.

---

## Support
Open an issue in the repository or contact the author for questions about false‑positive tuning, additional filters, or extending the tool to other forensic sources.
