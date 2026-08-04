import os
import sys
import csv
import re
import argparse
from datetime import datetime, timezone

# ----------------------------------------------------------------------
# TIMESTOMP DETECTOR - SENIOR DFIR ANALYSIS TOOL
# Parses MFTECmd CSV output or raw MFT file (via raw-reading or mftecmd wrappers)
# to detect timestomping anomalies.
# ----------------------------------------------------------------------

# Default Exclusions: Regex patterns for directories that naturally exhibit
# timestamp drift during system updates, servicing, etc.
DEFAULT_IGNORE_PATTERNS = [
    r'[\\/]Windows[\\/]servicing[\\/]',
    r'[\\/]WinSxS[\\/]',
    r'[\\/]SoftwareDistribution[\\/]',
    r'[\\/]Program Files[\\/]',
    r'[\\/]Program Files \(x86\)[\\/]',
    r'[\\/]Windows[\\/]assembly[\\/]',
    r'[\\/]Windows[\\/]Microsoft\.NET[\\/]',
]

def parse_mftecmd_timestamp(ts_str):
    """
    Parses MFTECmd timestamp format: YYYY-MM-DD HH:MM:SS.ffffff or ISO format YYYY-MM-DDTHH:MM:SS.ffffffZ
    Returns datetime object in UTC, or None if invalid/empty.
    """
    if not ts_str or ts_str.strip() == "":
        return None
    
    # Strip any trailing whitespace
    ts_str = ts_str.strip()
    
    # Pre-process ISO 8601 UTC representations
    ts_clean = ts_str.replace("T", " ").replace("Z", "")
    
    # Handle common formats
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            # MFTECmd might have up to 7 or more decimal digits for sub-seconds; Python supports 6 (%f).
            # We will truncate sub-seconds to 6 digits if necessary.
            if "." in ts_clean:
                parts = ts_clean.split(".")
                if len(parts) == 2:
                    subsecs = parts[1][:6]
                    ts_clean = f"{parts[0]}.{subsecs}"
            return datetime.strptime(ts_clean, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def has_zeroed_milliseconds(ts_str):
    """
    Returns True if the timestamp ends in exactly .000000 but has a timestamp structure,
    indicating subsecond zeroing (common in anti-forensics tools).
    """
    if not ts_str or ts_str.strip() == "":
        return False
    ts_str = ts_str.strip()
    if "." in ts_str:
        parts = ts_str.split(".")
        if len(parts) == 2:
            # If the fractional part is all zeros, it could be zeroed.
            # We want to flag if SI is zeroed (.000000) while FN is not,
            # or if SI contains exactly '.000000' or '.0000000'.
            frac = parts[1]
            # Match 6 or 7 zeroes
            if frac.startswith("000000"):
                return True
    return False

def analyze_mft_csv(csv_path, drift_threshold_seconds, ignore_regex_list, export_csv_path=None, strict=False, cluster_threshold=0, only_binaries=False):
    """
    Reads MFTECmd CSV output file and performs timestomp detection analysis.
    """
    print(f"[*] Reading and analyzing CSV: {csv_path}")
    print(f"[*] Drift Threshold: {drift_threshold_seconds} seconds")
    
    ignore_compiled = [re.compile(p, re.IGNORECASE) for p in ignore_regex_list]
    
    results = []
    
    try:
        with open(csv_path, mode='r', encoding='utf-8', errors='ignore') as f:
            # We use a DictReader to match column headers dynamically
            reader = csv.DictReader(f)
            
            # Identify headers
            headers = reader.fieldnames
            if not headers:
                print("[-] Error: Empty CSV file or invalid header row.")
                return
            
            # Map column names (handling potential case variations)
            col_map = {}
            required_fields = {
                'FileName': ['FileName', 'File Name', 'Filename'],
                'ParentPath': ['ParentPath', 'Parent Path', 'Path'],
                'OSPath': ['OSPath', 'Full OSPath', 'FullPath'],
                'EntryNumber': ['EntryNumber', 'Entry Number', 'RecordNumber', 'Record Number'],
                'Created0x10': ['Created0x10', 'Created 0x10', 'SI_Created', 'StandardInformationCreated'],
                'Created0x30': ['Created0x30', 'Created 0x30', 'FN_Created', 'FileNameCreated'],
                'Modified0x10': ['LastModified0x10', 'Modified0x10', 'Modified 0x10', 'SI_Modified'],
                'Modified0x30': ['LastModified0x30', 'Modified0x30', 'Modified 0x30', 'FN_Modified'],
                'IsDirectory': ['IsDirectory', 'IsDir', 'Directory'],
            }
            
            for key, options in required_fields.items():
                for opt in options:
                    # Case insensitive search
                    match = next((h for h in headers if h.lower() == opt.lower()), None)
                    if match:
                        col_map[key] = match
                        break
            
            # Diagnostic check
            missing = [k for k in ['FileName', 'Created0x10', 'Created0x30'] if k not in col_map]
            if missing:
                print(f"[-] Error: Could not map required CSV headers: {missing}")
                print(f"Available headers: {headers[:15]}...")
                return

            print("[*] Successfully mapped CSV fields:")
            for k, v in col_map.items():
                print(f"    - {k} -> '{v}'")

            row_count = 0
            match_count = 0
            
            for row in reader:
                row_count += 1
                
                # Check for Directory Exclusions
                is_dir_val = row.get(col_map.get('IsDirectory', ''), '').lower()
                if is_dir_val in ('true', 'yes', '1'):
                    continue
                
                parent_path = row.get(col_map.get('ParentPath', ''), '')
                file_name = row.get(col_map.get('FileName', ''), '')
                full_path = row.get(col_map.get('OSPath', ''), '')
                if not full_path:
                    full_path = os.path.join(parent_path, file_name)
                
                # Strip raw device namespace prefix (\\.\) if present at the start
                if full_path.startswith("\\\\.\\"):
                    full_path = full_path[4:]
                
                # Apply regex-based ignore list on path
                ignored = False
                for pattern in ignore_compiled:
                    if pattern.search(full_path):
                        ignored = True
                        break
                if ignored:
                    continue
                # Binary filter: only keep .exe and .dll when option is set
                if only_binaries:
                    ext = os.path.splitext(full_path)[1].lower()
                    if ext not in ('.exe', '.dll'):
                        continue
                
                entry_num = row.get(col_map.get('EntryNumber', ''), 'N/A')
                
                # Extract and parse raw timestamps
                si_created_raw = row.get(col_map.get('Created0x10', ''), '')
                fn_created_raw = row.get(col_map.get('Created0x30', ''), '')
                si_modified_raw = row.get(col_map.get('Modified0x10', ''), '')
                fn_modified_raw = row.get(col_map.get('Modified0x30', ''), '')
                
                # In MFTECmd, if 0x30 equals 0x10, the 0x30 field is left blank.
                # In that case, there is no mismatch/timestomp (FN equals SI).
                if not fn_created_raw or fn_created_raw.strip() == "":
                    # No 0x30 timestamp implies identical to 0x10, so skip
                    continue
                
                si_created = parse_mftecmd_timestamp(si_created_raw)
                fn_created = parse_mftecmd_timestamp(fn_created_raw)
                
                if not si_created or not fn_created:
                    continue
                
                # Core Anomaly Detection Logic:
                # Flag if $STANDARD_INFORMATION Creation timestamp is OLDER than $FILE_NAME Creation timestamp
                # taking into account the time-drift threshold.
                delta_seconds = (fn_created - si_created).total_seconds()
                si_lt_fn = si_created < fn_created
                
                is_timestomped = False
                reason = ""
                
                if delta_seconds > drift_threshold_seconds:
                    # In strict mode, we also verify if LastModified timestamp shows a discrepancy.
                    # Since 0x30 is blank if same as 0x10, if fn_modified is empty, they are equal.
                    # Equal modified dates means modified was NOT backdated, so it's likely just a standard file copy.
                    if strict:
                        if fn_modified_raw and fn_modified_raw.strip() != "":
                            si_mod = parse_mftecmd_timestamp(si_modified_raw)
                            fn_mod = parse_mftecmd_timestamp(fn_modified_raw)
                            if si_mod and fn_mod and (fn_mod - si_mod).total_seconds() > drift_threshold_seconds:
                                is_timestomped = True
                                reason = f"SI Created & Modified are older than FN ({delta_seconds:.1f}s / {(fn_mod - si_mod).total_seconds():.1f}s)"
                    else:
                        is_timestomped = True
                        reason = f"SI Created is older than FN Created by {delta_seconds:.3f}s"
                
                # Zeroed milliseconds check:
                # If SI has exactly '.000000' but FN has non-zero subseconds (e.g., .123456)
                is_zeroed_millis = False
                if has_zeroed_milliseconds(si_created_raw) and not has_zeroed_milliseconds(fn_created_raw):
                    is_zeroed_millis = True
                    is_timestomped = True
                    if reason:
                        reason += " & Zeroed Milliseconds in SI"
                    else:
                        reason = "Zeroed Milliseconds in SI (.000000)"
                
                if is_timestomped:
                    match_count += 1
                    try:
                        parsed_entry = int(entry_num)
                    except ValueError:
                        parsed_entry = -1
                    results.append({
                        'File Name': file_name,
                        'Full OSPath': full_path,
                        'Entry Number': entry_num,
                        'EntryInt': parsed_entry,
                        'SI_Created': si_created_raw,
                        'FN_Created': fn_created_raw,
                        'CreatedDeltaSeconds': round(delta_seconds, 6),
                        'SI_Lt_FN': si_lt_fn,
                        'ZeroedMillis': is_zeroed_millis,
                        'Reason': reason
                    })
            
            # --- Approach 1: MFT Record Sequence Clustering Filter ---
            if cluster_threshold > 0 and results:
                print(f"[*] Applying MFT Sequence Clustering Filter (Threshold: {cluster_threshold})...")
                # Sort findings by entry number to identify physical disk clusters
                results.sort(key=lambda x: x['EntryInt'])
                
                filtered_results = []
                i = 0
                n = len(results)
                
                while i < n:
                    # Find contiguous clusters of record numbers
                    cluster = [results[i]]
                    j = i + 1
                    while j < n and (results[j]['EntryInt'] - results[j-1]['EntryInt']) <= 5: # tolerating a gap of up to 5 entries
                        cluster.append(results[j])
                        j += 1
                    
                    # If this sequence group is larger than the cluster threshold, we treat it as an OS/Installer update block
                    if len(cluster) >= cluster_threshold:
                        # Skip this cluster (discard as false positives)
                        pass
                    else:
                        filtered_results.extend(cluster)
                    i = j
                
                results = filtered_results
                # Deduplicate entries based on Full OSPath
                seen_paths = set()
                deduped = []
                for r in results:
                    path = r.get('Full OSPath')
                    if path and path not in seen_paths:
                        seen_paths.add(path)
                        deduped.append(r)
                results = deduped
                match_count = len(results)

            print(f"[*] Processed {row_count} records. Found {match_count} timestomping anomalies after filtering and deduplication.")
            
    except Exception as e:
        print(f"[-] Error parsing CSV: {e}")
        return

    # Print results to terminal in a clean table view
    if results:
        print("\n" + "="*132)
        print(f"{'Entry':<8} | {'File Name':<25} | {'SI Created':<23} | {'FN Created':<23} | {'Delta (s)':<10} | {'ZeroedMS':<8} | {'Reason'}")
        print("="*132)
        for r in results[:50]: # Cap terminal output display to 50 for readability
            print(f"{r['Entry Number']:<8} | {r['File Name'][:25]:<25} | {r['SI_Created'][:23]:<23} | {r['FN_Created'][:23]:<23} | {r['CreatedDeltaSeconds']:<10} | {str(r['ZeroedMillis']):<8} | {r['Reason']}")
        if len(results) > 50:
            print(f"... and {len(results) - 50} more entries.")
        print("="*132 + "\n")
    else:
        print("[+] No timestomping anomalies detected.")

    # Export to CSV if flag is provided
    if export_csv_path and results:
        try:
            with open(export_csv_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['File Name', 'Full OSPath', 'Entry Number', 'SI_Created', 'FN_Created', 'CreatedDeltaSeconds', 'SI_Lt_FN', 'ZeroedMillis', 'Reason'], extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results)
            print(f"[+] Successfully exported {len(results)} anomalies to: {export_csv_path}")
        except Exception as e:
            print(f"[-] Failed to export CSV: {e}")

def run_mftecmd_live(output_csv_path):
    """
    Tries to execute MFTECmd.exe to parse a live C: drive.
    Requires MFTECmd.exe to be in the PATH or same directory.
    """
    import subprocess
    print("[*] Attempting to parse live physical drive using MFTECmd...")
    
    # Standard MFTECmd syntax to dump C: MFT to CSV
    cmd = ["MFTECmd.exe", "-d", "C:", "--csv", os.path.dirname(output_csv_path), "--csvf", os.path.basename(output_csv_path)]
    print(f"[*] Running command: {' '.join(cmd)}")
    
    try:
        # Run process
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("[+] MFTECmd completed successfully.")
        return True
    except FileNotFoundError:
        print("[-] Error: 'MFTECmd.exe' was not found in your system PATH or local folder.")
        print("    Please download Eric Zimmerman's MFTECmd and place it in the executable path.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[-] MFTECmd execution failed: {e.stderr}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="DFIR Timestomp Detector - Analyze MFTECmd CSV exports or live physical disks for timestamp anomalies."
    )
    
    # Input selection
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--csv-file', help="Path to the parsed MFT CSV file generated by MFTECmd.")
    group.add_argument('-live', action='store_true', help="Parse live physical disk C: (requires administrative privileges & MFTECmd.exe in PATH).")
    
    # Params
    parser.add_argument('-t', '--threshold', type=float, default=5.0, help="Adjustable time-drift threshold in seconds (default: 5.0 seconds).")
    parser.add_argument('-o', '--output', help="Export results to a structured CSV file.")
    parser.add_argument('--temp-csv', default="live_mft_parsed.csv", help="Temporary file name for live parsed MFT output (default: live_mft_parsed.csv).")
    parser.add_argument('--strict', action='store_true', help="Only flag anomalies if BOTH Creation AND Modification times are mismatched (helps eliminate copy/install false positives).")
    parser.add_argument('--cluster-threshold', type=int, default=0, help="MFT Entry clustering filter (default: 0, disabled). Set to e.g. 20 to ignore anomalies that occur within a continuous sequence of 20+ records modified at similar times (Windows Update batched actions).")
    parser.add_argument('--only-binaries', action='store_true', help="Only flag anomalies for common binary extensions (.exe, .dll, .sys, .bat, .ps1).")
    
    args = parser.parse_args()
    
    csv_file = args.csv_file
    
    if args.live:
        temp_csv_path = os.path.abspath(args.temp_csv)
        success = run_mftecmd_live(temp_csv_path)
        if success and os.path.exists(temp_csv_path):
            csv_file = temp_csv_path
        else:
            print("[-] Cannot proceed with analysis since live parsing failed.")
            sys.exit(1)
            
    if csv_file:
        if not os.path.exists(csv_file):
            print(f"[-] Error: File not found: {csv_file}")
            sys.exit(1)
            
        analyze_mft_csv(
            csv_path=csv_file,
            drift_threshold_seconds=args.threshold,
            ignore_regex_list=DEFAULT_IGNORE_PATTERNS,
            export_csv_path=args.output,
            strict=args.strict,
            cluster_threshold=args.cluster_threshold,
            only_binaries=args.only_binaries
        )

if __name__ == "__main__":
    main()
