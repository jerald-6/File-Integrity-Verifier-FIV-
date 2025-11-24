FILE INTEGRITY VERIFIER (FIV) — USER MANUAL


Prerequisites (before running the .py)

1. Install Python 3.8 or later.

2. Install Python packages
	reportlab>=3.6.12
	Pillow>=9.5.0

Quick start:
1. Ensure you installed dependencies (see above).
2. From the folder containing the script, run:
   python /path/to/FIV.py
3. The GUI opens. Typical workflow:
   - Click **Add Files** or **Add Folder** to select files you want to hash.
   - Select hashing algorithms from the list (Ctrl+click to multi-select).
   - (Optional) Click **Set Output Folder** to choose where reports are saved.
   - Click **Generate Report (TXT + PDF)** to create a manifest.
   - To verify: click **Select Manifest TXT for Verification** to pick a previously generated manifest,
     add the evidence files (if not already present), then click **Run Verification**.

Outputs:
- `integrity_report.txt` — plain-text manifest with timestamps, file metadata and hashes.
- `integrity_report.pdf` — formatted PDF report with icon, file metadata, and wrapped hash strings.
- `verification_result.txt` / `verification_result.pdf` — verification outputs that summarize OK/MISMATCH/MISSING.

Important configuration points
------------------------------

1. Output folder: If you do not set an output folder through GUI, reports will be saved to the
   folder of the first selected evidence file.

2. Available hash algorithms: The script uses Python's `hashlib` algorithms available in your Python build. If a selected algorithm is not supported by your platform, the script will show an error for that algorithm.

Common issues & troubleshooting:
- GUI does not start:
  - Ensure Python and tkinter are installed. On some Linux distros install `python3-tk` or equivalent.
- `reportlab` not found or PDF generation fails:
  - Ensure you installed `reportlab` (pip install reportlab). If still failing, run the script in console to see the exception trace.
- Long hashes in PDF overflow:
  - The PDF generation uses ReportLab Paragraphs to wrap long lines; ensure you are using the provided final script version.
- Permission errors saving files:
  - Set an output folder where you have write permission, or run the script as a user with appropriate permissions.


Contact / Support
-----------------
If you encounter any issue while running the script locally, paste the exact console error message and OS details
(Windows/macOS/Linux + Python version) and I'll help debug.
