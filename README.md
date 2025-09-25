#ArcanumI_week2

# Windows Integrity Level Extraction

**Script:** `02_ArcanumI_week2_process_scry.py`

This tool extracts and displays the Windows integrity level of the current process using the Windows Token API.

## Features
- Retrieves process token information
- Parses mandatory integrity labels
- Maps raw integrity values to human-readable levels
- Provides both console and JSON output formats

## Security Relevance
Understanding integrity levels is crucial for:
- Detecting privilege escalation attempts
- Monitoring for UAC bypass techniques
- Identifying anomalous parent-child process relationships
- Implementing proper application sandboxing

## Usage
```python
python 02_ArcanumI_week2_process_scry.py
