
#!/bin/bash

# ==========================================
# FILE AND DIRECTORY PERMISSION AUDITOR
# Member 3 - Unix Security Audit Project
# ==========================================

SCAN_DIR="${1:-/}"
OUTPUT_FILE="${2:-/tmp/file_findings.txt}"

# Check whether the directory exists
if [ ! -d "$SCAN_DIR" ]; then
    echo "Error: Directory does not exist."
    exit 1
fi

# Create or clear output file
mkdir -p "$(dirname "$OUTPUT_FILE")"
> "$OUTPUT_FILE"

# Function to save findings
record_finding() {
    echo "$1|$2|$3|$4" >> "$OUTPUT_FILE"
}

echo "======================================"
echo "     FILE PERMISSION SECURITY AUDIT"
echo "======================================"
echo "Scanning directory: $SCAN_DIR"
echo ""

# 1. CHECK WORLD-WRITABLE FILES AND DIRECTORIES

echo "[1] Checking world-writable files and directories..."

find "$SCAN_DIR" -xdev \
   \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt \) -prune -o \
    \( -type f -perm -0002 -o -type d -perm -0002 ! -perm -1000 \) -print0 2>/dev/null |
while IFS= read -r -d '' file
do
    record_finding "HIGH" \
    "World writable file or directory" \
    "$file" \
    "Restrict write permissions to authorized users"
done

# 2. CHECK SUID FILES

echo "[2] Checking SUID files..."

find "$SCAN_DIR" -xdev \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt \) -prune -o \
    -type f -perm -4000 -print0 2>/dev/null |
while IFS= read -r -d '' file
do
    record_finding "MEDIUM" \
    "SUID file found" \
    "$file" \
    "Review whether elevated privileges are necessary"
done

# 3. CHECK SGID FILES

echo "[3] Checking SGID files..."

find "$SCAN_DIR" -xdev \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt \) -prune -o \
    -type f -perm -2000 -print0 2>/dev/null |
while IFS= read -r -d '' file
do
    record_finding "MEDIUM" \
    "SGID file found" \
    "$file" \
    "Review whether special group privileges are necessary"
done

# 4. CHECK UNOWNED FILES AND DIRECTORIES

echo "[4] Checking unowned files and directories..."

find "$SCAN_DIR" -xdev \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt \) -prune -o \
    \( -nouser -o -nogroup \) -print0 2>/dev/null |
while IFS= read -r -d '' file
do
    record_finding "HIGH" \
    "Unowned file or directory" \
    "$file" \
    "Assign a valid owner and group"
done

# 5. CHECK IMPORTANT SYSTEM FILE PERMISSIONS

if [ "$SCAN_DIR" = "/" ]; then

    echo "[5] Checking important system files..."

    if find /etc/passwd -maxdepth 0 -perm /022 -print -quit 2>/dev/null | grep -q .; then
        record_finding "HIGH" \
        "Unsafe permissions" \
        "/etc/passwd" \
        "Remove group and other write permissions"
    fi

    if find /etc/shadow -maxdepth 0 -perm /007 -print -quit 2>/dev/null | grep -q .; then
        record_finding "CRITICAL" \
        "Unsafe permissions" \
        "/etc/shadow" \
        "Restrict access to authorized accounts"
    fi
fi

# DISPLAY COMPLETION MESSAGE

echo ""
echo "======================================"
echo "       AUDIT COMPLETED"
echo "======================================"

echo "Findings saved in: $OUTPUT_FILE"

echo ""
echo "Total findings:"
wc -l < "$OUTPUT_FILE"

echo "======================================"
