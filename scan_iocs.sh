#!/bin/bash
# PolyShell IOC Scanner — run from Magento root directory
# Scans for known backdoors and suspicious files left by the attack campaign.

MAGENTO_ROOT="${1:-.}"
echo "=== PolyShell IOC Scanner ==="
echo "Scanning: $MAGENTO_ROOT"
echo ""

echo "[1] PHP files in pub/media/custom_options/ (should be empty):"
find "$MAGENTO_ROOT/pub/media/custom_options" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" \) 2>/dev/null | tee /tmp/polyshell_found_php.txt
echo ""

echo "[2] Known backdoor filenames (accesson.php, bypass.phtml):"
find "$MAGENTO_ROOT" -type f \( -name "accesson.php" -o -name "bypass.phtml" -o -name "index.php" -path "*/custom_options/*" \) 2>/dev/null
echo ""

echo "[3] Files modified in last 30 days in pub/media/:"
find "$MAGENTO_ROOT/pub/media" -type f -newer "$MAGENTO_ROOT/pub/media/catalog" -mtime -30 2>/dev/null | head -50
echo ""

echo "[4] GIF89a polyglot files (image with embedded PHP):"
grep -rl "GIF89a" "$MAGENTO_ROOT/pub/media" --include="*.php" --include="*.phtml" 2>/dev/null
grep -rl "<?php" "$MAGENTO_ROOT/pub/media" 2>/dev/null | head -20
echo ""

echo "[5] Known malicious domains in JS/PHP files:"
grep -rl "lanhd6549tdhse\.top\|jslibrary\.net\|canevaslab\.com" "$MAGENTO_ROOT" \
    --include="*.php" --include="*.phtml" --include="*.js" --include="*.html" 2>/dev/null
echo ""

echo "[6] Base64 eval patterns (common in webshells):"
grep -rl "eval(base64_decode" "$MAGENTO_ROOT/pub" 2>/dev/null | head -20
echo ""

echo "[7] Summary:"
COUNT=$(cat /tmp/polyshell_found_php.txt 2>/dev/null | wc -l)
if [ "$COUNT" -gt 0 ]; then
    echo "  !! $COUNT PHP file(s) found in custom_options — INVESTIGATE IMMEDIATELY"
else
    echo "  No PHP files found in custom_options (clean)"
fi
echo ""
echo "Done."
