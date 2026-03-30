#!/bin/bash
echo "=== Yet another Bash jail challenge? ==="
echo "[*] Guess the correct secret (In hexadecimal format):"
read guess

forbidden_chars='[<>]'
if [[ "$guess" =~ $forbidden_chars ]]; then
    echo "[-] Forbidden characters."
    exit 1
fi

if [[ "$guess" =~ ^[0-9a-fA-F]+ ]]; then
    let "guessHex = 0x$guess" 2>/dev/null
else
    echo "[-] Invalid guess."
    exit 1
fi

secret=$(head -c 16 /dev/urandom | md5sum | cut -c1-16)
let "secretHex = 0x$secret" 2>/dev/null

if [[ $guessHex -eq $secretHex ]]; then
    echo "[+] Congratulations! You guessed the correct secret: $secret"
else
    echo "[-] Not the correct secret. Try harder!"
fi