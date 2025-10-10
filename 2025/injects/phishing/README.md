# Phishing Documentation

This directory contains phishing methodology documentation for penetration testing.

## Usage

Files are stored in binary format for security. To decode:

```powershell
# Windows
certutil -decodehex phish.bin phish.md

# Linux
xxd -r -p phish.bin > phish.md
```

## Files

- `phish.bin` - Fleet Operations phishing methodology
- `phish2.bin` - Shipboard Tech phishing methodology

**Note:** These files contain sensitive penetration testing materials and should not be committed to public repositories.
