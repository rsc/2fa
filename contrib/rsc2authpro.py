#!/usr/bin/env python3
import sys

def convert_rsc_config_to_otpauth(config_path):
    with open(config_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3 and parts[1] == '6':
                label, digits, secret = parts
                otpauth = f"otpauth://totp/{label}:{label}?secret={secret}&issuer={label}&digits=6"
                print(otpauth)

if len(sys.argv) < 2:
    print("Usage: python rsc2authpro.py ~/.2fa")
    sys.exit(1)
convert_rsc_config_to_otpauth(sys.argv[1])
