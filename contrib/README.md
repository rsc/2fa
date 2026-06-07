tiny tool to export the set of secrets in .2fa into text file for [Authenticator Pro](https://stratumauth.com/)

usage:
```bash
./path-to/rsc2authpro.py .2fa > uris.txt
```

normally it prints into stdout set of secrets in form similar to 

otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
