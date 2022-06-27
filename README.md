2fa is a two-factor authentication agent.

Usage:

    go install rsc.io/2fa@latest

    2fa -add [-7] [-8] [-hotp] name
    2fa -list
    2fa name

`2fa -add name` adds a new key to the 2fa keychain with the given name. It
prints a prompt to standard error and reads a two-factor key from standard
input. Two-factor keys are short case-insensitive strings of letters A-Z and
digits 2-7.

By default the new key generates time-based (TOTP) authentication codes; the
`-hotp` flag makes the new key generate counter-based (HOTP) codes instead.

By default the new key generates 6-digit codes; the `-7` and `-8` flags select
7- and 8-digit codes instead.

`2fa -list` lists the names of all the keys in the keychain.

`2fa name` prints a two-factor authentication code from the key with the
given name. If `-clip` is specified, `2fa` also copies to the code to the system
clipboard.

With no arguments, `2fa` prints two-factor authentication codes from all
known time-based keys.

The default time-based authentication codes are derived from a hash of the
key and the current time, so it is important that the system clock have at
least one-minute accuracy.

The keychain is stored unencrypted in the text file `$HOME/.2fa`.

## Example

During GitHub 2FA setup, at the “Scan this barcode with your app” step,
click the “enter this text code instead” link. A window pops up showing
“your two-factor secret,” a short string of letters and digits.

Add it to 2fa under the name github, typing the secret at the prompt:

    $ 2fa -add github
    2fa key for github: nzxxiidbebvwk6jb
    $

Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:

    $ 2fa github
    268346
    $

Or to type less:

    $ 2fa
    268346	github
    $
