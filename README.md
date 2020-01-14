# SearchPassword

SearchPassword is a penetration testing tool for searching through email to find if they have been leak from data breaches. Once founded then we can see if the password are available.

## Quick Start Guide

Get an API key from https://hashes.org/ and https://hunter.io

Import-Module .\SearchPassword.ps1

Invoke-HunterIO -Domain example.com -Outfile email

Invoke-EmailSearch -Emaillist .\email.txt -out report

Once you have a list of hash we can now search to see if them have already been cracked.

Invoke-HashSearch -Hashlist .\Hashlist.txt -OutFile Hashes

Let the magic happen.