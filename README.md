# ModSecurity rules checked
This script can check ModSecurity rules against some different WAF and is used as PoC for [following article](https://waf.ninja/modsecurity-rules-verification/). It uses following algorithm:
- parse security rules configuration files
- generate pattern for regex in rules
- send requests to some WAF and check if it is blocked based on response code
- generate report with statistics

# Help
```
python3 modsec-checker.py -h
usage: modsec-checker.py [-h] -f FOLDER -u HOST [-t TEMPLATE] [-o OUTPUT]
                         [-s STATUS] [--all]

ModSecurity rules tester

optional arguments:
  -h, --help            show this help message and exit
  -f FOLDER, --folder FOLDER
                        Folder containing ModSecurity rules
  -u HOST, --url HOST   Host with WAF to send requests (e.g.
                        https://waf.hostname)
  -t TEMPLATE, --template TEMPLATE
                        Jinja2 report template to generate WAF testing report
                        (default: report.html)
  -o OUTPUT, --output OUTPUT
                        Output file for report (default: report.html)
  -s STATUS, --s STATUS
                        Stats code of blocked requests
  --all                 Include parse errors in the report
```

## Example
```
python3 modsec-checker.py -f ../../owasp-modsecurity-crs/ -u https://vulnbank.com --all
```
