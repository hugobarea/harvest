# Harvest
## An OSINT tool by Hugo Barea
- Scans a given domain for WHOIS data, checks its emails for leaks and scans for open ports.
- Developed for an Introduction to Information Security class.

#### Install:
```bash
git clone http://github.com/hugobarea/harvest
cd harvest
pip install -r requirements.txt
# (or use a virtual environment)
```


#### Usage:
```bash
python3 harvest.py -target TARGET.com
```