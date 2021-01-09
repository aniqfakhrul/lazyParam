# What is lazyParams?
lazyParams is a simple automation tool for checking hidden parameters in a page. _note: Works with python3_

# Usage

* Fuzz parameters for both GET and POST method
* Use intensive mode with characters bypassing techniques

# Usage

Fuzz parameters with build in wordlists
```
python3 lazyparam.py -u http://example.com/file.php
```

Fuzz with custom wordlist
```
python3 lazyparam.py -u http://example.com/file.php -w wordlists.lst
```
