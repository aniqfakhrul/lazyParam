# What is lazyParam?
lazyParam is a simple automation tool with implementation of multi-threading created by us [@aniqfakhrul](https://twitter.com/aniqfakhrul), [@h0j3n](https://twitter.com/h0j3n) and [@a_m1rz](https://twitter.com/a_m1rz) for checking hidden parameters in a page. _note: Works with python3_

# Usage

* Fuzz parameters for both GET and POST method
* Use intensive mode with characters bypassing techniques

# Todo 

* Implement MultiThreading for faster fuzzing
* Implement SSTI checking

# Usage

Fuzz parameters with build in wordlists
```
python3 lazyparam.py -u http://example.com/file.php
```

Fuzz with custom wordlist
```
python3 lazyparam.py -u http://example.com/file.php -w wordlists.lst
```
