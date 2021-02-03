# What is lazyParam?
lazyParam is a simple automation tool with implementation of multi-threading created by us [@aniqfakhrul](https://twitter.com/aniqfakhrul), [@h0j3n](https://twitter.com/h0j3n) and [@a_m1rz](https://twitter.com/a_m1rz) for checking hidden parameters in a page. This tool is still in testing phase and more implementations are soon to be made. _note: Works with python3_

# Features

* Fuzz parameters for both GET and POST method
* Multi-threaded _(Default: 4)_
* Use intensive mode with characters bypassing techniques (beta)

# Todo 

* Implement SSTI checking

# Usage

Fuzz parameters with build in wordlists
```
python3 lazyparam.py -u http://example.com/file.php
```

Specify custom wordlist
```
python3 lazyparam.py -u http://example.com/file.php -w wordlists.lst
```

