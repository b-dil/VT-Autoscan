# VT-Autoscan
Simple autoscan for Virus Total using MongoDB to keep track of requests.

`vtSend.py` is used in conjunction with a filename to submit the file to Virus Total via API. Upon sending the file, its information is added into MongoDB collection and removed when `vtRetrieve.py` is used to request Virus Total's scan results. The scan results are added into another collection on Mongo. `vtRetrieve.py` will simply run and receive scan results at an interval set in `vt.json`. `vt.json` will also contain your API key.

To do:

- Daemonize script
- Have submit script automatically scan a specific directory at a set frequency
- Bash mongo setup script
- Mongo security
- Allow script to connect to remote dbs
