[![Tests](https://github.com/sir-go/tls-reject/actions/workflows/python-app.yml/badge.svg)](https://github.com/sir-go/tls-reject/actions/workflows/python-app.yml)

## Traffic reject by TLS SNI

This is a part of the parental control system. 

Script sniffs mirrored users traffic, gets values of TLS SNI extension in each packet, 
and sends reset packets to the source IP if SNI contains a denied hostname.

Denied hostnames keep in the periodically updated MySQL database.

### Configure

Environment variables:

| variable           | description                        |
|--------------------|------------------------------------|
| BLOCK_DB_HOST      | mysql host                         |
| BLOCK_DB_USERNAME  | db username                        |
| BLOCK_DB_PASSWORD  | db password                        |
| BLOCK_DB_NAME      | db name                            |
| BLOCK_UPD_INTERVAL | update list from db interval (sec) |
| BLOCK_IN_IF        | input interface name               |
| BLOCK_OUT_IF       | output interface name              |


### Install -> Test -> Run
```bash
virtualenv venv
source ./venv/bin/activate
pip install -r requirements.txt
python -m pytest && python reject.py
```
