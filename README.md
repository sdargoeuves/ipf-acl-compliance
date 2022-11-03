# acl-compliance.py
Script to check ACL on the devices in IP Fabric are compliant.
Tested with python 3.8 and 3.10.

## How to install

***Install ipfabric Python module and dependencies***
```sh
pip install -r requirements.txt
```

## How to use

***.env file***
Create a copy of the example file
```sh
cp .env.example .env
```
Now edit the variables with the relevant information for your environment

***compliance.json***
This is the reference used to perform the comparison against the ACL found on the devices.
It has to be created following the IP Fabric's model.


## Help

```sh
python acl-compliance.py
```
 
The default mode will show the compliance status, per device.

- -v, --verbose

Enable the verbose mode, which shows what is different (added, removed, changed)

- -t, --table

Enable the table view. Can be combined with the verbose opt


## License

MIT

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

