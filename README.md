## A utility for reading basic information about an .exe file including:
* Magic
* PE header
* Optional header
* Data directories
* File sections
* Import and export tables

### Install:
Make sure to have an updated version of setuptools:
```console
pip install setuptools --upgrade
```
Install the libraries required for work:
```console
pip install -r /path/to/requirements.txt
```

### Usage:
Run the command:
```console
python exeparser.py /path/to/your/file.exe
```
or if you need details:
```console
python exeparser.py -h
```