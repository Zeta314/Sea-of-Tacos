# Sea of Tacos

Sea of Tacos is a Python 3 library aimed to wrap Windows APIs to interact with other processes by calling natives.

## Installation

Just clone this repository and use python `setuptools` to install Sea of Tacos.

```bash
python setup.py --install
```

## Sample usage

For more visit the [wiki](https://github.com/Zeta314/Sea-of-Tacos/wiki).

```python
from seaoftacos.process import Process
from seaoftacos.memory import Memory

proc = Process.by_name("notepad.exe")
proc.open()

mem = Memory(proc)
mem.write_int(0xdeadbeef, 1234)

proc.close()

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
This software is licensed under the [MIT](https://choosealicense.com/licenses/mit/) license.

## Authors

Just me, [@Zeta314](https://github.com/Zeta314).
