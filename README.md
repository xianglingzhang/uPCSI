# uPCSI

## Dependency
See the instruction in [APSI](https://github.com/microsoft/APSI) for needed dependencies. Moreover, [libOTe](https://github.com/osu-crypto/libOTe) for oblivious transfer extension is also needed.
| Dependency                                                | vcpkg name                                           |
|-----------------------------------------------------------|------------------------------------------------------|
| [Microsoft SEAL](https://github.com/microsoft/SEAL)       | `seal[no-throw-tran]`                                |
| [Microsoft Kuku](https://github.com/microsoft/Kuku)       | `kuku`                                               |
| [Log4cplus](https://github.com/log4cplus/log4cplus)       | `log4cplus`                                          |
| [cppzmq](https://github.com/zeromq/cppzmq)                | `cppzmq` (needed only for ZeroMQ networking support) |
| [FlatBuffers](https://github.com/google/flatbuffers)      | `flatbuffers`                                        |
| [jsoncpp](https://github.com/open-source-parsers/jsoncpp) | `jsoncpp`                                            |
| [TCLAP](https://sourceforge.net/projects/tclap/)          | `tclap` (needed only for building CLI)               |

## How to build 
```
git clone https://github.com/xianglingzhang/uPCSI.git
cd uPCSI
mkdir build
cd build
cmake ..
make -j8
```

## How to run
```
../bin/receiver_cli -d db.csv --port 60000 -p ../parameters/16M-1024.json -t 1 --len 16
../bin/sender_cli -q query.csv -a 127.0.0.1 -p ../parameters/16M-1024.json --port 60000 -t 1
```
