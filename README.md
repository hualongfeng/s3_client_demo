# System

```bash
$ uname -a
Linux fhl-Z391 5.4.0-58-generic #64~18.04.1-Ubuntu SMP Wed Dec 9 17:11:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

$ gcc -v
gcc version 9.3.0 (Ubuntu 9.3.0-11ubuntu0~18.04.1)

```



# boost
## Get source

`wget https://dl.bintray.com/boostorg/release/1.73.0/source/boost_1_73_0.tar.gz`

## build

```bash
tar -zxf boost_1_73_0.tar.gz
cd boost_1_73_0
./b2
```
## Adaptor

Change the CMakeLists.txt. Make it adaptor your boost directory


