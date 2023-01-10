# airodump-bob

## Installation

assume go is installed.

```sh
make
## clean build files
make clean
```

## Execution

```sh
sudo ./airodump <monitor interface>
```

## Explanation

Content overflows when there are too many APs.
Cipher type 'specific' or null are 0x01~0x03, 0x05~0x06
Cipher type 'CCMP' is 0x04
