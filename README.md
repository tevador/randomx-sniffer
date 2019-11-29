# RandomX Sniffer
RandomX Sniffer is a proof of concept tool that can detect RandomX cryptojacking malware on Windows. RandomX Sniffer will detect any process running RandomX regardless of how it's coded or obfuscated. This is possible because the RandomX algorithm leaves a trace in the CPU registers that can be detected.

There are only 2 ways how malware can hide from being detected by this technique:

1. by emulating floating point operations using integer math and losing >95% of performance in the process
1. by modifying the operating system

## Build

Build using Visual Studio 2019.

## License

The source code is released into the public domain under CC0.

## Donations

Author's XMR address:
```
845xHUh5GvfHwc2R8DVJCE7BT2sd4YEcmjG8GNSdmeNsP5DTEjXd1CNgxTcjHjiFuthRHAoVEJjM7GyKzQKLJtbd56xbh7V
```
