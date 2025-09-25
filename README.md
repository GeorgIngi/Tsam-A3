# TSAM A3 — Port Forward, Starboard Back

## Build

```bash
make
```

## Usage

* Firstly, run UDP port scanner:

```bash
./scanner <IP> <low-port> <high-port>
# example:
./scanner 130.208.246.98 4000 4100
```

* Run puzzle solver (may require root for raw sockets):

```bash
sudo ./puzzlesolver <IP> <port1> <port2> <port3> <port4>
# example (ports discovered by scanner):
sudo ./puzzlesolver 130.208.246.98 4008 4022 4034 4080
```

## Notes

* `puzzlesolver` uses raw sockets (E.V.I.L.) and may need `sudo`.
* The program expects the four puzzle ports as arguments in any order; it auto-detects each role from the banners.

## Files

* `scanner.cpp` — UDP scanner
* `puzzlesolver.cpp` — puzzle solver with handlers for S.E.C.R.E.T, E.V.I.L, CHECKSUM, E.X.P.S.T.N
* `Makefile` — build rules
