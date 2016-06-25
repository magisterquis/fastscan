fastscan
========
Quick and Dirty full-connect scanner.  Meant for when `nmap -Pn -p-` is too slow

fastscan can scan the entire TCP port space on a host in a little over 8
minutes if the host returns TCP reset packets.

For each listening port, a banner will be grabbed.

Please don't use for illegal purposes.

Installation
------------
```bash
go get github.com/magisterquis/fastscan
go install github.com/magisterquis/fastscan
```

Examples
--------
Check for really old services
```bash
./fastscan -p 1-19 192.168.1.1
```
Fire-and-forget scan for all open ports
```bash
./fastscan 192.169.1.1
```
When you really, really want the entire telnet banner, and aren't sure where
telnet's listening
```bash
./fastscan -p 23-23333,31337 -l 102400 -w 30s 192.168.1.1
```
Cheezy way to packet someone
```bash
while :; do ./fastscan -n 500 192.168.1.1; done # Please don't...
```

No Route to Host
----------------
There's an error when the scan is going too fast which comes back as "no route
to host," even though there's a perfectly good route.  Use the -r flag to retry
the ports that would have been missed.  In practice, it's still pretty fast.

Defaults
--------
The defaults are somewhat conservative.  Testing has shown that 500
simultaneous connection attempts works just fine.

Usage
-----
```
Usage: ./fastscan [options] target

Determines which of the ports on the given targets are listening.

Options:
  -f	Show failed connection attempts and other errors
  -l length
    	Max banner length, in bytes (default 128)
  -n N
    	Scan N ports in parallel (default 128)
  -p list
    	Comma-separated list of ports and port ranges to scan (default "1-65535")
  -r	Work around "no route to host" errors
  -w timeout
    	Connection and banner-grab timeout (default 1s)
```

Windows
-------
It's particularly unfancy Go, so it should compile and run under Windows just
fine.
