# Call Of Penetration (cop!)

## Doing some penetration testing automatically.


*   Information Gathering:
    * Tasks:
    *   Whois IP
    *   Extract `network range`, `network name`, `description`,
                `address`, `country`, `city`, `phone`, `fax_number`, `fax-no`
    *   Tools:
    *   whois
*   Network:
    *   Tasks:
        *   Check host is up
        *   Scan top `100` ports and discover states of `TCP` and `UDP` ports including: `open`, `closed`,
                                                          `filtered`, `unfiltered`,
                                                          `open|filtered` or `closed|filtered`.
        *   Scan all `TCP` and `UDP` ports, from `0` to `65535`
        *   Detect os
        *   Detect services with version info
    *   Tools:
    *   nmap, masscan
*   DNS:
    *   Tasks:
        *   Performing DNS lookup
        *   Performing reverse DNS lookup
        *   Getting name server records
        *   Getting name servers bind version
        *   Getting any type of ns record information
        *   Checking DNSSEC
        *   Checking wildcard DNS
        *   Checking DNS allow recursion
        *   Checking DNS zone transfer
    *   Tools:
        *   dig
*   Brute Force:
    *   Tasks:
        *   sub domains
    *   Tools:
        *   dig
*   Probe Services:
    *   Tasks:
        *   ftp
            *   Anonymous access detection
        *   ssh
            *   Detect ssh authentication types available
            *   Username enumeration time-based attack for OpenSSH
    *   Tools:
        *   nmap, ssh

## Tools

*   whois https://github.com/rfc1036/whois
*   dig http://linux.die.net/man/1/dig
*   nmap http://nmap.org/
*   masscan https://github.com/robertdavidgraham/masscan
*   ssh http://linux.die.net/man/1/ssh
*   paramiko https://github.com/paramiko/paramiko (external python module)
*   fierce http://ha.ckers.org/fierce/ (* only using sub domains list, currently added to `lst` folder)
*   subbrute https://github.com/TheRook/subbrute  (* only using sub domains list, currently added to `lst` folder)

## Usage
```
$ git clone https://github.com/omidraha/cop
$ cd cop
$ pip install -r requirements.txt
$ ./cop.py
```


