# Call Of Penetration (cop!)

## Doing some penetration testing automatically.


* Information Gathering:
 * Tasks:
    * Whois IP
      * Extract `network range`, `network name`, `description`,
                `address`, `country`, `city`, `phone`, `fax_number`, `fax-no`
 * Tools:
   * whois
* Network:
 * Tasks:
    * Check host is up
    * Discover states of `TCP` and `UDP` ports including: `open`, `closed`,
                                                          `filtered`, `unfiltered`,
                                                          `open|filtered` or `closed|filtered`.
    * Detect os
    * Detect services with version info
 * Tools:
   * nmap
* DNS:
  * Tasks:
      * Performing DNS lookup
      * Performing reverse DNS lookup
      * Getting name server records
      * Getting name servers bind version
      * Getting any type of ns record information
      * Checking DNSSEC
      * Checking wildcard DNS
      * Checking DNS allow recursion
      * Checking DNS zone transfer
 * Tools:
   * dig
* Brute Force:
  * Tasks:
      * sub domains
 * Tools:
   * dig
* Services:
  * Tasks:
    * ftp
       * Anonymous access detection
    * ssh
       * Detect ssh authentication types available
       * Username enumeration time-based attack for OpenSSH
 * Tools:
   * nmap, ssh



## Usage
```
$ git clone https://github.com/omidraha/cop
$ cd cop
$ pip install -r requirements.txt
$ ./cop.py
```


