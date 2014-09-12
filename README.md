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
* Dns:
  * Tasks:
      * Performing dns lookup
      * Performing reverse dns lookup
      * Getting name server records
      * Getting any type of ns record information
      * Checking dnssec
      * Checking wildcard dns
      * Checking dns allow recursion
      * Checking dns zone transfer
 * Tools:
   * dig

* Brute Force:
  * Tasks:
      * sub domains
      * ftp
 * Tools:
   * dig