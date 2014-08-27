# Call Of Penetration (cop!)

## Doing some penetration testing automatically.


* Information Gathering Rules:
 * Tasks:
    * Whois IP
      * Extract `network range`, `network name`, `description`,
                `address`, `country`, `city`, `phone`, `fax_number`, `fax-no`
 * Tools:
   * whois
* Network Rules:
 * Tasks:
    * Check host is up
    * Discover open `TCP` and `UDP` ports
    * Detect os
    * Detect services with version info
 * Tools:
   * nmap
* Dns Rules:
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
