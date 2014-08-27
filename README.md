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
      * Performing DNS Lookup
      * Performing Reverse DNS Lookup
      * Getting Name Server records
      * Getting any type of ns record information
      * Checking DNSSEC
      * Checking Wildcard DNS
      * Checking DNS Zone Transfer
 * Tools:
   * dig
