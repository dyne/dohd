# dohd

Dohd (pron. doh-dee) is a minimalist DNS-over-HTTPS daemon that redirects all DoH queries
to a local DNS server running on localhost:53 (UDP).

## Features

- Partial support for RFC8484 DNS-over-HTTPS (POST method only for now)
- Record freshness derived from minimum TTL among answers

## Building

1. Ensure that  [wolfSSL](https://github.com/wolfssl/wolfssl) is installed on your system, and
configured to support TLS 1.3 (configure option: --enable-tls13).

2. Type `make`. 

## Usage

dohd -c *certificate* -k *private-key* \[-p *port*\] \[-F\]

### Command line parameters:

- '-c *certificate*' - specifies which certificate for the TLS server. (Mandatory parameter)
- '-k *private-key*' - specifies the public key for the TLS server. (Mandatory parameter)
- '-p *port*' - changes the listening port for the DoH service (default:8053)
- '-F' - runs dohd in foreground (instead of creating a daemon)

### Browser configuration

- In Firefox, go to 'about:preferences' -> Network Settings -> Settings
- check 'Enable DNS over HTTPS'
- Enable 'custom' option 
- specify the URL of your DoH server

### Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including
but not limited to the warranties of merchantability, fitness for a particular purpose, title 
and non-infringement. in no event shall the copyright holders or anyone distributing the 
software be liable for any damages or other liability, whether in contract, tort or otherwise,
arising from, out of or in connection with the software or the use or other dealings in the 
software.

### License

Dohd is licensed under the terms of GNU General Public License (GNU GPL) Version 2.

