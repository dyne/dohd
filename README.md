# dohd

Dohd (pron. doh-dee) is a minimalist DNS-over-HTTPS daemon that redirects all DoH queries
to a local DNS server running on localhost:53 (UDP).

## Features

- Support for RFC8484 DNS-over-HTTPS (POST and GET method) - HTTP/1.1 only for now.
- Record freshness derived from minimum TTL among answers

## Building

1. Ensure that  [wolfSSL](https://github.com/wolfssl/wolfssl) is installed on your system, and
configured to support TLS 1.3 (configure option: --enable-tls13).

2. Type `make`.

## Usage

dohd -c *certificate* -k *private-key* \[-p *port*\] \[-F\] \[-u *user*\]

### Command line parameters:

- '-c *certificate*' - specifies which certificate for the TLS server. (Mandatory parameter)
- '-k *private-key*' - specifies the private key used by the TLS server. (Mandatory parameter)
- '-p *port*' - changes the listening port for the DoH service (default:8053)
- '-u *user*' - drop root privileges after binding to the TCP port by switching user (mandatory when running as root)
- '-F' - runs dohd in foreground (instead of creating a daemon)

### Browser configuration

- In Firefox, go to 'about:preferences' -> Network Settings -> Settings
- check 'Enable DNS over HTTPS'
- Enable 'custom' option
- specify the URL of your DoH server
- Optional: set the Trusted Recursive Resolver (TRR) mode via 'about:settings' under `network_trr_mode`. Possible values:
   - 0 - _Off_ (default). use standard native resolving only (don't use TRR at all)
   - 1 -  _Reserved_. (do not use)
   - 2 -  _First_. Use TRR first, and only if the name resolve fails use the native resolver as a fallback.
   - 3 -  _Only_. Only use TRR, never use the native resolver.
   - 4 -  _Reserved_. (do not use)
   - 5 -  _Off by choice_. This is the same as 0 but marks it as done by choice and not done by default.

More info available on [wiki.mozilla.org](https://wiki.mozilla.org/Trusted_Recursive_Resolver).

### Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including
but not limited to the warranties of merchantability, fitness for a particular purpose, title
and non-infringement. in no event shall the copyright holders or anyone distributing the
software be liable for any damages or other liability, whether in contract, tort or otherwise,
arising from, out of or in connection with the software or the use or other dealings in the
software.

### License

Dohd is licensed under the terms of GNU Affero General Public License (GNU AGPL).
See COPYING for details.


