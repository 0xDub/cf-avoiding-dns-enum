# Cloudflare-avoiding DNS Enumeration
Very simple DNS enumeration tool written in Rust. It recursively queries DNS records for the main domain name given as well as subdomains via the wordlist attached (feel free to add / remove as you'd like!). The goal with this script is to scrape for IPs and domains that are not serviced via Cloudflare as they mask the real IP of the underlying servers. Once enumeration is done the results are saved in the `results` folder which could be piped to another tool like nmap

If you're looking for something more advanced I recommend checking out `TheRook/subbrute`! The contributors over there did a great job and are much faster / complex than this script

## Setup

```
git clone https://github.com/0xDub/cf-avoiding-dns-enum.git
```

```
cd cf-avoiding-dns-enum
```

```
cargo run -- [domain_name]
```

### Note

- Currently AXFR is not implemented