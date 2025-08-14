# Proxy Firewall

A Python-based HTTP/HTTPS proxy server with domain blocking functionality.  
Blocks specific domains from being accessed and logs all traffic.

## Features
- Blocks domains from `blocked_domains.txt` or `proxy_config.json`
- Supports HTTP and HTTPS connections
- Simple configuration
- Logs all requests and blocks

## Project Structure
.gitignore # Git ignore rules

LICENSE # MIT License

README.md # Documentation

blocked_domains.txt # List of blocked domains

roxy.log # Runtime log file

proxy_config.json # Proxy configuration

proxy_firewall.py # Main Python script

## Example: Blocked Site

When you try to visit a blocked domain, the proxy firewall prevents access and returns an error page.

### Blocked Facebook
![Blocked Facebook] (screenshots/blocked_facebook.png)
