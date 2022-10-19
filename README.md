# certgrabber

## Summary

Tool to grab x509 certificate(s) from a remote host. By default the certificates will be returned in PEM format but this can be overrwridden to use DER using the `--der` flag.

## Usage

~~~
Usage: ./certgrabber [Options] host:port

Grabs x509 certificate(s) from a remote host
  v1.0.0 Mike Cromwell 2022

Options:
  -h, --help    show this help message and exit
  -c, --chain   include the chain
  -d, --der     write in DER format instead of PEM
  -w, --wait    wait timeout for connection in seconds
  -o, --out     output to file instead of stdout
~~~

## Examples

Wait 5 secs return cert in PEM:

`./certgrabber --wait 5 google.com:443`

Return cert in DER format and write to google.der:

`./certgrabber --der --out google.der google.com:443`

Return the full cert chain:

`./certgrabber --chain google.com:443`
