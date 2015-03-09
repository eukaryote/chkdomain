=========
chkdomain
=========

A simple utility script that does a whois lookup for each domain name
given as a paramemer and reports whether it is available or not.

Installation
------------

Assuming you have Go installed and on your `PATH` and `GOPATH` is valid,
you can install it with::

    $ go get github.com/eukaryote/chkdomain
    $ go install github.com/eukaryote/chkdomain


Example
-------

An example that checks four domain names::

    $ chkdomain tlon.com uqbar.io kjczr.com google.com
    kjczr.com
    uqbar.io

Only the domain names that are available are printed, and the order of
results depends on which lookups finish first.
