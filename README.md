# getgo
A program that downloads go binaries according to current best practice: https://github.com/golang/go/issues/14739

Since there are no out of band signatures available, it instead tries really hard to make sure it's talking to Google.

Usage:
`./getgo --version 1.6.2 --platform linux-amd64 -o /path/to/file.tar.gz`
