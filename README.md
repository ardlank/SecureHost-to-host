# Secure Host-to-Host VPN

## What is it?
This program serves as a host-to-host communication between a client and a server. This repository relies heavily on openSSL for a secure connection. It uses AES for confidentiality and HMAC for Integrity of the message packets. These programs also use the TUN interface to establish a connection.

Currently this VPN only works for Linux.

## Using the VPN
A makefile is provided for compiling the the client and server program. 

Go to the directory and initiate the makefile with

```sh
$ make
```

Now you should be able to run the client and server executable on seperate VMs


## Demo

Link: https://www.youtube.com/watch?v=mr7EfV9hIn0

## Author

**Ardlan Khalili**

## Questions?

Email me at ardlankhalili@gmail.com

