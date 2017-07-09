# Secure Host-to-Host VPN

## What is it?
This is a secure host-to-host communication between a client and a server (client on one instance of a Linux virtual machine and server on another instance). This repository relies heavily on openSSL for a secure connection. It uses AES for confidentiality and HMAC for Integrity of the message packets. These programs also use the TUN interface to establish a connection.

Currently this VPN only works for Linux.

## Setting up the VPN between the two virtual machines

Open two virtual machines and copy the repository into both virtual machines.

A makefile is provided for compiling the the client and server program. 

Go to the directory on both VMs and initiate the makefile with

```
$ make
```

### Next, you need to establish the tunnel interface between the VMs

#### Running the server executable:
```
$ sudo ./serv
```

Now you will need to establish the tunnel (tun) interface for the server.

On another terminal run these commands

```
$ sudo ip addr add 10.0.4.1/24 dev tun0
$ sudo ifconfig tun0 up
```

Now the server VM has an two interfaces, one is its own Ethernet card interface, and the other is the virtual network interface called tun0.

Lastly do a ifconfig to get the ip address for the server (need to pass it to the client).

```
$ ifconfig
```


#### Running the client exectuable:**
```
$ sudo ./cli "ip address of the server"
```

Now you will need to establish the tunnel (tun) interface for the client.

On another terminal run these commands

```sh
$ sudo ip addr add 10.0.5.1/24 dev tun0
$ sudo ifconfig tun0 up
```

Now the client VM has an two interfaces, one is its own Ethernet card interface, and the other is the virtual network interface called tun0.

## Route the virtual machines to each other

### Server's virtual machine
```
$ sudo route add -net 10.0.5.0 netmask 255.255.255.0 dev tun0
```

### Client's virtual machine
```
$ sudo route add -net 10.0.4.0 netmask 255.255.255.0 dev tun0
```

## Communicating between virtual machines

Now you can ping and ssh from one virtual machine to another machine.

### On server
```
$ ping 10.0.5.1
$ ssh 10.0.5.1
```
### On client
```
$ ping 10.0.4.1
$ ssh 10.0.4.1
```

## Special characters for client side of the VPN

Also there is 3 special characters that you can enter into the client program.

* q: Quits the session.
* k: Change the key between server and client.
* v: Change the IV between the server and client.


## Demo

Link: https://www.youtube.com/watch?v=mr7EfV9hIn0

## Author

**Ardlan Khalili**

## Questions?

Email me at ardlankhalili@gmail.com