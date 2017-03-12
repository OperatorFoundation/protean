# The Operator Foundation

[Operator](https://operatorfoundation.org) makes useable tools to help people around the world with censorship, security, and privacy.

## Shapeshifter

The Shapeshifter project provides network protocol shapeshifting technology
(also sometimes referred to as obfuscation). The purpose of this technology is
to change the characteristics of network traffic so that it is not identified
and subsequently blocked by network filtering devices.

There are two primary components to Shapeshifter: transports and the dispatcher. Each
transport provide different approach to shapeshifting. These transports are
provided as a Go library which can be integrated directly into applications.
The dispatcher is a command line tool which provides a proxy that wraps the
transport library. It has several different proxy modes and can proxy both
TCP and UDP traffic.

If you are a tool developer working in the Go programming language, then you
probably want to use the transports library directly in your application.
<https://github.com/OperatorFoundation/shapeshifter-transports>

If you want a end user that is trying to circumvent filtering on your network or
you are a developer that wants to add pluggable transports to an existing tool
that is not written in the Go programming language, then you probably want the
dispatcher. Please note that familiarity with executing programs on the command
line is necessary to use this tool.
<https://github.com/OperatorFoundation/shapeshifter-dispatcher>

If you are looking for a complete, easy-to-use VPN that incorporates
shapeshifting technology and has a graphical user interface, consider
[Moonbounce](https://github.com/OperatorFoundation/Moonbounce), an application for macOS which incorporates shapeshifting without
the need to write code or use the command line.

## Protean

Protean is a collection of transformers designed for the purpose of obfuscating UDP network traffic.

This is a port of the [Typescript implementation](https://github.com/uProxy/uproxy/tree/master/src/lib/transformers) originally developed as a part of [uProxy](https://www.uproxy.org/).

The overall goal of Protean is to provide transformations from UDP traffic into other UDP traffic, where the target UDP traffic has properties that resist network filtering. This is in contract to tools such as Shapeshifter Dispatcher, which provide resistance to network filtering by tunneling UDP traffic over TCP protocols.

Currently, Protean is provided as a library of open source transformation functions. A possible future goal is to integrate these transformations into transports for the Shapeshifter Transports library, with integration into Shapeshifter Dispatcher. Before this can happen, the Pluggable Transports specification needs to be updated to allow for UDP-to-UDP transports. Currently in the PT 2.0 specification, UDP is supported, but only in the case of UDP-over-TCP.
