# GenQuic

I am going to start working on this again. There are some fairly large issues with the
crypto handshake that will be high priority to resolve.

TODO:

- Documentation
- Examples
- Tests
- List of supported parameters and differences from QUIC
- Fix errors from dialyzer. Most likely a constant TODO.
- Fix the crypto handshake. Potentially change to calling the tls module now that 1.3 is
  supported. I'm going to see if I can just get the tls messages.
- Look into using the new atomics module.

## Installation

Installation is not quite recommended yet. If you want to though, it can be installed in
the same manner as just about any Elixir library pulled from github.