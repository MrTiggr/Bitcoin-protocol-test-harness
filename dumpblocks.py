#!/usr/bin/env python
#
# Connect to a bitcoin node and dump out JSON-format block chain
#

import asyncore

from NodeConn import *

def main():
    import optparse
    parser = optparse.OptionParser(usage="%prog [options]\n"+
                                   "Reads JSON-format protocol messages on stdin, "+
                                   "writes JSON-format message responses on stdout.")
    parser.add_option("--host", dest="host", default="127.0.0.1",
                      help="IP/hostname to connect to (default: %default)")
    parser.add_option("--port", dest="port", default="8333", type="int",
                      help="port to connect to (default: %default)")
    parser.add_option("--testnet", dest="testnet", action="store_true", default=False,
                      help="Speak testnet protocol")
    parser.add_option("--n", dest="n_blocks", type="int", default=99999,
                      help="Dump this many blocks (default: all)")
    parser.add_option("--verbose", dest="verbose", action="store_true", default=False,
                      help="Print all messages sent/received")
    parser.add_option("--version", dest="version", default="0.4.0",
                      help="Version of the protocol to speak")

    (options, args) = parser.parse_args()

    # Convert string like "1.0" or "0.3.24.0" to integer version where 1.0.0.0 == 1000000
    version = sum([ int(j)*(100**(3-i)) for (i,j) in enumerate(options.version.split(".")) ])

    class handle_message(object):
        def __init__(self, n_blocks):
            self.n_to_fetch = n_blocks
            self.n_fetched = 0
            self.state = "start"
            self.batch_remaining = 0

        def __call__(self, connection, message):
            if connection.handshaking:
                if message.command == "version":
                    self.n_to_fetch = min(self.n_to_fetch, message.nStartingHeight)

            elif self.state == "ending":
                pass

            elif self.state == "start":
                self.state = "inv"
                m = msg_getblocks(version=connection.ver_send)
                m.locator = [ connection.genesis_value ]
                connection.send_message(m)

            elif self.state == "inv" and message.command == "inv":
                self.batch_remaining = len(message.inv)/2
                self.state = "blocks"
                m = msg_getdata()
                m.inv = message.inv
                connection.send_message(m)

            elif message.command == "block":
                print repr(message)
                self.n_fetched += 1
                self.batch_remaining -= 1
                if self.n_fetched >= self.n_to_fetch:
                    self.state = "ending"
                    connection.close()
                elif self.batch_remaining == 0:
                    self.state = "inv"
                    m = msg_getblocks(version=connection.ver_send)
                    m.locator = [ connection.genesis_value, message.calc_sha256() ]
                    connection.send_message(m)
                    

    c = NodeConn(options.host, options.port, version, options.testnet, handle_message(options.n_blocks))
    c.verbose = options.verbose

    c.version_handshake()

    asyncore.loop()

if __name__ == '__main__':
    main()
