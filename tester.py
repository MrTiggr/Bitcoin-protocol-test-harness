#!/usr/bin/env python
#
# Test a bitcoin implementation by connecting to it and sending it
# bitcoin protocol messages.
#
# This is the generic test harness; it reads messages-to-send from a file
# and spits out messages-sent on standard output. It is meant to be used
# by pyexepect scripts that setup clean or pre-defined bitcoin client configurations
# and then run the client, run this test harness, and then send pre-defined
# messages to the bitcoin client to make sure it Does the Right Things.
#

import asyncore

from NodeConn import *

def main():
    import optparse
    parser = optparse.OptionParser(usage="%prog [options]\n"+
                                   "Reads JSON-format protocol messages from file arguments, "+
                                   "writes JSON-format message responses on stdout.")
    parser.add_option("--host", dest="host", default="127.0.0.1",
                      help="IP/hostname to connect to (default: %default)")
    parser.add_option("--port", dest="port", default="8333", type="int",
                      help="port to connect to (default: %default)")
    parser.add_option("--testnet", dest="testnet", action="store_true", default=False,
                      help="Speak testnet protocol")
    parser.add_option("--nohandshake", dest="handshake", action="store_false", default=True,
                      help="Do not automatically perform initial version/verack handshake")
    parser.add_option("--verbose", dest="verbose", action="store_true", default=False,
                      help="Print all messages sent/received")
    parser.add_option("--version", dest="version", default="0.4.0",
                      help="Version of the protocol to speak")

    (options, args) = parser.parse_args()

    to_send = []
    for file in args:
        to_send.extend(json.loads(open(file, "r").read()))

    # Convert string like "1.0" or "0.3.24.0" to integer version where 1.0.0.0 == 1000000
    version = sum([ int(j)*(100**(3-i)) for (i,j) in enumerate(options.version.split(".")) ])

    class handle_message(object):
        def __init__(self, to_send):
            self.ending = False
            self.to_send = to_send

        def __call__(self, connection, message):
            if self.ending:
                if message.command == "block" and message.hashPrevBlock == 0:
                    # Got genesis block, that's the signal to exit
                    connection.close()
                    return
                else:
                    print(repr(message))
                    return

            print repr(message)

            if len(self.to_send) > 0:
                (wait_for, what, todo) = self.to_send[:3]
        
                if wait_for == "waitmessage" and message.command != what:
                    return

                # Got the message we're waiting for:
                self.to_send = self.to_send[3:]
            else:
                todo = "end"

            if todo == "end":    
                self.ending = True
                # Send a getdata message for the genesis block; when bitcoind replies with
                # the genesis block, that's the signal to exit.
                connection.send_message('{"getdata":[["2","__GENESIS__"]]}')
            else:
                connection.send_message(todo)

    c = NodeConn(options.host, options.port, version, options.testnet, handle_message(to_send))
    c.verbose = options.verbose

    if options.handshake:
        c.version_handshake()

    asyncore.loop()

if __name__ == '__main__':
    main()
