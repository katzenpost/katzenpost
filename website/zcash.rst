
Using Zcash with Katzenpost
===========================

A Katzenpost mix network can be used to anonymize Zcash client interaction
with the Zcash blockchain. That is to say, although Shielded Zcash Transactions
are not linkable to previous transactions your network interactions can still
be linked with your transaction on the Zcash blockchain.

Our server side plugin system allows you to add mix network services. We've
detailed the design of these auto-responder Provider-side plugins here:
https://github.com/katzenpost/katzenpost/blob/master/docs/specs/kaetzchen.rst

Here I've written "echo" service plugins for you to learn from in golang and Rust:
https://github.com/katzenpost/katzenpost/server_plugins

You could easily write plugin for Katzenpost that allows you to submit crypto currency
transactions but I've already written such a plugin and I called it "currency":

https://github.com/katzenpost/currency

It's very simple. This plugin uses the Bitcoin HTTP JSON API to submit
a raw transaction to the blockchain. The idea here is that your
Katzenpost mix network client can compose a Sphinx packet whose
payload contains your Zcash transaction. This Sphinx packet gets
routed through the mix network until it reaches it's destination, a
Provider on the network which is running this currency plugin. The
Zcash transaction is passed from the Provider's Katzenpost mix server
to the plugin which talks directly to the Zcash daemon using the
Bitcoin HTTP JSON API, and submits the transaction.

If you'd like to read further justification for my design then please
read **Extending the Anonymity of Zcash** by George Kappos and Ania M. Piotrowska:
https://arxiv.org/abs/1902.07337
