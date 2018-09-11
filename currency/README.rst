
crypto currency transaction proxy mixnet microservice
=====================================================

Also known as currency-go because it's written in golang. This service
proxies transaction blobs to a *coin daemon via the BTC JSON HTTP
RPC. That is to say, many of crypto currency daemons use this RPC
besides just bitcoin. Here we only make use of the "Send Raw
Transaction" command. Yes, it's so simple. This service receives
transaction blobs from random sketch clients on the mixnet and it just
submits them to the blockchain. Done.


usage
-----

It's a plugin. You are not supposed to run it yourself on the commandline.
See the handbook to learn how to configure external plugins:

* https://github.com/katzenpost/docs/blob/master/handbook/index.rst#external-kaetzchen-plugin-configuration

( if that's not enough then read our spec: https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst )

::
   ./currency-go -h
  Usage of ./currency-go:
    -f string
        Path to the currency config file. (default "currency.toml")
    -log_dir string
        logging directory
    -log_level string
        logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL (default "DEBUG")


configuration
-------------

In order to use this plugin your Katzenpost server will need
a configuration section that looks like this:

::
   [[Provider.PluginKaetzchen]]
     Capability = "zec"
     Endpoint = "+zec"
     Disable = false
     Command = "/home/user/test_mixnet/bin/currency-go"
     MaxConcurrency = 10
     [Provider.PluginKaetzchen.Config]
       log_dir = "/home/user/test_mixnet/zec_tx_logs"
       f = "/home/user/test_mixnet/currency_zec/curreny.toml"


Here's a sample configuration file for currency-go to learn it's
Ticker and RPC connection information, currency_go.toml:

::
  [Config]
    Ticker = "ZEC"
    RPCUser = "rpcuser"
    RPCPass = "rpcpassword"
    RPCURL = "http://127.0.0.1:18232/"


license
=======

AGPL: see LICENSE file for details.
