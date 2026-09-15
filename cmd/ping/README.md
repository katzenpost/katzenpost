# ping
mixnet ping tool for testing and debugging

## Run instructions
```
go build
```
You should now have a *ping* executable in the current directory.

Now, in order to run the ping program, you need to specify a configuration file and a service name. 

A configuration file is provided in this repo. You can use it as a template for your own needs. If you are using the configuration file in this repo, ensure that you have uncommented out the portions that are relevant for your needs (in addition to ensuring that you have everything else setup). 

If you have run the instructions in the docker repository, you should have an echo_server running in a docker container. This has a service name of `echo`.
You can now run the following:
```
./ping -c configuration_file -s echo
```

You should see output indicating that the echo_server is being ping'ed. If your program times out, just wait a few minutes and rerun the same command.
