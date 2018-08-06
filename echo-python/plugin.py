#!/usr/bin/env python

from concurrent import futures
import sys
import time
import random
import string
import logging
import argparse
import os
import os.path

import grpc

import kaetzchen_pb2
import kaetzchen_pb2_grpc


class EchoServicer(kaetzchen_pb2_grpc.KaetzchenServicer):

    def __init__(self, logger):
        self.logger = logger

    def OnRequest(self, request, context):
        self.logger.info("received echo request")
        return request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-l", required=True, help="log directory")
    args = vars(ap.parse_args())
    log_dir = args["l"]

    # validate log dir
    if not os.path.exists(log_dir) or not os.path.isdir(log_dir):
        print("log dir doesn't exist or is not a directory")
        os.exit(1)

    # setup logging
    logger = logging.getLogger('echo-python')
    logger.setLevel(logging.DEBUG)
    log_path = os.path.join(log_dir, "echo_python_%s.log" % os.getpid())
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    logger.setLevel(logging.DEBUG)

    # start service
    logger.info("starting echo-python service")
    rand = ''.join(random.choice(string.digits) for _ in range(10))
    socket = "/tmp/pyecho_plugin_%s.sock" % rand
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    kaetzchen_pb2_grpc.add_KaetzchenServicer_to_server(
        EchoServicer(logger), server)
    server.add_insecure_port("unix:%s" % socket)
    server.start()

    # Output information
    print("1|1|unix|%s|grpc" % socket)
    sys.stdout.flush()

    try:
        while True:
            time.sleep(60 * 5)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    main()
