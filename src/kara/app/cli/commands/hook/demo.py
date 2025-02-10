# -*- encoding: utf-8 -*-
"""
kara.cli.commands module

"""
import argparse
import logging

import falcon
from hio.base import doing
from hio.core import http
from keri import help
from keri.app import keeping, habbing, directing, configing
from keri.app.cli.common import existing
from keri.end import ending

from kara.core import serving

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Launch KARA sample web hook server')
parser.set_defaults(handler=lambda args: launch(args),
                    transferable=True)
parser.add_argument('-p', '--http',
                    action='store',
                    default=9923,
                    help="Port on which to listen for web hook event.  Defaults to 9923")


def launch(args, expire=0.0):
    baseFormatter = logging.Formatter('%(asctime)s [hook] %(levelname)-8s %(message)s')
    baseFormatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(baseFormatter)
    help.ogler.level = logging.getLevelName(logging.INFO)
    help.ogler.reopen(name="hook", temp=True, clear=True)

    httpPort = args.http

    app = falcon.App(
        middleware=falcon.CORSMiddleware(
            allow_origins='*',
            allow_credentials='*',
            expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    app.add_route("/", WebhookListener())

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    print(f"Kara Web Hook Sample listening on {httpPort}")
    directing.runController(doers=[httpServerDoer], expire=expire)


class WebhookListener:
    """
    Demonstration endpoint for web hook calls that prints events to stdout and stores a simple presentation cache.
    """

    def on_post(self, req, rep):
        """ Responds to web hook event POSTs by printing the results to stdout

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        """
        print("** HEADERS **")
        print(req.headers)
        print("*************")

        print("**** BODY ****")
        body = req.get_media()
        print(body)
        print("**************")


