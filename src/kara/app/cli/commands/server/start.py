# -*- encoding: utf-8 -*-
"""
kara.cli.commands module

"""
import argparse
import logging
import os

from keri import help
from keri.app import keeping, habbing, directing, configing, oobiing
from keri.app.cli.common import existing
from keri.end import ending

import kara
from kara.core import serving

parser = argparse.ArgumentParser(description='Launch KARA Reporting Agent')
parser.set_defaults(handler=lambda args: launch(args), transferable=True)
parser.add_argument(
    '-p', '--http', action='store', default=9723,
    help="Port on which to listen for OOBI requests.  Defaults to 9723",)
parser.add_argument(
    '-n', '--name', action='store', default="kara",
    help="Name of controller. Default is kara.")
parser.add_argument(
    '-b', '--base', required=False, default="",
    help='additional optional prefix to file location of KERI keystore')
parser.add_argument(
    "-c", "--config-dir", dest="configDir",
    help="directory override for configuration data")
parser.add_argument(
    "-f", '--config-file', dest="configFile", action='store', default=None,
    help="configuration filename override")
parser.add_argument(
    '-a', '--alias', required=True,
    help='human readable alias for the new identifier prefix')
parser.add_argument(
    '-s', '--salt', required=False,
    help='qualified base64 salt for creating key pairs')
parser.add_argument(
    '--passcode', dest="bran", default=None,
    help='21 character encryption passcode for keystore (is not saved)')
parser.add_argument(
    '-w', '--web-hook', action='store', required=True, default=None,
    help='Webhook address for outbound notifications of credential issuance or revocation')
parser.add_argument(
    "-r", "--retry-delay", default=10, type=int, action="store",
    help="retry delay (in seconds) for failed web hook attempts")
parser.add_argument(
    "-e", "--escrow-timeout", default=10, type=int, action="store",
    help="timeout (in minutes) for escrowed events that have not been delivered to the web hook.  Defaults to 10")
parser.add_argument(
    "-l", "--loglevel", action="store", required=False, default=os.getenv("KARA_LOG_LEVEL", "INFO"),
    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is CRITICAL")

help.ogler.level = logging.getLevelName(logging.INFO)
logger = help.ogler.getLogger()

app_name = "kara"


def launch(args, expire=0.0):
    base_formatter = logging.Formatter(f"%(asctime)s [{app_name}] %(levelname)-8s %(message)s")
    base_formatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(base_formatter)
    help.ogler.level = logging.getLevelName(args.loglevel.upper())
    logger.setLevel(help.ogler.level)
    help.ogler.reopen(name=app_name, temp=True, clear=True)

    hook = args.web_hook
    name = args.name
    salt = args.salt
    base = args.base
    bran = args.bran
    httpPort = args.http
    timeout = args.escrow_teimout
    retry = args.retry_delay

    alias = args.alias
    configFile = args.configFile
    configDir = args.configDir

    ks = keeping.Keeper(name=name,
                        base=base,
                        temp=False,
                        reopen=True)

    aeid = ks.gbls.get('aeid')

    cf = None
    if aeid is None:
        if configFile is not None:
            cf = configing.Configer(name=configFile,
                                    base=base,
                                    headDirPath=configDir,
                                    temp=False,
                                    reopen=True,
                                    clear=False)

        kwa = dict()
        kwa["salt"] = salt
        hby = habbing.Habery(name=name, base=base, bran=bran, cf=cf, **kwa)
    else:
        hby = existing.setupHby(name=name, base=base, bran=bran)

    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
    obl = oobiing.Oobiery(hby=hby)

    doers = [hbyDoer, *obl.doers]

    doers += serving.setup(
        hby, alias=alias, httpPort=httpPort, hook=hook, timeout=timeout, retry=retry)

    print(f"KARA Agent v{kara.__version__} listening on {httpPort} with DB version {hby.db.version}")
    directing.runController(doers=doers, expire=expire)
