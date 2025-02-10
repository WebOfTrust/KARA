# -*- encoding: utf-8 -*-
"""
KARA
kara.core.serving module

Endpoint service
"""
import os

import falcon
from hio.base import doing
from hio.core import http
from hio.help import decking
from keri import help
from keri.app import indirecting, storing, notifying
from keri.core import routing, eventing, parsing
from keri.end import ending
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import viring, verifying
from keri.vdr.eventing import Tevery

from kara.core import handling, basing
from kara.core.credentials import TeveryCuery
from kara.core.monitoring import HealthEnd

logger = help.ogler.getLogger()


def setup(hby, *, alias, httpPort, hook, timeout=10, retry=3):
    """ Setup serving package and endpoints

    Parameters:
        hby (Habery): identifier database environment
        alias (str): alias of the identifier representing this agent
        httpPort (int): external port to listen on for HTTP messages
        hook (str): URL of external web hook to notify of credential issuance and revocations
        timeout (int): escrow timeout (in minutes) for events not delivered to upstream web hook
        retry (int): retry delay (in seconds) for failed web hook attempts

    """
    cues = decking.Deck()
    # make hab
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True)

    logger.info(f"Using hab {hab.name}:{hab.pre}")

    # Set up components to listen for credential presentations in direct HTTP mode with HttpEnd
    reger = viring.Reger(name=hab.name, db=hab.db, temp=False)
    verifier = verifying.Verifier(hby=hby, reger=reger)

    mbx = storing.Mailboxer(name=hby.name)
    exc = exchanging.Exchanger(hby=hby, handlers=[])

    app = falcon.App(middleware=cors_middleware())
    rep = storing.Respondant(hby=hby, mbx=mbx)

    # Set up KEL, TEL, Router, and Parser components for use with the HttpEnd in direct HTTP mode
    # Since ReportingAgent runs as a controller.
    rvy = routing.Revery(db=hby.db)
    kvy = eventing.Kevery(db=hby.db,
                          lax=True,
                          local=False,
                          rvy=rvy,
                          cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)
    tvy = Tevery(reger=verifier.reger,
                 db=hby.db,
                 local=False,
                 cues=cues)
    tvy.registerReplyRoutes(router=rvy.rtr)
    parser = parsing.Parser(framed=True,
                            kvy=kvy,
                            tvy=tvy,
                            rvy=rvy,
                            vry=verifier,
                            exc=exc)

    notifier = notifying.Notifier(hby=hby)
    # writes notifications for received IPEX grant exn messages
    protocoling.loadHandlers(hby=hby, exc=exc, notifier=notifier)

    # Set up reporting database to handle credential presentation cues
    cdb = basing.CueBaser(name=hby.name)
    if env_var_to_bool("CLEAR_ESCROWS", True):
        logger.info("Clearing escrows")
        cdb.clearEscrows()
    tc = TeveryCuery(cdb=cdb, reger=reger, cues=tvy.cues)

    comms = handling.Communicator(
        hby=hby,
        hab=hab,
        cdb=cdb,
        reger=reger,
        hook=hook,
        timeout=timeout,
        retry=retry)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    handling.loadHandlers(exc=exc, hby=hby, cdb=cdb)

    ending.loadEnds(app, hby=hby, default=hab.pre)
    # Set up HTTP endpoitnf or PUT-ing application/cesr streams to the ReportingAgent at '/'
    httpEnd = indirecting.HttpEnd(rxbs=parser.ims, mbx=mbx)
    app.add_route('/', httpEnd)

    # Health and metrics endpoint
    app.add_route("/health", HealthEnd(cdb=cdb))

    doers = [httpServerDoer, comms, tc]
    # reading notifications for received ipex grant exn messages
    doers.extend(handling.loadHandlers(cdb=cdb, hby=hby, notifier=notifier, parser=parser))

    # Long running Sally agent listening for presentations
    sallyAgent = ReportingAgent(hab=hab, parser=parser, kvy=kvy, tvy=tvy, rvy=rvy, exc=exc, cues=cues)
    doers.append(sallyAgent)

    return doers

def cesr_headers():
    """CESR HTTP Headers to be expected in requests"""
    return ['cesr-attachment', 'cesr-date', 'content-type']

def cors_middleware():
    return falcon.CORSMiddleware(
        allow_origins='*',
        allow_credentials='*',
        expose_headers=cesr_headers())

def env_var_to_bool(var_name, default=False):
    val = os.getenv(var_name, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ["true", "1"]
    return default

class ReportingAgent(doing.DoDoer):
    """
    Doer for running the reporting agent in direct HTTP mode rather than indirect mode.

    Direct mode is used when presenting directly to the reporting agent after resolving the reporting agent OOBI as a Controller OOBI.
    Indirect mode is used when presenting to the reporting agent via a mailbox whether from a witness or a mailbox agent.
    """

    def __init__(self, hab, parser, kvy, tvy, rvy, exc, cues=None, **opts):
        """
        Initializes the ReportingAgent with an identifier (Hab), parser, KEL, TEL, and Exchange message processor
        so that it can process incoming credential presentations.
        """
        self.hab = hab
        self.parser = parser
        self.kvy = kvy
        self.tvy = tvy
        self.rvy = rvy
        self.exc = exc
        self.cues = cues if cues is not None else decking.Deck()
        doers = [doing.doify(self.msgDo), doing.doify(self.escrowDo)]
        super().__init__(doers=doers, **opts)

    def msgDo(self, tymth=None, tock=0.0):
        """
        Processes incoming messages from the parser which triggers the KEL, TEL, Router, and Exchange
        message processor to process credential presentations.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.parser.ims:
            logger.debug(f"ReportingAgent received:\n%s\n...\n", self.parser.ims[:1024])
        done = yield from self.parser.parsator(local=True)
        return done

    def escrowDo(self, tymth=None, tock=0.0):
        """
        Processes KEL, TEL, Router, and Exchange message processor escrows.
        This ensures that each component processes the messages parsed from the HttpEnd.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.kvy.processEscrows()
            self.rvy.processEscrowReply()
            if self.tvy is not None:
                self.tvy.processEscrows()
            self.exc.processEscrow()

            yield