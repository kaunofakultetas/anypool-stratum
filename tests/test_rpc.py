############################################################
#  [*] Tests — Full Node RPC Client
#
#  Covers node/rpc.py against a real HTTP server on the
#  loopback (aiohttp's own test server), answering the way a
#  Bitcoin Core-style node answers:
#
#    - a call posts a JSON-RPC 1.0 body with the configured
#      basic auth and hands back the result field
#    - named arguments travel as an object, and a wallet
#      call goes to that wallet's own endpoint, its name
#      escaped
#    - a refusal raises NodeRPCError with the node's code and
#      message — under the HTTP 500 the node sends it with,
#      and under a 200 alike — keeping the "RPC Error" text
#      the log has always shown
#    - an answer that is no JSON-RPC answer (an HTML error
#      page, plain text, an error status without a refusal)
#      reports the bare HTTP status instead
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import base64
import unittest

from aiohttp import web
from aiohttp.test_utils import TestServer

from anypool import config
from anypool.node.rpc import NodeRPC, NodeRPCError
from tests import mweb_vectors as mv








############################################################
# TestNodeRPC
############################################################
#
# NodeRPC.call() against a real HTTP server on the loopback:
# what goes over the wire — path, body, credentials — and
# what comes back for every kind of answer a node, or a
# proxy in front of it, can give.
############################################################

class TestNodeRPC(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # asyncSetUp
    ############################################################
    #
    # A node on the loopback — aiohttp's test server on a free
    # port — that records each request and answers with
    # `reply`, an empty successful answer until a test sets
    # its own; and a NodeRPC pointed at it.
    ############################################################

    async def asyncSetUp(self):
        self.requests = []
        self.reply = (200, {"result": None, "error": None, "id": "stratum"})

        app = web.Application()
        app.router.add_post("/{tail:.*}", self.answer)
        self.node = TestServer(app, host="127.0.0.1")
        await self.node.start_server()

        self.rpc = NodeRPC()
        self.rpc.url = f"http://127.0.0.1:{self.node.port}"






    ############################################################
    # asyncTearDown
    ############################################################
    #
    # Closes the client's session and stops the node.
    ############################################################

    async def asyncTearDown(self):
        await self.rpc.close()
        await self.node.close()






    ############################################################
    # answer
    ############################################################
    #
    # The loopback node's handler for every POST: records the
    # request as it arrived (the raw path, the decoded body,
    # the Authorization header) and answers with `reply` — a
    # status with a JSON body, or with text served as an HTML
    # page, the way an overloaded node or a proxy answers.
    #
    # Used by:
    #   - asyncSetUp (above) — the route every request takes
    ############################################################

    async def answer(self, request):
        self.requests.append({
            "path": request.raw_path,
            "body": await request.json(),
            "auth": request.headers.get("Authorization"),
        })
        status, body = self.reply
        if isinstance(body, dict):
            return web.json_response(body, status=status)
        return web.Response(status=status, text=body, content_type="text/html")






    ############################################################
    # test_call_posts_a_json_rpc_body_and_returns_the_result
    ############################################################
    #
    # The request a plain call sends — a JSON-RPC 1.0 body on
    # the root path, with the configured basic auth — and the
    # result it hands back.
    ############################################################

    async def test_call_posts_a_json_rpc_body_and_returns_the_result(self):
        self.reply = (200, {"result": 6476, "error": None, "id": "stratum"})

        result = await self.rpc.call("getblockcount")

        credentials = base64.b64encode(f"{config.RPC_USER}:{config.RPC_PASS}".encode()).decode()
        self.assertEqual(result, 6476)
        self.assertEqual(self.requests, [{
            "path": "/",
            "body": {"jsonrpc": "1.0", "id": "stratum", "method": "getblockcount", "params": []},
            "auth": f"Basic {credentials}",
        }])






    ############################################################
    # test_named_arguments_travel_as_an_object
    ############################################################
    #
    # Named arguments travel as an object, positional ones as
    # a list.
    ############################################################

    async def test_named_arguments_travel_as_an_object(self):
        self.reply = (200, {"result": mv.PEGIN_TXID, "error": None, "id": "stratum"})

        await self.rpc.call("sendtoaddress", {"address": "tmweb1qq", "amount": "1", "fee_rate": "10"})
        await self.rpc.call("getnewaddress", ["", "mweb"])

        self.assertEqual(self.requests[0]["body"]["params"], {"address": "tmweb1qq", "amount": "1", "fee_rate": "10"})
        self.assertEqual(self.requests[1]["body"]["params"], ["", "mweb"])






    ############################################################
    # test_wallet_calls_go_to_the_wallets_endpoint
    ############################################################
    #
    # A wallet call goes to that wallet's own endpoint under
    # /wallet/, its name escaped whole — a slash or space in
    # it cannot change the path — while a call without a
    # wallet stays on the root path.
    ############################################################

    async def test_wallet_calls_go_to_the_wallets_endpoint(self):
        self.reply = (200, {"result": "tmweb1qq", "error": None, "id": "stratum"})

        await self.rpc.call("getnewaddress", ["", "mweb"], wallet="pool")
        await self.rpc.call("getnewaddress", ["", "mweb"], wallet="pool wallet/2")
        await self.rpc.call("getnewaddress", ["", "mweb"])

        self.assertEqual([request["path"] for request in self.requests],
                         ["/wallet/pool", "/wallet/pool%20wallet%2F2", "/"])






    ############################################################
    # test_refusal_under_http_500_is_a_node_rpc_error
    ############################################################
    #
    # The node's real refusal of the first MWEB block's
    # template, under HTTP 500: a NodeRPCError carrying its
    # code and message, worded as the log always showed it.
    ############################################################

    async def test_refusal_under_http_500_is_a_node_rpc_error(self):
        self.reply = (500, {"result": None, "error": mv.STALL_ERROR, "id": "stratum"})

        with self.assertRaises(NodeRPCError) as raised:
            await self.rpc.call("getblocktemplate", [{"rules": ["segwit", "mweb"]}])

        self.assertEqual(raised.exception.code, -1)
        self.assertEqual(raised.exception.message, mv.STALL_ERROR["message"])
        self.assertEqual(str(raised.exception), f"RPC Error: {mv.STALL_ERROR}")






    ############################################################
    # test_refusal_under_http_200_too
    ############################################################
    #
    # A refusal under HTTP 200 is the same refusal.
    ############################################################

    async def test_refusal_under_http_200_too(self):
        self.reply = (200, {"result": None, "error": mv.PEGIN_REFUSALS["insufficient_funds"], "id": "stratum"})

        with self.assertRaises(NodeRPCError) as raised:
            await self.rpc.call("sendtoaddress", {"address": "tmweb1qq", "amount": "1"})

        self.assertEqual((raised.exception.code, raised.exception.message), (-6, "Insufficient funds"))






    ############################################################
    # test_no_json_rpc_answer_reports_the_status
    ############################################################
    #
    # Anything that is no JSON-RPC answer reports the HTTP
    # status and the start of the body — and is no refusal.
    ############################################################

    async def test_no_json_rpc_answer_reports_the_status(self):
        cases = [
            ((502, "<html><body>Bad Gateway</body></html>"), "RPC HTTP 502 from node: <html><body>Bad Gateway</body></html>"),
            ((200, "work queue depth exceeded"), "RPC HTTP 200 from node: work queue depth exceeded"),
            ((503, {"result": None, "error": None, "id": "stratum"}), "RPC HTTP 503 from node: "),
        ]
        for reply, text in cases:
            with self.subTest(status=reply[0]):
                self.reply = reply
                with self.assertRaises(Exception) as raised:
                    await self.rpc.call("getblocktemplate")
                self.assertNotIsInstance(raised.exception, NodeRPCError)
                self.assertTrue(str(raised.exception).startswith(text), str(raised.exception))








############################################################
# TestNodeRPCError
############################################################
#
# NodeRPCError built straight from an error that is not the
# usual object — a shape no node in TestNodeRPC sends, which
# the pool must still keep and log whole.
############################################################

class TestNodeRPCError(unittest.TestCase):






    ############################################################
    # test_odd_error_shapes_are_kept_whole
    ############################################################
    #
    # An error that is not the usual object with a code and a
    # message is kept whole: no code, its text as the message,
    # and the log's usual wording.
    ############################################################

    def test_odd_error_shapes_are_kept_whole(self):
        error = NodeRPCError("Work queue depth exceeded")

        self.assertIsNone(error.code)
        self.assertEqual(error.message, "Work queue depth exceeded")
        self.assertEqual(str(error), "RPC Error: Work queue depth exceeded")








if __name__ == "__main__":
    unittest.main()
