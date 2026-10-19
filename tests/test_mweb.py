############################################################
#  [*] Tests — MWEB Activation
#
#  Covers families/bitcoin/mweb.py on its own, against the
#  real node answers in tests/mweb_vectors.py:
#
#    - deployment_state reads a deployment the same way on
#      every chain: the regtest activation's bip9 reports at
#      each stage, the KNF mainnet node's bip8 report, a
#      buried deployment and newer Bitcoin Core's
#      getdeploymentinfo shape — and knows nothing of a
#      deployment the node does not report
#    - activation_height names the first MWEB block as soon
#      as the reports allow, after lock-in from a remembered
#      signalling period
#    - first_block_pending recognizes the one block that
#      needs a peg-in, and nothing else
#    - send_pegin makes the two wallet calls a peg-in takes,
#      routed to the configured wallet, with the fee rate only
#      when one is set
#    - pegin_hint turns each real refusal of the wallet into
#      the fix the operator needs
#    - MwebWatch announces each deployment state once,
#      explains the stall once per stuck tip (and again after
#      STALL_REMINDER_SECONDS), and sends one peg-in per stuck
#      tip — a failed one retried after PEGIN_RETRY_SECONDS, a
#      sent one never, never two at once
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import asyncio
import contextlib
import dataclasses
import io
import unittest
from unittest import mock

from anypool import coins
from anypool.coins.base import MwebPegin
from anypool.families.bitcoin import mweb
from anypool.families.bitcoin.mweb import (
    PEGIN_RETRY_SECONDS,
    STALL_REMINDER_SECONDS,
    MwebWatch,
    activation_height,
    deployment_state,
    first_block_pending,
    pegin_hint,
    send_pegin,
)
from anypool.node.rpc import NodeRPCError
from tests import mweb_vectors as mv
from tests.test_server import FakeNodeRPC


# The fresh MWEB address the fake wallet's getnewaddress hands
# out — not a real address, as nothing on a fake node checks
# it (test_mweb_activation.py hands it out too)
MWEB_ADDRESS = "tmweb1qq0anypooltestaddress"

# The panel titles the operator watches for, worded as
# display.py words them (test_mweb_activation.py checks the
# stall title too)
STALL_TITLE = "Mining stopped before the first MWEB block"
PEGIN_SENT_TITLE = "MWEB peg-in sent"
PEGIN_FAILED_TITLE = "MWEB peg-in failed"








############################################################
# chain_info
############################################################
#
# A getblockchaininfo answer built around one mweb softfork
# entry: a regtest chain at the given tip height, with the
# given tip hash — a filler hash when the test does not care
# which block is the tip — and the entry under softforks.
#
# Used by:
#   - stalled_node() (below)
#   - TestDeploymentState, TestActivationHeight,
#     TestFirstBlockPending, TestMwebWatchObserve and
#     TestMwebWatchDiagnose (below)
#   - tests/test_mweb_activation.py — stalled_server() and
#     the test cases there
############################################################

def chain_info(entry, blocks, tip_hash="ab" * 32):
    return {"chain": "regtest", "blocks": blocks, "bestblockhash": tip_hash, "softforks": {"mweb": entry}}








############################################################
# stalled_node
############################################################
#
# A FakeNodeRPC standing where the regtest node stood in
# front of its first MWEB block: MWEB applies to the next
# block, the tip carries no MWEB section, getnewaddress
# hands out MWEB_ADDRESS and a peg-in comes back with the
# real peg-in's txid. Given a node, it lays the stall over
# that one instead of a fresh FakeNodeRPC.
#
# Used by:
#   - TestSendPegin and TestMwebWatchDiagnose (below)
############################################################

def stalled_node(node=None):
    node = node or FakeNodeRPC()
    tip = mv.TIP_BEFORE_FIRST_MWEB_BLOCK
    node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING, tip["height"], tip["hash"])
    node.answers["getblock"] = dict(tip)
    node.answers["getnewaddress"] = MWEB_ADDRESS
    node.answers["sendtoaddress"] = mv.PEGIN_TXID
    return node








############################################################
# printed
############################################################
#
# Runs one coroutine with stdout captured, and hands back its
# result together with everything it printed.
#
# Used by:
#   - TestMwebWatchObserve and TestMwebWatchDiagnose (below)
############################################################

async def printed(coro):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = await coro
    return result, out.getvalue()








############################################################
# pegin_settings
############################################################
#
# The active coin — KNF, as tests/__init__.py pins it — with
# the given MWEB peg-in settings in its definition, patched
# into the coin registry for as long as the returned context
# is open; the defaults are what a peg-in-enabled pool would
# run with.
#
# Used by:
#   - TestMwebWatchObserve and TestMwebWatchDiagnose (below)
#   - tests/test_mweb_activation.py — TestFirstMwebBlockStall
############################################################

def pegin_settings(amount="1", wallet="pool", fee_rate="10"):
    knf = dataclasses.replace(coins.REGISTRY["KNF"], mweb_pegin=MwebPegin(amount, wallet, fee_rate))
    return mock.patch.dict(coins.REGISTRY, {"KNF": knf})








############################################################
# SlowWallet
############################################################
#
# A FakeNodeRPC whose sendtoaddress holds until the test
# opens `wallet_gate`, announcing through `at_wallet` that a
# peg-in is in flight — the window in which a second
# template poll must not send another one. stalled_node()
# lays the stall over it.
#
# Used by:
#   - test_two_polls_at_once_send_one_peg_in (below, in
#     TestMwebWatchDiagnose)
############################################################

class SlowWallet(FakeNodeRPC):






    ############################################################
    # __init__
    ############################################################
    #
    # A FakeNodeRPC plus the two events: the peg-in arrived,
    # the peg-in may go on.
    #
    # Used by:
    #   - test_two_polls_at_once_send_one_peg_in (below) — the
    #     one SlowWallet it builds
    ############################################################

    def __init__(self):
        super().__init__()
        self.at_wallet = asyncio.Event()
        self.wallet_gate = asyncio.Event()






    ############################################################
    # call
    ############################################################
    #
    # sendtoaddress waits for the gate; every call is then
    # answered as FakeNodeRPC answers it.
    #
    # Used by:
    #   - families/bitcoin/mweb.py — MwebWatch.diagnose() and
    #     send_pegin(), on the node
    #     test_two_polls_at_once_send_one_peg_in hands them
    ############################################################

    async def call(self, method, params=None, timeout=10.0, wallet=None):
        if method == "sendtoaddress":
            self.at_wallet.set()
            await self.wallet_gate.wait()
        return await super().call(method, params, timeout, wallet)








############################################################
# TestDeploymentState
############################################################
#
# deployment_state() read against the node's real reports in
# every shape a pool meets — bip9, bip8, buried, and newer
# Bitcoin Core's layout — so one reader serves every chain;
# an answer without a usable mweb entry gives nothing.
############################################################

class TestDeploymentState(unittest.TestCase):






    ############################################################
    # test_regtest_reports_at_every_stage
    ############################################################
    #
    # Every stage of the real regtest activation reads as the
    # node meant it: status, whether the next block is bound,
    # the height the status began at, the activation height
    # once active, and the tally while blocks signal.
    ############################################################

    def test_regtest_reports_at_every_stage(self):
        stages = [
            (mv.SOFTFORK_DEFINED, "defined", False, 0, None),
            (mv.SOFTFORK_STARTED, "started", False, 144, None),
            (mv.SOFTFORK_LOCKED_IN, "locked_in", False, 288, None),
            (mv.SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING, "active", True, 432, 432),
            (mv.SOFTFORK_ACTIVE, "active", True, 432, 432),
        ]
        for entry, status, active, since, height in stages:
            with self.subTest(status=status, active=active):
                state = deployment_state(chain_info(entry, 0))
                self.assertEqual((state["status"], state["active"], state["since"], state["height"]),
                                 (status, active, since, height))

        started = deployment_state(chain_info(mv.SOFTFORK_STARTED, 150))
        self.assertEqual((started["period"], started["threshold"], started["elapsed"], started["count"]),
                         (144, 108, 7, 7))






    ############################################################
    # test_knf_mainnet_bip8_report
    ############################################################
    #
    # The live KNF mainnet node reports MWEB as bip8 (its start
    # set by height) — read exactly like regtest's bip9.
    ############################################################

    def test_knf_mainnet_bip8_report(self):
        state = deployment_state(chain_info(mv.SOFTFORK_KNF_MAINNET, 6476))

        self.assertEqual((state["status"], state["active"], state["since"]), ("defined", False, 0))
        self.assertIsNone(state["period"])






    ############################################################
    # test_buried_deployment
    ############################################################
    #
    # A buried deployment has no details block: active, with
    # the height the node buried it at.
    ############################################################

    def test_buried_deployment(self):
        state = deployment_state(chain_info({"type": "buried", "active": True, "height": 2265984}, 2700000))

        self.assertEqual((state["status"], state["active"], state["since"], state["height"]),
                         ("active", True, 2265984, 2265984))






    ############################################################
    # test_getdeploymentinfo_shape
    ############################################################
    #
    # Newer Bitcoin Core moved deployments to getdeploymentinfo
    # under "deployments" — the same entries, read the same.
    ############################################################

    def test_getdeploymentinfo_shape(self):
        answer = {"hash": "cd" * 32, "height": 432, "deployments": {"mweb": mv.SOFTFORK_ACTIVE}}

        self.assertEqual(deployment_state(answer), deployment_state(chain_info(mv.SOFTFORK_ACTIVE, 432)))






    ############################################################
    # test_unknown_deployment_gives_nothing
    ############################################################
    #
    # A node that does not know MWEB gives no state — and nor
    # does no answer at all, an answer of the wrong shape, or
    # an mweb entry that is no object.
    ############################################################

    def test_unknown_deployment_gives_nothing(self):
        for answer in (None, [], {}, {"softforks": {}}, {"softforks": {"taproot": mv.SOFTFORK_ACTIVE}},
                       {"softforks": {"mweb": "active"}}):
            with self.subTest(answer=answer):
                self.assertIsNone(deployment_state(answer))






    ############################################################
    # test_entry_without_details_falls_back_on_the_active_flag
    ############################################################
    #
    # An entry without its details block falls back on the
    # active flag alone for its status, and knows no height
    # that status began at.
    ############################################################

    def test_entry_without_details_falls_back_on_the_active_flag(self):
        for active, status in ((True, "active"), (False, "defined")):
            with self.subTest(active=active):
                state = deployment_state(chain_info({"type": "bip9", "active": active}, 0))
                self.assertEqual((state["status"], state["since"]), (status, None))








############################################################
# TestActivationHeight
############################################################
#
# activation_height(): when the node's reports tell the
# height of the first MWEB block — named outright, or
# following from lock-in and a remembered period — and when
# nothing can tell it yet.
############################################################

class TestActivationHeight(unittest.TestCase):






    ############################################################
    # test_active_deployment_names_its_height
    ############################################################
    #
    # Active: the node names the height — or its "since" when
    # it does not.
    ############################################################

    def test_active_deployment_names_its_height(self):
        self.assertEqual(activation_height(deployment_state(chain_info(mv.SOFTFORK_ACTIVE, 432))), 432)

        unnamed = {key: value for key, value in mv.SOFTFORK_ACTIVE.items() if key != "height"}
        self.assertEqual(activation_height(deployment_state(chain_info(unnamed, 432))), 432)






    ############################################################
    # test_locked_in_follows_from_the_period
    ############################################################
    #
    # Locked in at 288 with a 144-block period: active from
    # 432, which is where the real chain activated. The node
    # drops the period after lock-in, so it comes from memory.
    ############################################################

    def test_locked_in_follows_from_the_period(self):
        locked_in = deployment_state(chain_info(mv.SOFTFORK_LOCKED_IN, 301))

        self.assertEqual(activation_height(locked_in, period=144), 432)
        self.assertIsNone(activation_height(locked_in))






    ############################################################
    # test_not_known_before_lock_in
    ############################################################
    #
    # Before lock-in nothing tells the height yet.
    ############################################################

    def test_not_known_before_lock_in(self):
        for entry in (mv.SOFTFORK_DEFINED, mv.SOFTFORK_STARTED, mv.SOFTFORK_KNF_MAINNET):
            with self.subTest(entry=entry["type"]):
                self.assertIsNone(activation_height(deployment_state(chain_info(entry, 0)), period=144))
        self.assertIsNone(activation_height(None))








############################################################
# TestFirstBlockPending
############################################################
#
# first_block_pending(): the one moment a chain needs a
# peg-in — MWEB bound from the next block while the tip has
# no MWEB section — told apart from every other state.
############################################################

class TestFirstBlockPending(unittest.TestCase):






    ############################################################
    # test_the_real_stall_is_recognized
    ############################################################
    #
    # The real stall: MWEB bound from the next block, the tip
    # without an MWEB section.
    ############################################################

    def test_the_real_stall_is_recognized(self):
        state = deployment_state(chain_info(mv.SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING, 431))

        self.assertTrue(first_block_pending(state, mv.TIP_BEFORE_FIRST_MWEB_BLOCK))






    ############################################################
    # test_everything_else_is_no_stall
    ############################################################
    #
    # A tip that has its MWEB section is past the first block;
    # a chain before activation is not there yet; and nothing
    # known means no stall.
    ############################################################

    def test_everything_else_is_no_stall(self):
        active = deployment_state(chain_info(mv.SOFTFORK_ACTIVE, 432))
        locked_in = deployment_state(chain_info(mv.SOFTFORK_LOCKED_IN, 301))
        tip_with_mweb = dict(mv.TIP_BEFORE_FIRST_MWEB_BLOCK, mweb=mv.FIRST_MWEB_BLOCK_MWEB_ENTRY)

        self.assertFalse(first_block_pending(active, tip_with_mweb))
        self.assertFalse(first_block_pending(locked_in, mv.TIP_BEFORE_FIRST_MWEB_BLOCK))
        self.assertFalse(first_block_pending(None, mv.TIP_BEFORE_FIRST_MWEB_BLOCK))
        self.assertFalse(first_block_pending(active, None))








############################################################
# TestSendPegin
############################################################
#
# send_pegin() against a fake node: the two wallet calls a
# peg-in takes, how the wallet name and the fee rate travel
# with them, and how the wallet's refusal comes back.
############################################################

class TestSendPegin(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_pegin_pays_a_fresh_mweb_address
    ############################################################
    #
    # A peg-in is a fresh MWEB address of the wallet and a
    # payment to it, both routed to the named wallet, the fee
    # rate riding along as a named argument.
    ############################################################

    async def test_pegin_pays_a_fresh_mweb_address(self):
        node = stalled_node()

        txid = await send_pegin(node, "0.5", "pool", "12")

        self.assertEqual(txid, mv.PEGIN_TXID)
        self.assertEqual(node.calls, [
            ("getnewaddress", ["", "mweb"]),
            ("sendtoaddress", {"address": MWEB_ADDRESS, "amount": "0.5", "fee_rate": "12"}),
        ])
        self.assertEqual(node.wallets, [("getnewaddress", "pool"), ("sendtoaddress", "pool")])






    ############################################################
    # test_no_fee_rate_and_no_wallet_name
    ############################################################
    #
    # Without a fee rate the payment leaves the fee to the
    # wallet; without a wallet name the calls take the node's
    # plain endpoint.
    ############################################################

    async def test_no_fee_rate_and_no_wallet_name(self):
        node = stalled_node()

        await send_pegin(node, "1", None)

        self.assertEqual(node.calls_to("sendtoaddress"), [{"address": MWEB_ADDRESS, "amount": "1"}])
        self.assertEqual(node.wallets, [("getnewaddress", None), ("sendtoaddress", None)])






    ############################################################
    # test_a_refusal_is_raised
    ############################################################
    #
    # The wallet's refusal reaches the caller as the node's
    # own error.
    ############################################################

    async def test_a_refusal_is_raised(self):
        node = stalled_node()
        node.answers["sendtoaddress"] = NodeRPCError(mv.PEGIN_REFUSALS["insufficient_funds"])

        with self.assertRaises(NodeRPCError) as raised:
            await send_pegin(node, "1", None)
        self.assertEqual(raised.exception.code, -6)








############################################################
# TestPeginHint
############################################################
#
# pegin_hint() over the wallet's real refusals: each mapped
# to the fix the operator needs, read from the message where
# two refusals share a code, and no hint for what it does
# not know.
############################################################

class TestPeginHint(unittest.TestCase):






    ############################################################
    # test_every_real_refusal_gets_its_fix
    ############################################################
    #
    # Every real refusal the wallet gave gets its fix — and
    # the fixes cover exactly the captured refusals, so one
    # added to the vectors without a fix fails here.
    ############################################################

    def test_every_real_refusal_gets_its_fix(self):
        fixes = {
            "no_wallet_loaded": "Load a wallet",
            "wallet_not_found": "Load a wallet",
            "wallet_not_specified": "MWEB_PEGIN_WALLET",
            "fee_rate_below_minimum": "below the wallet's minimum fee rate",
            "insufficient_funds": "no spendable coins",
            "wallet_disabled": "without wallet support",
        }
        self.assertEqual(set(fixes), set(mv.PEGIN_REFUSALS))
        for label, fix in fixes.items():
            with self.subTest(refusal=label):
                self.assertIn(fix, pegin_hint(NodeRPCError(mv.PEGIN_REFUSALS[label])))






    ############################################################
    # test_one_code_two_fixes
    ############################################################
    #
    # A fee rate too low and a wallet too poor share code -6;
    # the hint follows the message, not the code.
    ############################################################

    def test_one_code_two_fixes(self):
        low_fee = NodeRPCError(mv.PEGIN_REFUSALS["fee_rate_below_minimum"])
        no_coins = NodeRPCError(mv.PEGIN_REFUSALS["insufficient_funds"])

        self.assertEqual(low_fee.code, no_coins.code)
        self.assertNotEqual(pegin_hint(low_fee), pegin_hint(no_coins))






    ############################################################
    # test_no_fee_estimate
    ############################################################
    #
    # A wallet without a fee estimate (the node's own wording,
    # from its transaction assembler) is told to set a rate.
    ############################################################

    def test_no_fee_estimate(self):
        refusal = NodeRPCError({"code": -6, "message": "Fee estimation failed. Fallbackfee is disabled. "
                                                       "Wait a few blocks or enable -fallbackfee."})

        self.assertIn("MWEB_PEGIN_FEE_RATE", pegin_hint(refusal))






    ############################################################
    # test_no_hint_for_the_unknown
    ############################################################
    #
    # An unknown refusal, and a failure that is no refusal at
    # all, get no hint.
    ############################################################

    def test_no_hint_for_the_unknown(self):
        self.assertIsNone(pegin_hint(NodeRPCError({"code": -1, "message": "something else entirely"})))
        self.assertIsNone(pegin_hint(ConnectionError("node unreachable")))








############################################################
# TestMwebWatchObserve
############################################################
#
# MwebWatch.observe(): the deployment announcements an
# operator sees as the chain moves through the activation,
# and silence when the node has nothing to report.
############################################################

class TestMwebWatchObserve(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # test_each_state_is_announced_once
    ############################################################
    #
    # Each state is announced once, however many tips report
    # it.
    ############################################################

    async def test_each_state_is_announced_once(self):
        watch, node = MwebWatch(), FakeNodeRPC()
        stages = [
            (mv.SOFTFORK_DEFINED, 0), (mv.SOFTFORK_DEFINED, 1),
            (mv.SOFTFORK_STARTED, 150), (mv.SOFTFORK_STARTED, 151),
            (mv.SOFTFORK_LOCKED_IN, 301),
            (mv.SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING, 431), (mv.SOFTFORK_ACTIVE, 432),
        ]

        output = ""
        for entry, blocks in stages:
            node.answers["getblockchaininfo"] = chain_info(entry, blocks)
            _, out = await printed(watch.observe(node))
            output += out

        for status in ("defined", "started", "locked_in", "active"):
            with self.subTest(status=status):
                self.assertEqual(output.count(f"MWEB deployment: {status}"), 1)






    ############################################################
    # test_lock_in_names_the_first_block_and_its_peg_in
    ############################################################
    #
    # At lock-in the period remembered from signalling names
    # the first MWEB block — 432 on the real chain — and the
    # panel says what that block will need: it asks for
    # MWEB_PEGIN_AMOUNT when none is set, and names the
    # amount the pool will peg in when one is.
    ############################################################

    async def test_lock_in_names_the_first_block_and_its_peg_in(self):
        watch, node = MwebWatch(), FakeNodeRPC()
        node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_STARTED, 150)
        await printed(watch.observe(node))

        node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_LOCKED_IN, 301)
        with pegin_settings(amount=""):
            _, without_pegin = await printed(watch.observe(node))

        self.assertIn("height 432", without_pegin)
        self.assertIn("peg-in", without_pegin)
        self.assertIn("Set MWEB_PEGIN_AMOUNT", without_pegin)

        watch.status = None
        with pegin_settings(amount="0.25"):
            _, with_pegin = await printed(watch.observe(node))
        self.assertIn("The pool will peg in 0.25", with_pegin)






    ############################################################
    # test_no_peg_in_note_after_the_first_block
    ############################################################
    #
    # Once the first MWEB block is in, the active panel has
    # nothing to warn about.
    ############################################################

    async def test_no_peg_in_note_after_the_first_block(self):
        watch, node = MwebWatch(), FakeNodeRPC()
        node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_ACTIVE, 432)

        state, output = await printed(watch.observe(node))

        self.assertEqual(state["status"], "active")
        self.assertIn("height 432", output)
        self.assertNotIn("peg-in", output)






    ############################################################
    # test_silence_without_an_answer
    ############################################################
    #
    # A node that fails, or does not know MWEB, makes the watch
    # say nothing.
    ############################################################

    async def test_silence_without_an_answer(self):
        watch, node = MwebWatch(), FakeNodeRPC()

        for answer in (ConnectionError("node unreachable"), {"blocks": 5, "softforks": {}}):
            with self.subTest(answer=type(answer).__name__):
                node.answers["getblockchaininfo"] = answer
                state, output = await printed(watch.observe(node))
                self.assertIsNone(state)
                self.assertEqual(output, "")








############################################################
# TestMwebWatchDiagnose
############################################################
#
# MwebWatch.diagnose() on a stalled fake node with a fake
# clock: the first MWEB block's stall told apart from every
# other template failure, how often the stall is explained,
# and the one-peg-in-per-stuck-tip rule with its retry.
############################################################

class TestMwebWatchDiagnose(unittest.IsolatedAsyncioTestCase):






    ############################################################
    # setUp
    ############################################################
    #
    # A fake clock for the retry and reminder intervals, and
    # the node's real refusal of the first MWEB block's
    # template as the failure every test diagnoses.
    ############################################################

    def setUp(self):
        self.now = 1000.0
        clock = mock.patch.object(mweb, "monotonic", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.stall = NodeRPCError(mv.STALL_ERROR)






    ############################################################
    # test_any_other_failure_is_left_alone
    ############################################################
    #
    # Not the first MWEB block — before activation, after the
    # first block, or a node that cannot even answer — is no
    # business of the watch: "other", and not a word printed.
    ############################################################

    async def test_any_other_failure_is_left_alone(self):
        before = stalled_node()
        before.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_LOCKED_IN, 301)
        after = stalled_node()
        after.answers["getblock"] = dict(mv.TIP_BEFORE_FIRST_MWEB_BLOCK, mweb=mv.FIRST_MWEB_BLOCK_MWEB_ENTRY)
        unreachable = stalled_node()
        unreachable.answers["getblockchaininfo"] = ConnectionError("node unreachable")

        for name, node in (("before", before), ("after", after), ("unreachable", unreachable)):
            with self.subTest(node=name), pegin_settings():
                verdict, output = await printed(MwebWatch().diagnose(node, self.stall))
                self.assertEqual(verdict, "other")
                self.assertEqual(output, "")
                self.assertEqual(node.calls_to("sendtoaddress"), [])






    ############################################################
    # test_stall_without_peg_in_is_explained_once
    ############################################################
    #
    # Without MWEB_PEGIN_AMOUNT the stall is explained once —
    # with the node's refusal and the manual remedy — and the
    # wallet is never touched.
    ############################################################

    async def test_stall_without_peg_in_is_explained_once(self):
        watch, node = MwebWatch(), stalled_node()

        with pegin_settings(amount="", wallet=None, fee_rate=""):
            first, output = await printed(watch.diagnose(node, self.stall))
            second, repeat = await printed(watch.diagnose(node, self.stall))

        self.assertEqual((first, second), ("stalled", "stalled"))
        self.assertIn(STALL_TITLE, output)
        self.assertIn("Block 432", output)
        self.assertIn("bad-txns-vin-empty", output)
        self.assertIn("getnewaddress", output)
        self.assertEqual(repeat, "")
        self.assertEqual(node.calls_to("getnewaddress"), [])






    ############################################################
    # test_a_lasting_stall_is_explained_again
    ############################################################
    #
    # A stall that lasts is explained again every
    # STALL_REMINDER_SECONDS — a stopped chain never goes quiet.
    ############################################################

    async def test_a_lasting_stall_is_explained_again(self):
        watch, node = MwebWatch(), stalled_node()

        with pegin_settings(amount=""):
            await printed(watch.diagnose(node, self.stall))
            self.now += STALL_REMINDER_SECONDS - 1
            _, early = await printed(watch.diagnose(node, self.stall))
            self.now += 1
            _, reminder = await printed(watch.diagnose(node, self.stall))

        self.assertEqual(early, "")
        self.assertIn(STALL_TITLE, reminder)






    ############################################################
    # test_peg_in_unsticks_the_chain
    ############################################################
    #
    # With MWEB_PEGIN_AMOUNT set the watch pegs in through the
    # configured wallet and answers "unstuck", so the caller
    # asks for the template again at once.
    ############################################################

    async def test_peg_in_unsticks_the_chain(self):
        watch, node = MwebWatch(), stalled_node()

        with pegin_settings(amount="1", wallet="pool", fee_rate="10"):
            verdict, output = await printed(watch.diagnose(node, self.stall))

        self.assertEqual(verdict, "unstuck")
        self.assertEqual(node.calls_to("sendtoaddress"),
                         [{"address": MWEB_ADDRESS, "amount": "1", "fee_rate": "10"}])
        self.assertIn(("sendtoaddress", "pool"), node.wallets)
        self.assertIn(STALL_TITLE, output)
        self.assertIn(PEGIN_SENT_TITLE, output)
        self.assertIn(mv.PEGIN_TXID, output)






    ############################################################
    # test_a_sent_peg_in_is_never_repeated
    ############################################################
    #
    # A peg-in that went out is never sent again for the same
    # tip; a later reminder names it and points at its fee.
    ############################################################

    async def test_a_sent_peg_in_is_never_repeated(self):
        watch, node = MwebWatch(), stalled_node()

        with pegin_settings():
            await printed(watch.diagnose(node, self.stall))
            again, _ = await printed(watch.diagnose(node, self.stall))
            self.now += STALL_REMINDER_SECONDS
            later, reminder = await printed(watch.diagnose(node, self.stall))

        self.assertEqual((again, later), ("stalled", "stalled"))
        self.assertEqual(len(node.calls_to("sendtoaddress")), 1)
        self.assertIn("Peg-in already sent", reminder)
        self.assertIn(mv.PEGIN_TXID, reminder)






    ############################################################
    # test_a_failed_peg_in_is_retried_after_the_interval
    ############################################################
    #
    # A refused peg-in is reported with its fix and tried again
    # once PEGIN_RETRY_SECONDS have passed — not before.
    ############################################################

    async def test_a_failed_peg_in_is_retried_after_the_interval(self):
        watch, node = MwebWatch(), stalled_node()
        node.answers["sendtoaddress"] = NodeRPCError(mv.PEGIN_REFUSALS["insufficient_funds"])

        with pegin_settings():
            first, output = await printed(watch.diagnose(node, self.stall))
            self.now += PEGIN_RETRY_SECONDS - 1
            await printed(watch.diagnose(node, self.stall))
            attempts_before = len(node.calls_to("sendtoaddress"))

            node.answers["sendtoaddress"] = mv.PEGIN_TXID
            self.now += 1
            retried, _ = await printed(watch.diagnose(node, self.stall))

        self.assertEqual(first, "stalled")
        self.assertIn(PEGIN_FAILED_TITLE, output)
        self.assertIn("no spendable coins", output)
        self.assertEqual(attempts_before, 1)
        self.assertEqual(retried, "unstuck")
        self.assertEqual(len(node.calls_to("sendtoaddress")), 2)






    ############################################################
    # test_a_new_stuck_tip_starts_over
    ############################################################
    #
    # A new stuck tip (another block at the same height) starts
    # over: explained again, pegged in again.
    ############################################################

    async def test_a_new_stuck_tip_starts_over(self):
        watch, node = MwebWatch(), stalled_node()

        with pegin_settings():
            await printed(watch.diagnose(node, self.stall))
            other_tip = dict(mv.TIP_BEFORE_FIRST_MWEB_BLOCK, hash="ef" * 32)
            node.answers["getblockchaininfo"] = chain_info(mv.SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING, 431, other_tip["hash"])
            node.answers["getblock"] = other_tip
            verdict, output = await printed(watch.diagnose(node, self.stall))

        self.assertEqual(verdict, "unstuck")
        self.assertIn(STALL_TITLE, output)
        self.assertEqual(len(node.calls_to("sendtoaddress")), 2)






    ############################################################
    # test_two_polls_at_once_send_one_peg_in
    ############################################################
    #
    # Two template polls failing at once send ONE peg-in: the
    # attempt is marked before the wallet call returns. The
    # waits are bounded, so a second peg-in stuck at the gate
    # fails the test instead of hanging the run.
    ############################################################

    async def test_two_polls_at_once_send_one_peg_in(self):
        watch, node = MwebWatch(), stalled_node(SlowWallet())

        with pegin_settings(), contextlib.redirect_stdout(io.StringIO()):
            first = asyncio.create_task(watch.diagnose(node, self.stall))
            try:
                await asyncio.wait_for(node.at_wallet.wait(), timeout=2.0)
                second = await asyncio.wait_for(watch.diagnose(node, self.stall), timeout=2.0)
            finally:
                node.wallet_gate.set()
            first = await asyncio.wait_for(first, timeout=2.0)

        self.assertEqual((first, second), ("unstuck", "stalled"))
        self.assertEqual(len(node.calls_to("sendtoaddress")), 1)








if __name__ == "__main__":
    unittest.main()
