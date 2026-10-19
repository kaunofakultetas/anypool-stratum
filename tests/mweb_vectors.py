############################################################
#  [*] MWEB Activation Test Vectors
#
#  Real node answers and real accepted blocks from MWEB's
#  activation, captured on 2026-10-19 from a throwaway regtest
#  KnfCoin node (image vuknf/knfcoin-fullnode:20260713, no
#  network) whose MWEB deployment activated at height 432 —
#  regtest's 144-block signalling window. The blocks were
#  mined with this pool's own build_job(), build_header() and
#  assemble_block(), with the environment tests/__init__.py
#  pins, and the node accepted each one (submitblock null):
#
#    - a block before MWEB, ending right after its
#      transactions — no MWEB marker
#    - the first MWEB block: coinbase, the peg-in it needed,
#      the HogEx, then the MWEB section
#    - the next MWEB block: coinbase and a HogEx spending the
#      previous one, then the MWEB section
#
#  Next to them: the node's deployment report at every stage,
#  the tip it refused to build on and the refusal itself, and
#  the wallet's real refusals of a peg-in. The one live answer
#  is the KNF mainnet node's report, read on the same day.
#
#  Used by:
#    - tests/test_mweb.py, test_mweb_activation.py,
#      test_rpc.py, test_blocks.py, test_jobs.py
############################################################








############################################################
# Deployment reports
############################################################
#
# getblockchaininfo's softforks entry for mweb at each stage
# of the regtest activation (a bip9 deployment, its start
# set by time) and the live KNF mainnet node's entry (bip8,
# its start set by height), with the chain height the node
# reported next to each.
############################################################

# Tip 0: nothing signalled yet
SOFTFORK_DEFINED = {
    "type": "bip9",
    "bip9": {
        "status": "defined",
        "start_time": 1601450001,
        "timeout": 9223372036854775807,
        "since": 0,
    },
    "active": False,
}

# Tip 150: blocks signal, with the period's tally
SOFTFORK_STARTED = {
    "type": "bip9",
    "bip9": {
        "status": "started",
        "bit": 4,
        "start_time": 1601450001,
        "timeout": 9223372036854775807,
        "since": 144,
        "statistics": {
            "period": 144,
            "threshold": 108,
            "elapsed": 7,
            "count": 7,
            "possible": True,
        },
    },
    "active": False,
}

# Tip 301: locked in at 288, active one period later
SOFTFORK_LOCKED_IN = {
    "type": "bip9",
    "bip9": {
        "status": "locked_in",
        "start_time": 1601450001,
        "timeout": 9223372036854775807,
        "since": 288,
    },
    "active": False,
}

# Tip 431: the rules apply to the next block, the first MWEB block
SOFTFORK_ACTIVE_FIRST_BLOCK_PENDING = {
    "type": "bip9",
    "bip9": {
        "status": "active",
        "start_time": 1601450001,
        "timeout": 9223372036854775807,
        "since": 432,
    },
    "height": 432,
    "active": True,
}

# Tip 432: the first MWEB block is in
SOFTFORK_ACTIVE = {
    "type": "bip9",
    "bip9": {
        "status": "active",
        "start_time": 1601450001,
        "timeout": 9223372036854775807,
        "since": 432,
    },
    "height": 432,
    "active": True,
}

# The live KNF mainnet node at height 6476
SOFTFORK_KNF_MAINNET = {
    "type": "bip8",
    "bip8": {
        "status": "defined",
        "start_height": 0,
        "timeout_height": 9999999999,
        "since": 0,
    },
    "active": False,
}

# The tip height the node reported with each answer above.
# Nothing reads this table at the moment: the tests pass the
# heights inline, next to the entry they belong to.
CHAIN_HEIGHTS = {
    "defined": 0,
    "started": 150,
    "locked_in": 301,
    "active_first_block_pending": 431,
    "active_running": 432,
}








############################################################
# The stall
############################################################
#
# The tip the node refused to build on — getblock's answer,
# which lists no mweb entry — the refusal of
# getblocktemplate for block 432 while no peg-in waited, and
# getblock's mweb entry for the first MWEB block once it was
# in.
############################################################

TIP_BEFORE_FIRST_MWEB_BLOCK = {
    "hash": "34ddbab60d046a6e8cb6ebe6ee2badce92a5f3ff7ad7e1197d4ee468fdc851fd",
    "height": 431,
    "tx": ["841e6470e84279d1ae5d696eb705dfc44a29eb6608ac23ddd954d93c523e1562"],
}

STALL_ERROR = {
    "code": -1,
    "message": (
        "CreateNewBlock: TestBlockValidity failed: bad-txns-vin-empty, Tr"
        "ansaction check failed (tx hash 58338ec7c9c4e6086f9eef6093d79a69"
        "d930d7ca695d1759b07180fef29d8f8e) "
    ),
}

FIRST_MWEB_BLOCK_MWEB_ENTRY = {
    "hash": "8f6f376015da2dea574f851b0807cc7b24c5630606a9f4b29d56adb2381dbe57",
    "height": 432,
    "kernel_offset": "696e82af0eb57986eba891e7ad7e7a2357f45e4dbaa6adbc008b674f39b262d0",
    "stealth_offset": "5947ccc231fdb37c2f558dbfa5dc3c4b79cb35c29fde2e2378739d84d3184dd1",
    "num_kernels": 1,
    "num_txos": 2,
    "kernel_root": "75d03fa2f13cbc695406b1a48d5bd44c7900931b38822b0af8f5ed9cc13218c8",
    "output_root": "71dc8df5d16eed2fa8779a66f385ff72ebd0116b60fff4c6c6a08531e75fe5fe",
    "leaf_root": "af2edc674154ff129d9e826727ada0828d3ba480924bbed84bf6dcae2e1f1db2",
    "inputs": [],
    "outputs": [
        "33dc9d704543a04690cdc0701281eeeb72894e5ca0f92130709bba11a9b6085f",
        "39844da34ce5865260e8b4947b34e9a37bb117c77e2ddce1692cdd5914b7f47b",
    ],
    "kernels": ["091d0031ac620a6e1b05ed5ecc991b0cbafd3a452b3821f48d6c7c35f73dc77a1f"],
}








############################################################
# Peg-in refusals
############################################################
#
# The wallet's real answers to the peg-in calls when it
# could not pay: no wallet loaded, a wallet name the node
# does not know, several wallets and none named, a fee rate
# under the wallet's minimum, no coins, and a node started
# without wallet support.
############################################################

PEGIN_REFUSALS = {
    "no_wallet_loaded": {
        "code": -18,
        "message": (
            "No wallet is loaded. Load a wallet using loadwallet or create a "
            "new one with createwallet. (Note: A default wallet is no longer "
            "automatically created)"
        ),
    },
    "wallet_not_found": {
        "code": -18,
        "message": "Requested wallet does not exist or is not loaded",
    },
    "fee_rate_below_minimum": {
        "code": -6,
        "message": (
            "Fee rate (2.000 sat/vB) is lower than the minimum fee rate setti"
            "ng (10.000 sat/vB)"
        ),
    },
    "wallet_not_specified": {
        "code": -19,
        "message": (
            "Wallet file not specified (must request wallet RPC through /wall"
            "et/<filename> uri-path)."
        ),
    },
    "insufficient_funds": {
        "code": -6,
        "message": "Insufficient funds",
    },
    "wallet_disabled": {
        "code": -32601,
        "message": "Method not found",
    },
}








############################################################
# Accepted blocks
############################################################
#
# Each block as the pool built it: the template the node
# served, the share that solved it (extranonces, ntime,
# nonce), the header and its scrypt hash, and the block hex
# the node accepted, with the block's hash — recorded for
# reference, no test reads it. The peg-in the first MWEB
# block carries is PEGIN_TXID.
############################################################

# Block 201, before MWEB
PRE_MWEB_BLOCK = {
    "template": {
        "capabilities": ["proposal"],
        "version": 805306384,
        "rules": ["csv", "!segwit", "taproot"],
        "vbavailable": {
            "testdummy": 28,
            "mweb": 4,
        },
        "vbrequired": 0,
        "previousblockhash": "4089f718ce17c513a8c807ee554634a87719a6e58a524a9d8fc54123dad29cfe",
        "transactions": [],
        "coinbaseaux": {},
        "coinbasevalue": 2500000000,
        "longpollid": "4089f718ce17c513a8c807ee554634a87719a6e58a524a9d8fc54123dad29cfe203",
        "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
        "mintime": 1792387983,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
        "curtime": 1792387983,
        "bits": "207fffff",
        "height": 201,
        "default_witness_commitment": (
            "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48beb"
            "d836974e8cf9"
        ),
    },
    "extranonce1": "00000001",
    "extranonce2": "6c390000",
    "ntime": "6ad5ab8f",
    "nonce": "00000003",
    "header_hex": (
        "10000030fe9cd2da2341c58f9d4a528ae5a61977a8344655ee07c8a813c517ce"
        "18f789403e67034018459c770402760f97c9a8ababdabe24228e27156ca4801a"
        "a48e429c8fabd56affff7f2003000000"
    ),
    "pow_hash": "68053af7bc86ba6607812d5460aa04b8aae01e258a803dcc340b0cba8f82dbcd",
    "block_hex": (
        "10000030fe9cd2da2341c58f9d4a528ae5a61977a8344655ee07c8a813c517ce"
        "18f789403e67034018459c770402760f97c9a8ababdabe24228e27156ca4801a"
        "a48e429c8fabd56affff7f200300000001010000000001010000000000000000"
        "000000000000000000000000000000000000000000000000ffffffff1902c900"
        "000000016c3900002f5075626c6963204d696e65722fffffffff0200f9029500"
        "000000160014d328b4b46cef262169f8d7605498ad5ac5829e55000000000000"
        "0000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962"
        "b48bebd836974e8cf90120000000000000000000000000000000000000000000"
        "000000000000000000000000000000"
    ),
    "block_hash": "ee1fffdc9839419fe779974cf05956417cb4ec2474d3b2502cdc27cacbbaa7ae",
}

# Block 432, the first MWEB block
FIRST_MWEB_BLOCK = {
    "template": {
        "capabilities": ["proposal"],
        "version": 536870912,
        "rules": ["csv", "!segwit", "testdummy", "taproot", "mweb"],
        "vbavailable": {},
        "vbrequired": 0,
        "previousblockhash": "34ddbab60d046a6e8cb6ebe6ee2badce92a5f3ff7ad7e1197d4ee468fdc851fd",
        "transactions": [
            {
                "data": (
                    "020000000001011ef726d1e71caadb413c1d433402f60e9629574c96fdf51e4b"
                    "02c0e56d0f0f3d0000000000fdffffff012276814a00000000225920f033b068"
                    "1f50871267099e342cd7e02eb3479b15fa284775e2f881a032ae20e102473044"
                    "022063e54c53747a3ce48a6b7d25bf759989a2f6b5e1348edfedb750470163a9"
                    "2393022003533ec63ae0b225c277aa2609d3b50878e9b93ccebd4a9b52ea036f"
                    "8338533001210306bf83c2152c9ce9f5cfbf12071e724f5a996d929b92602d08"
                    "6f21d486da0686af010000"
                ),
                "txid": "5a5854b90e2db39db7620d7b8ef4e94cc4e2a038005843f78b20d1132ca88cdf",
                "hash": "50ced4de63340921996fc3fb90002dd39772cf842a84886e8f3eeb580ceba1bc",
                "depends": [],
                "fee": 5530,
                "sigops": 1,
                "weight": 485,
            },
            {
                "data": (
                    "02000000000801df8ca82c13d1208bf743580038a0e2c44ce9f48e7b0d62b79d"
                    "b32d0eb954585a0000000000ffffffff01e666814a000000002258208f6f3760"
                    "15da2dea574f851b0807cc7b24c5630606a9f4b29d56adb2381dbe5700000000"
                    "00"
                ),
                "txid": "f43df9413f9994e71db5582abeb091ecb58c19c47a6f3a8863be73cab9bf002e",
                "hash": "f43df9413f9994e71db5582abeb091ecb58c19c47a6f3a8863be73cab9bf002e",
                "depends": [1],
                "fee": 0,
                "sigops": 0,
                "weight": 376,
            },
        ],
        "coinbaseaux": {},
        "coinbasevalue": 1250005530,
        "longpollid": "34ddbab60d046a6e8cb6ebe6ee2badce92a5f3ff7ad7e1197d4ee468fdc851fd435",
        "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
        "mintime": 1792388021,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
        "curtime": 1792388021,
        "bits": "207fffff",
        "height": 432,
        "default_witness_commitment": (
            "6a24aa21a9edc1b91caa0c1aa838c3734c82407b296b4189f80af863cb4d07fe"
            "7eb74908fd16"
        ),
        "mweb": (
            "823071dc8df5d16eed2fa8779a66f385ff72ebd0116b60fff4c6c6a08531e75f"
            "e5fe75d03fa2f13cbc695406b1a48d5bd44c7900931b38822b0af8f5ed9cc132"
            "18c8af2edc674154ff129d9e826727ada0828d3ba480924bbed84bf6dcae2e1f"
            "1db2696e82af0eb57986eba891e7ad7e7a2357f45e4dbaa6adbc008b674f39b2"
            "62d05947ccc231fdb37c2f558dbfa5dc3c4b79cb35c29fde2e2378739d84d318"
            "4dd10201000208ea3e63830d8bf1243fcc94323e29567c84c623e83bc90679f3"
            "bce19c8aa0660f0286b94120e8b2a43f38f3d9874ea91ca58355ee3962d6b99f"
            "1ebeeff29485d1a9032982ea106d80c0c67883f8d0503f616c294cf3cc6692b2"
            "8edb078319f902f5b80103709c17f7b74a7201e83b3d3b1611a431657797ce90"
            "e91cd738b382feaa2ee869f961696087de3f6b9bec07fc10258dad860d657c7f"
            "eed379b7b16ddd1e3626030c70a35dc0bf34da7cdd36aeb7400a23f074139b30"
            "5eef7898de7941ea2d3b058615ac000364484413f073ac97882a41d7f549614a"
            "002a17ca07b8fae31ddcd3c59b6c094d9fd2046be7c71b99cb016d6c38712062"
            "2e576553d936ea29633f9db59a340cd12d9d694b9c60a5098ad71adc6ea9485a"
            "e358e4b1d4840d944e03a709d429eda81ffa50e7aaabf32ff1ca26c672f702c1"
            "80f00643f77e700136c162d64a4849499e7c90acd6210d4bcec3176bd3c507bd"
            "57e595a36d955483223b0abf976dc53ff4e2462b7d775308167f959fd13d8954"
            "1f2e317709446eae71554d308e90550d8b1bd550dabad77ea637387df944d511"
            "9685d68da4196d102d6248c260368e62745b0fc94f9f0893cfa0cd273949d5b0"
            "4db37756bb49a2aba6eb9105cf79dadca3322bd8a9866db6589901741aa89175"
            "e4493320518879bc1b02b8f24d02416bff5931212dfafcdbe7f5fdb4244604bb"
            "17f877e34e0b038bb61b3698c703f16f099746049bddd2413f7f558e7219ad90"
            "9c0d304dd5843ba295a217f95f220e1758606c800adae510dabeda6657634cdf"
            "aeb29a6b6452248b427a27cb5839e656c3e5edb137c5731e4bce9285904a70e9"
            "595691365891c57b13a64e414f14e2559a49dd937c09e19013a927247d7f9716"
            "40e6dfbe77eade492414912bc94159f7719f4c93b16e9e4e3bc2ed9ead10bdf8"
            "532649c0d0692213377c50ee12b1a1ff0142ca09461a2664138b644a6699e55f"
            "e3f0abf882bb654c1a4e40f507adbf8cbb416dd9a68b1fafaf6777d5a5ed0454"
            "f722245593ab930bdea2573a0389586d9230a6b39c6e6312e12fa44883e46089"
            "f816d73c7308400dc9a324b112e27df4d55beb82db7027b55f8b7366a4b25e3d"
            "a03cb98970f4c2989cb5f64592946e690b374d7dd0abcc3a9185354c80c61538"
            "9ec9681c0c4c7c6355a7759b3ef7d3602e1aa87448d21762c4306fa780f975c8"
            "c094a089cdb5d10e57f8d90b1e1eaf8f638284f8118569b978e0a3d99b7395f5"
            "ed95ee93d5b62f0847d612121b52da7a99fcb62d88127461294b07da05f02dbf"
            "9cb95ded5767d5f403f1bdfd486fd608d4ca99781072789d9b85a2edf191a49c"
            "c0423242e0b9f8a1a703887d17c081c852bcf7937333e841c6766955ab9579ca"
            "75a639ddb5a5c5928a1b01027087e10d45ef8bac5a382389cf22bb6263ecb6fa"
            "257ccea01f28feea8e4df72d39a3a2d303d82e0d0dbb05d947083f89187e691e"
            "f975e0176226c7be02679e15366524adc5bd5247b55b3dc5a7ec2f1637726c47"
            "f3543bf421cb801e11b29e3dbeb68dcae9ee9745179bc29bc08a7216212ec7ad"
            "693f1d8bc5051b8e9c6288dbfb0a10f2ee2d07cfc26b85b91efd9bd6a82556b3"
            "dfba61ce0ba05cd623c36311949bc0122192673a6dd06907a21aeab2ccdcef0d"
            "80f94490ed7513d33bb9e21e7c4fe32d0262ebcea7690471d22a4ea30e8412b7"
            "7154357013055a3a92a718cebcf7378464ffbcb726c7a7c3319d63ff778384bf"
            "5e392542d0ca576df207b3aae4362e1dbfbf354f4d2b0a63481962ba2bc65330"
            "8429d9645433c0d07124aecb2a588d3a24c20c91b514be5222db875961f02afc"
            "15b825e428d15875b11da460cee136c49306fb40a917bef21f6bc82349ec011e"
            "67f7b9829fe400272d0e6a61cd96ea1840d0d2e9a85ac74df7f8252c51b214f9"
            "9069d17ddf82402350fdd6aa74e73c354d5ab71a0f9222591aefeb7db604daaf"
            "af7df9c18d3eaf00b8ac5b5683bb4b7ace10a7b0b6c1e1459becf0b4b7e2224c"
            "b6fb3181603a40f81479c1eb0409eabcd975890d4662b0751eb0e0bb16655959"
            "3d8815500c3a20ebb49daa8e0407ad94a48d090321bf69fc81ed5c3acd1e2346"
            "264258b17984030960290cede01588e8197a3cfbc3959d4fb9dac02a64ed1a5b"
            "89f89137e5f80ea87bbc8e39dbd0c9ff6801772c2c5f0d0965b72b89d74a372b"
            "c5a762a8b5ad3e5d21cec525afc98a4edb0cd95346bc94d75f8bfaf7e217c2f2"
            "002c0fc0f3353b33d03ce3bd3d8df2d3f4fd0019e3c1c69e6a1a91e290f7eab3"
            "59cc40110fbb566010cdbb226ba5c74e2594d134b9892e4257a9bba246b1b44b"
            "06bb3e0c31c5b5449a189aad8270f57172893427fa9e7c221f1fa6d1fe0e8223"
            "bf2fe8ea0488e438f34fd134afd48e9f3225d98e398d011b0048de95addebf06"
            "9aa3906650461f91f21b139fe4a35697a82a6580544a97a378047dbb1743545b"
            "02c26fc91ce7f9898c7d927ee384bf1f44f8b633b65e11b1382cad00ea1a1a5c"
            "ac314c88d656ddeb01139d3c83d384eb220338f30c4b1d2ecf8e73cd486471e5"
            "9e1fb222931441a8ea13da01ef58100f143c091d0031ac620a6e1b05ed5ecc99"
            "1b0cbafd3a452b3821f48d6c7c35f73dc77a1f6c155694a96cdd1358abe35000"
            "7d9644f703676f7ebf3209d7bdfcf20cf35184d4922142651e81ada8df0bba9c"
            "69177a8b1ba21277cf84ee28daafa0627967fb"
        ),
    },
    "extranonce1": "00000001",
    "extranonce2": "6c390000",
    "ntime": "6ad5abb5",
    "nonce": "00000000",
    "header_hex": (
        "00000020fd51c8fd68e44e7d19e1d77afff3a592cead2beee6ebb68c6e6a040d"
        "b6badd34fe0420738514f40579a1d9b18556823ad732058b45c0fcda30b9b8e2"
        "06f7db5cb5abd56affff7f2000000000"
    ),
    "pow_hash": "484015abd74a67c37729c06c4df4ad5d248db635cb5c3bd28fe1fc7c5eeb01ce",
    "block_hex": (
        "00000020fd51c8fd68e44e7d19e1d77afff3a592cead2beee6ebb68c6e6a040d"
        "b6badd34fe0420738514f40579a1d9b18556823ad732058b45c0fcda30b9b8e2"
        "06f7db5cb5abd56affff7f200000000003010000000001010000000000000000"
        "000000000000000000000000000000000000000000000000ffffffff1902b001"
        "000000016c3900002f5075626c6963204d696e65722fffffffff021a92814a00"
        "000000160014d328b4b46cef262169f8d7605498ad5ac5829e55000000000000"
        "0000266a24aa21a9edc1b91caa0c1aa838c3734c82407b296b4189f80af863cb"
        "4d07fe7eb74908fd160120000000000000000000000000000000000000000000"
        "000000000000000000000000000000020000000001011ef726d1e71caadb413c"
        "1d433402f60e9629574c96fdf51e4b02c0e56d0f0f3d0000000000fdffffff01"
        "2276814a00000000225920f033b0681f50871267099e342cd7e02eb3479b15fa"
        "284775e2f881a032ae20e102473044022063e54c53747a3ce48a6b7d25bf7599"
        "89a2f6b5e1348edfedb750470163a92393022003533ec63ae0b225c277aa2609"
        "d3b50878e9b93ccebd4a9b52ea036f8338533001210306bf83c2152c9ce9f5cf"
        "bf12071e724f5a996d929b92602d086f21d486da0686af010000020000000008"
        "01df8ca82c13d1208bf743580038a0e2c44ce9f48e7b0d62b79db32d0eb95458"
        "5a0000000000ffffffff01e666814a000000002258208f6f376015da2dea574f"
        "851b0807cc7b24c5630606a9f4b29d56adb2381dbe57000000000001823071dc"
        "8df5d16eed2fa8779a66f385ff72ebd0116b60fff4c6c6a08531e75fe5fe75d0"
        "3fa2f13cbc695406b1a48d5bd44c7900931b38822b0af8f5ed9cc13218c8af2e"
        "dc674154ff129d9e826727ada0828d3ba480924bbed84bf6dcae2e1f1db2696e"
        "82af0eb57986eba891e7ad7e7a2357f45e4dbaa6adbc008b674f39b262d05947"
        "ccc231fdb37c2f558dbfa5dc3c4b79cb35c29fde2e2378739d84d3184dd10201"
        "000208ea3e63830d8bf1243fcc94323e29567c84c623e83bc90679f3bce19c8a"
        "a0660f0286b94120e8b2a43f38f3d9874ea91ca58355ee3962d6b99f1ebeeff2"
        "9485d1a9032982ea106d80c0c67883f8d0503f616c294cf3cc6692b28edb0783"
        "19f902f5b80103709c17f7b74a7201e83b3d3b1611a431657797ce90e91cd738"
        "b382feaa2ee869f961696087de3f6b9bec07fc10258dad860d657c7feed379b7"
        "b16ddd1e3626030c70a35dc0bf34da7cdd36aeb7400a23f074139b305eef7898"
        "de7941ea2d3b058615ac000364484413f073ac97882a41d7f549614a002a17ca"
        "07b8fae31ddcd3c59b6c094d9fd2046be7c71b99cb016d6c387120622e576553"
        "d936ea29633f9db59a340cd12d9d694b9c60a5098ad71adc6ea9485ae358e4b1"
        "d4840d944e03a709d429eda81ffa50e7aaabf32ff1ca26c672f702c180f00643"
        "f77e700136c162d64a4849499e7c90acd6210d4bcec3176bd3c507bd57e595a3"
        "6d955483223b0abf976dc53ff4e2462b7d775308167f959fd13d89541f2e3177"
        "09446eae71554d308e90550d8b1bd550dabad77ea637387df944d5119685d68d"
        "a4196d102d6248c260368e62745b0fc94f9f0893cfa0cd273949d5b04db37756"
        "bb49a2aba6eb9105cf79dadca3322bd8a9866db6589901741aa89175e4493320"
        "518879bc1b02b8f24d02416bff5931212dfafcdbe7f5fdb4244604bb17f877e3"
        "4e0b038bb61b3698c703f16f099746049bddd2413f7f558e7219ad909c0d304d"
        "d5843ba295a217f95f220e1758606c800adae510dabeda6657634cdfaeb29a6b"
        "6452248b427a27cb5839e656c3e5edb137c5731e4bce9285904a70e959569136"
        "5891c57b13a64e414f14e2559a49dd937c09e19013a927247d7f971640e6dfbe"
        "77eade492414912bc94159f7719f4c93b16e9e4e3bc2ed9ead10bdf8532649c0"
        "d0692213377c50ee12b1a1ff0142ca09461a2664138b644a6699e55fe3f0abf8"
        "82bb654c1a4e40f507adbf8cbb416dd9a68b1fafaf6777d5a5ed0454f7222455"
        "93ab930bdea2573a0389586d9230a6b39c6e6312e12fa44883e46089f816d73c"
        "7308400dc9a324b112e27df4d55beb82db7027b55f8b7366a4b25e3da03cb989"
        "70f4c2989cb5f64592946e690b374d7dd0abcc3a9185354c80c615389ec9681c"
        "0c4c7c6355a7759b3ef7d3602e1aa87448d21762c4306fa780f975c8c094a089"
        "cdb5d10e57f8d90b1e1eaf8f638284f8118569b978e0a3d99b7395f5ed95ee93"
        "d5b62f0847d612121b52da7a99fcb62d88127461294b07da05f02dbf9cb95ded"
        "5767d5f403f1bdfd486fd608d4ca99781072789d9b85a2edf191a49cc0423242"
        "e0b9f8a1a703887d17c081c852bcf7937333e841c6766955ab9579ca75a639dd"
        "b5a5c5928a1b01027087e10d45ef8bac5a382389cf22bb6263ecb6fa257ccea0"
        "1f28feea8e4df72d39a3a2d303d82e0d0dbb05d947083f89187e691ef975e017"
        "6226c7be02679e15366524adc5bd5247b55b3dc5a7ec2f1637726c47f3543bf4"
        "21cb801e11b29e3dbeb68dcae9ee9745179bc29bc08a7216212ec7ad693f1d8b"
        "c5051b8e9c6288dbfb0a10f2ee2d07cfc26b85b91efd9bd6a82556b3dfba61ce"
        "0ba05cd623c36311949bc0122192673a6dd06907a21aeab2ccdcef0d80f94490"
        "ed7513d33bb9e21e7c4fe32d0262ebcea7690471d22a4ea30e8412b771543570"
        "13055a3a92a718cebcf7378464ffbcb726c7a7c3319d63ff778384bf5e392542"
        "d0ca576df207b3aae4362e1dbfbf354f4d2b0a63481962ba2bc653308429d964"
        "5433c0d07124aecb2a588d3a24c20c91b514be5222db875961f02afc15b825e4"
        "28d15875b11da460cee136c49306fb40a917bef21f6bc82349ec011e67f7b982"
        "9fe400272d0e6a61cd96ea1840d0d2e9a85ac74df7f8252c51b214f99069d17d"
        "df82402350fdd6aa74e73c354d5ab71a0f9222591aefeb7db604daafaf7df9c1"
        "8d3eaf00b8ac5b5683bb4b7ace10a7b0b6c1e1459becf0b4b7e2224cb6fb3181"
        "603a40f81479c1eb0409eabcd975890d4662b0751eb0e0bb166559593d881550"
        "0c3a20ebb49daa8e0407ad94a48d090321bf69fc81ed5c3acd1e2346264258b1"
        "7984030960290cede01588e8197a3cfbc3959d4fb9dac02a64ed1a5b89f89137"
        "e5f80ea87bbc8e39dbd0c9ff6801772c2c5f0d0965b72b89d74a372bc5a762a8"
        "b5ad3e5d21cec525afc98a4edb0cd95346bc94d75f8bfaf7e217c2f2002c0fc0"
        "f3353b33d03ce3bd3d8df2d3f4fd0019e3c1c69e6a1a91e290f7eab359cc4011"
        "0fbb566010cdbb226ba5c74e2594d134b9892e4257a9bba246b1b44b06bb3e0c"
        "31c5b5449a189aad8270f57172893427fa9e7c221f1fa6d1fe0e8223bf2fe8ea"
        "0488e438f34fd134afd48e9f3225d98e398d011b0048de95addebf069aa39066"
        "50461f91f21b139fe4a35697a82a6580544a97a378047dbb1743545b02c26fc9"
        "1ce7f9898c7d927ee384bf1f44f8b633b65e11b1382cad00ea1a1a5cac314c88"
        "d656ddeb01139d3c83d384eb220338f30c4b1d2ecf8e73cd486471e59e1fb222"
        "931441a8ea13da01ef58100f143c091d0031ac620a6e1b05ed5ecc991b0cbafd"
        "3a452b3821f48d6c7c35f73dc77a1f6c155694a96cdd1358abe350007d9644f7"
        "03676f7ebf3209d7bdfcf20cf35184d4922142651e81ada8df0bba9c69177a8b"
        "1ba21277cf84ee28daafa0627967fb"
    ),
    "block_hash": "4a86343c6fc2c02dda76a0ce61567a81b8b389f51c110f7fbd9bcdac8f1530e4",
}

# Block 433, the next MWEB block
NEXT_MWEB_BLOCK = {
    "template": {
        "capabilities": ["proposal"],
        "version": 536870912,
        "rules": ["csv", "!segwit", "testdummy", "taproot", "mweb"],
        "vbavailable": {},
        "vbrequired": 0,
        "previousblockhash": "4a86343c6fc2c02dda76a0ce61567a81b8b389f51c110f7fbd9bcdac8f1530e4",
        "transactions": [
            {
                "data": (
                    "020000000008012e00bfb9ca73be63883a6f7ac4198cb5ec91b0be2a58b51de7"
                    "94993f41f93df40000000000ffffffff01e666814a0000000022582073a33b96"
                    "7603cd59878457cf1e41abda6b83293fe1f0ff36c0a11b274b6497fb00000000"
                    "00"
                ),
                "txid": "a64a3e0aa63951b368a406b4c441a7d17fad85b26c259ab77101284d4e96b921",
                "hash": "a64a3e0aa63951b368a406b4c441a7d17fad85b26c259ab77101284d4e96b921",
                "depends": [],
                "fee": 0,
                "sigops": 0,
                "weight": 376,
            },
        ],
        "coinbaseaux": {},
        "coinbasevalue": 1250000000,
        "longpollid": "4a86343c6fc2c02dda76a0ce61567a81b8b389f51c110f7fbd9bcdac8f1530e4437",
        "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
        "mintime": 1792388021,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
        "curtime": 1792388021,
        "bits": "207fffff",
        "height": 433,
        "default_witness_commitment": (
            "6a24aa21a9ede06342e5e7b38603e3e3c32e0b5d9884aafa5c2fa7dc9bb7c5de"
            "d0853e00c035"
        ),
        "mweb": (
            "823171dc8df5d16eed2fa8779a66f385ff72ebd0116b60fff4c6c6a08531e75f"
            "e5fe000000000000000000000000000000000000000000000000000000000000"
            "0000af2edc674154ff129d9e826727ada0828d3ba480924bbed84bf6dcae2e1f"
            "1db2696e82af0eb57986eba891e7ad7e7a2357f45e4dbaa6adbc008b674f39b2"
            "62d0000000000000000000000000000000000000000000000000000000000000"
            "00000200000000"
        ),
    },
    "extranonce1": "00000001",
    "extranonce2": "6c390000",
    "ntime": "6ad5abb5",
    "nonce": "00000000",
    "header_hex": (
        "00000020e430158faccd9bbd7f0f111cf589b3b8817a5661cea076da2dc0c26f"
        "3c34864a83b00dfcbbf631b1d20cad2d1586cec40200d4594a054299662e011b"
        "1c646d9fb5abd56affff7f2000000000"
    ),
    "pow_hash": "2c11847b5701823f27bd5cc47e524ccfea73f1a8ab2dbab5cbcac943881db265",
    "block_hex": (
        "00000020e430158faccd9bbd7f0f111cf589b3b8817a5661cea076da2dc0c26f"
        "3c34864a83b00dfcbbf631b1d20cad2d1586cec40200d4594a054299662e011b"
        "1c646d9fb5abd56affff7f200000000002010000000001010000000000000000"
        "000000000000000000000000000000000000000000000000ffffffff1902b101"
        "000000016c3900002f5075626c6963204d696e65722fffffffff02807c814a00"
        "000000160014d328b4b46cef262169f8d7605498ad5ac5829e55000000000000"
        "0000266a24aa21a9ede06342e5e7b38603e3e3c32e0b5d9884aafa5c2fa7dc9b"
        "b7c5ded0853e00c0350120000000000000000000000000000000000000000000"
        "000000000000000000000000000000020000000008012e00bfb9ca73be63883a"
        "6f7ac4198cb5ec91b0be2a58b51de794993f41f93df40000000000ffffffff01"
        "e666814a0000000022582073a33b967603cd59878457cf1e41abda6b83293fe1"
        "f0ff36c0a11b274b6497fb000000000001823171dc8df5d16eed2fa8779a66f3"
        "85ff72ebd0116b60fff4c6c6a08531e75fe5fe00000000000000000000000000"
        "00000000000000000000000000000000000000af2edc674154ff129d9e826727"
        "ada0828d3ba480924bbed84bf6dcae2e1f1db2696e82af0eb57986eba891e7ad"
        "7e7a2357f45e4dbaa6adbc008b674f39b262d000000000000000000000000000"
        "000000000000000000000000000000000000000200000000"
    ),
    "block_hash": "fcf9751bf77b0313a48634b8e0fa4f69cca5ccfad370f7805e44c7198cd1e83f",
}

PEGIN_TXID = "5a5854b90e2db39db7620d7b8ef4e94cc4e2a038005843f78b20d1132ca88cdf"
