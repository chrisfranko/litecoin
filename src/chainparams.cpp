// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
                ( 0, uint256("0x19225ae90d538561217b5949e98ca4964ac91af39090d1a4407c892293e4f44f"))
                ( 10, uint256("0xb98fe58aa04ca9a5a216c0bd01d952e0fff16e702d0fb512f748f201b9be26fb"))
                ( 100, uint256("0x56b00c7d17fd10680dfafa0617f26af75f6c2b0c11aafa9cf1b6704de2766f72"))
                ( 1000, uint256("0x076d62aef68a8330e5f927cdbc23d58ac1e2838877936512aa16487f098d35ca"))
                ( 5000, uint256("0x5b7fc427fa913510186e034e1415bdf987d37f4674c2f2fd0b492836fc58de0d"))
                ( 10000, uint256("0xd4bf99505611f97b6cf6f273a79c21c1b21b03238b06396e2e9a02f83c13d01c"))
                ( 27000, uint256("0x397e50d20f9a21f274b8787fa66ca1ebc208a1b7e5bc3a9a0e352350bd42e125"))
                ( 27650, uint256("0xb2a25b57648bf10a81dcc3b23fb758bceb6f652d121bd44b2f3c7da3fd0f0cef"))
                ( 29040, uint256("0x34b4dbe94b3e1bc0f6b199ee722a9fbbb52315ae53dd37cbc949fbc84aa3c6fe"))
                ( 48080, uint256("0x08f789323bf5d116575c5749fa617696f88d0179faac534647abb5065abbaddf"))
                ( 60000, uint256("0x046ca133f715de3f8d83965487002c9cc1cebe4bb0fc10a1155fc9a6d2767293b"))
                ( 70000, uint256("0x01ad0aa03e8888cef8381aeea5ca679602bbb32e8245e9cd36abce77cda936bfb"))
                ( 80000, uint256("0x03a508431391d8203d4dd8fde8ffc529c26923cc8da9f2e64342441bb7afa940c"))
                ( 90000, uint256("0x08571865fb72beddf95872cbe3490aeb2b7558c7810b0a4aef9d581e249ef9d98"))
                ( 216802, uint256("0x0c946c4bdb51a240a103059f69112f301995e3a293044d3a4eff8d4c95cb0a5e1"))
                ( 219638, uint256("0x035fcdaff88c5b989895047f2be66948618feec9ceefaa947341c4f58c55d9362"))
                ( 323288, uint256("0x089a2340f2715a4bede40ce7f095a8d841df7a18c46f76c21c312b31cee2c7a8d"))
                ( 402360, uint256("0x014a96abb528216321b91ac3f29918b60e9292d5cada7a047fcaeb6177c93fbe6"))
                ( 402376, uint256("0x041f33e89e8369d88e1a516a4860fb0c1b4b8b5037f28388a9fd062e4966258f6"))
                ( 472665, uint256("0x07b532f4e96384b2de42f73803572ae5a2bfbecf19462cf2c9f754e7421498ba0"))
                ( 605904, uint256("0x97a0618b8971a7627eb30f3346245af28fe43e32af117b915132b8c0efb1c1f9"))
                ( 785863, uint256("0x9ea053de310cc64a14c9b48849f9ed1e5b5898b30696f3d935b40047feb2306b"))
                ( 785950, uint256("0x1ea42eb64c0a5027549e58d2b532e4fe5da6c901b723fd2ae2d4b7263807e8da"))
                ( 786082, uint256("0x980e5394dee86c2d12572cff87d74b260e2e37c2ef321118cf5a7b68f15188ea"))
                ( 805345, uint256("0xa35e590108bb87970c748ea4f39bc700fc1adf3e0cfea28317f6f7236beeebb3"))
                ( 1699200, uint256("0xc787b18ca8949323efe905e0919751ba31182bb737c5ebe75c89b15317cea0eb"))
                ( 1713100, uint256("0x09b94c703c53663d4e943e67cb032bd92de2c667f0a738e5838156f9651627a4"))
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1432125800, // * UNIX timestamp of last checkpoint block
        1978824,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        5500.0     // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 546, uint256("0xa0fea99a6897f531600c8ae53367b126824fd6a847b2b2b73817a95b8e27e602"))
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1365458829,
        547,
        576
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xde;
        pchMessageStart[1] = 0xfa;
        pchMessageStart[2] = 0xce;
        pchMessageStart[3] = 0xed;
        vAlertPubKey = ParseHex("04d4da7a5dae4db797d9b0644d57a5cd50e05a70f36091cd62e2fc41c98ded06340be5a43a35e185690cd9cde5d72da8f6d065b499b06f51dcfba14aad859f443a");
        nDefaultPort = 4561;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        nSubsidyHalvingInterval = 22471626;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 0.25 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 30; // 2.5 minutes

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         * 
         * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
         *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
         *   vMerkleTree: 4a5e1e
         */
        const char* pszTimestamp = "Optimized More for GPU by Christopher Franko";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1396615615;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 1390771;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0xee960feb663ca4231c851e0ef84205ec068a5efec38bcff39d83a6b637039449"));
        assert(genesis.hashMerkleRoot == uint256("0xb82a06c6261cb11ad8332da805bcc356bf120ffecb94a2dd9e7f2c7ebecdf930"));

        vSeeds.push_back(CDNSSeedData("dirtydiggers.org", "www.dirtydiggers.org"));
        vSeeds.push_back(CDNSSeedData("magicinternetmoney.org", "seed.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("2.magicinternetmoney.org", "seed2.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("3.magicinternetmoney.org", "seed3.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("4.magicinternetmoney.org", "seed4.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("5.magicinternetmoney.org", "seed5.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("6.magicinternetmoney.org", "seed6.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("7.magicinternetmoney.org", "seed7.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("8.magicinternetmoney.org", "seed8.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("9.magicinternetmoney.org", "seed9.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("10.magicinternetmoney.org", "seed10.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("11.magicinternetmoney.org", "seed11.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("12.magicinternetmoney.org", "seed12.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("13.magicinternetmoney.org", "seed13.magicinternetmoney.org"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(35);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5);
        base58Prefixes[SECRET_KEY] =     list_of(163);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Aiden: Mainnet v2 enforced as of block 710k
        nEnforceV2AfterHeight = 1200000;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        vAlertPubKey = ParseHex("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
        nDefaultPort = 4556;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 2.5 * 60; // 2.5 minutes

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime    = 1396616971;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 103293;
        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x9b37e368684f25a05a440287990bd53f9d1be3cced840d2052c2533d764a03d6"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("magicinternetmoney.org", "testnet-seed.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("2.magicinternetmoney.org", "testnet-seed2.magicinternetmoney.org"));
        vSeeds.push_back(CDNSSeedData("3.magicinternetmoney.org", "testnet-seed3.magicinternetmoney.org"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(113);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        // Aiden: Testnet v2 enforced as of block 400k
        nEnforceV2AfterHeight = -1;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xcc;
        pchMessageStart[3] = 0xdd;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime    = 1422288163;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 181887;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";

        assert(hashGenesisBlock == uint256("0x8974140c0959d36496fd28c4d64d2d13c310cd637dae01c6f581b2a7208a2d1f"));
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Aiden: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        // Aiden: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
