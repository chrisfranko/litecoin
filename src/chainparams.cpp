// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xde;
        pchMessageStart[1] = 0xfa;
        pchMessageStart[2] = 0xce;
        pchMessageStart[3] = 0xed;
        vAlertPubKey = ParseHex("04d4da7a5dae4db797d9b0644d57a5cd50e05a70f36091cd62e2fc41c98ded06340be5a43a35e185690cd9cde5d72da8f6d065b499b06f51dcfba14aad859f443a");
        nDefaultPort = 4561; // M.I.M (Aiden) ^_^
        nRPCPort = 4562;
		bnProofOfWorkLimit[ALGO_SHA256D] = CBigNum(~uint256(0) >> 32);
		bnProofOfWorkLimit[ALGO_SCRYPT_OG] = CBigNum(~uint256(0) >> 20);
		bnProofOfWorkLimit[ALGO_SCRYPT] = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_BLAKE] = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_SKEIN] = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_QUBIT]  = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_X11] = CBigNum(~uint256(0) >> 20);
        //nSubsidyHalvingInterval = 210000;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        const char* pszTimestamp = "Optimized More for GPU by Christopher Franko";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
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

        vSeeds.push_back(CDNSSeedData("seed1.aidencoin.org", "seed1.aidencoin.org"));
        vSeeds.push_back(CDNSSeedData("seed2.aidencoin.org", "seed2.aidencoin.org"));
        vSeeds.push_back(CDNSSeedData("seed3.aidencoin.org", "seed3.aidencoin.org"));
        vSeeds.push_back(CDNSSeedData("seed4.aidencoin.org", "seed4.aidencoin.org"));
        vSeeds.push_back(CDNSSeedData("seed5.aidencoin.org", "seed5.aidencoin.org"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(48);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5);
        base58Prefixes[SECRET_KEY] =     list_of(176);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xc6;
        pchMessageStart[1] = 0xab;
        pchMessageStart[2] = 0xc7;
        pchMessageStart[3] = 0x9d;
        vAlertPubKey = ParseHex("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
        nDefaultPort = 60603;
        nRPCPort = 60604;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime    = 1396616971;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 103293;
        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x9b37e368684f25a05a440287990bd53f9d1be3cced840d2052c2533d764a03d6"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testseed1.aiden.info", "testseed1.aiden.info"));
        vSeeds.push_back(CDNSSeedData("testseed2.aiden.info", "testseed2.aiden.info"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(130);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(192);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xc7;
        pchMessageStart[1] = 0xab;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0x9d;
//        nSubsidyHalvingInterval = 150;
		bnProofOfWorkLimit[ALGO_SHA256D] = CBigNum(~uint256(0) >> 1);
		bnProofOfWorkLimit[ALGO_SCRYPT_OG] = CBigNum(~uint256(0) >> 1);
		bnProofOfWorkLimit[ALGO_SCRYPT] = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_BLAKE] = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_SKEIN] = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_QUBIT]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_X11] = CBigNum(~uint256(0) >> 1);
        genesis.nTime    = 1422288163;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 181887;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";
	
        assert(hashGenesisBlock == uint256("0x8974140c0959d36496fd28c4d64d2d13c310cd637dae01c6f581b2a7208a2d1f"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}