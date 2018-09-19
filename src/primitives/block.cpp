// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>
#include <chainparams.h>
#include <script/standard.h>
#include <pubkey.h>

#include <vector>

typedef std::vector<unsigned char> valtype;

uint256 CBlockHeader::GetHash() const
{
    uint256 thash;
    scryptHash(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u, vchBlockSig=%s)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size(),
        HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

// ppcoin: check block signature
bool CBlock::CheckBlockSignature(bool fProofOfStake) const
{
    bool fTestNet = false; // XXX testnet?
    uint256 hashGenesisBlockTestNet = Params().GetConsensus().hashGenesisBlock;
    uint256 hashGenesisBlock = Params().GetConsensus().hashGenesisBlock;

    if (GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
        return vchBlockSig.empty();

    std::vector<valtype> vSolutions;
    txnouttype whichType;

    if(fProofOfStake)
    { 
        const CTxOut& txout = vtx[1]->vout[1]; 

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;
        if (whichType == TX_PUBKEY)
        {
            valtype& vchPubKey = vSolutions[0];
            CPubKey key(vchPubKey); 
            if (vchBlockSig.empty())
                return false;  
            return key.Verify(GetHash(), vchBlockSig);
        }
    }
    else
    {
        for(unsigned int i = 0; i < vtx[0]->vout.size(); i++)
        {
            const CTxOut& txout = vtx[0]->vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;

            if (whichType == TX_PUBKEY)
            {
                // Verify
                valtype& vchPubKey = vSolutions[0];
                CPubKey key(vchPubKey);
                if (vchBlockSig.empty())
                    continue;
                if(!key.Verify(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    return false;    
}

