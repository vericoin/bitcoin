// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0,       hashGenesisBlock )
        ( 2700,    uint256("0x52f0119bd2252422ea4aebb25273a98155972cf25a6ef267a7ef35103b5466c3") )
        ( 5700,    uint256("0x000000001c3865f29140f49217c99ad985e80e89ca4d1e6a518a47f6961d6f16") )
        ( 10080,   uint256("0x00000000023212158c4a50727711ffc9ddbcb246e7c34e8a6668c49aad3b5390") )
        ( 16346,   uint256("0x0000000002963467ff7c61f53f2a141819e8dcd04b5320e1e78f50d52e4d312e") )
        ( 24533,   uint256("0xccec1c9940fcc78e95ecb75213469a8220280e23bab4976d2132e0b5513798cb") )
        ( 26196,   uint256("0x84d6eac78587fad5c11a0475ee6085bbff505e3d3be78734c6be2908c5154849") )
        ( 27159,   uint256("0x9bad4fb0cdc3a774981d53eef6fda7fb3fe720b2f847dbb9b6eafba72f535571") )
        ( 107670,  uint256("0xcbe5acc625d669c603943daa26e7bac3fcacb8f95d4a8fa2b00092ad22407a1a") )
        ( 107671,  uint256("0x61d59bbc7cbced427d0c4c6d779c1a7ad327bf788890b2cf4d3e2abdf11979e6") )
        ( 107672,  uint256("0x704197d86f68ec75a3a15e32ad6dc1a956400671a88eb2926e9bb78136cc8e0b") )
        ( 107699,  uint256("0xd4f67d88408ce3c268dc35478b10821f0bb787a7d131bdb57e94bd5c1b02078d") )
        ( 107700,  uint256("0x426cf03d395d0578d943a16e2dade3ae791d3d8759395fea99a98db62a778037") )
        ( 107720,  uint256("0x32d622ffeac54b872a04fb18df90807cb11e28452597acd410237ee05c89fb45") )
        ( 107738,  uint256("0xf0d742fd0a1aeaadf432f8af19276d5ecbb07a0706284d6cc0a70fb270a3d697") )
        ( 130932,  uint256("0xdced5f5ee627cb8af12c3439eb7e7f049f83235459377bf5981e8b906e1a945f") )
        ( 137725,  uint256("0xce241207536b7eada68b247edcfc1240e46dbf216385f102ade02645be07f6ef") )
        ( 239355,  uint256("0xe662449e6b86f473777749add48c2b6d33900227d4c283a9366d845a4dd92a71") )
        ( 239526,  uint256("0x4d07e6a7b3b1fda725d1e113eb2f04b188286a053b04833431ee81373de1ff58") )
        ( 241527,  uint256("0x80afc89cbee28cfc516b9c88c9d74446caa9a284bdcbe4e1655abd911044ac71") )
        ( 242108,  uint256("0x5fd020de15dff256b9136b9c874d11e2db25d960a546606c8d936afcefd2516a") )
        ( 295000,  uint256("0xc441ac33032db312b6fd7e62fe9774ad4f9d8d23c61c2047734b71667319999c") )
        ( 914000,  uint256("0xdeb31aa6af3b8d4e370faab196bbc8701146b900b93102ef432b23cd1d23dcb6") )
        ( 1417780, uint256("0xa5a4ae40a0f1c0a3517dc5e2e60a3020247c0f9878b40720099477609635a652") )
        ( 1417877, uint256("0x3c509ffd917975972001651a1cf666bb18112d9e31e4f484c2b2d922779e0755") )
        ( 1418062, uint256("0xf529c1f076221cc45e6c1f2003f4e1813330587597184444b43cc74042d241eb") )
        ( 1600000, uint256("0x2e7bf9adde16b33f852427b59c929b19994290e3e572d61938fed2a7cecb8bc5") )
        ( 1700000, uint256("0x54a39e165646195994a039f3b17f27363efbe074ea5816de81bd9d944f664c37") )
        ( 1745415, uint256("0x6980d7f2744c201db8a3383bc8014133e5af41529dd222dabb1a551b545d7da3") )
        ( 1751415, uint256("0xccb1350009a6e2bfa684f7461b455cc75db19b30e55f612d4b17b0fcee6585e9") )
        ( 2000000, uint256("0x5360959829df0cc297074df5b3083d9d671a34dbf709d835d1f913fcb3cb7318") )
        ( 4025153, uint256("0xd393a326a29747ad196537e5ef336eb8224013e21f440f90d495307937e13d3c") )



    ;

    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, hashGenesisBlockTestNet )
        ;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
        // return true;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        return checkpoints.rbegin()->first;
        // return 0;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
                // return NULL;
        }
        return NULL;
    }

    // Automatically select a suitable sync-checkpoint 
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && pindex->nHeight + nCoinbaseMaturity > pindexBest->nHeight)
            pindex = pindex->pprev;
        return pindex;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();
        if (nHeight <= pindexSync->nHeight)
            return false;
        return true;
    }
}
