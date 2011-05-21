
assert = require 'assert'
eq = (x, y) -> assert.equal JSON.stringify(x), JSON.stringify(y)

SHA256 = require './../crypto-js/sha256'
RIPEMD160 = require './../crypto-js/ripemd160'
{Crypto, hex_decode} = require './../crypto-js/crypto'

{ripemd160, sha256, hash160, hash256} = require './../cryptography'
{Address, address_to_hash160} = require './../address'
{base58_encode, base58_decode} = require './../base58'


#### Crypto

# console.log(require('crypto').createHash('ripemd160').update(new Buffer([1, 2, 3])).digest('hex'));
bytes = [1, 2, 3]
eq sha256(bytes), hex_decode("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81")
eq ripemd160(bytes), hex_decode("79f901da2609f020adadbf2e5f68a16c8c3f7d57")
eq hash160(bytes), ripemd160(sha256(bytes))
eq hash256(bytes), sha256(sha256(bytes))


#### Base58

data = hex_decode "005cc87f4a3fdfe3a2346b6953267ca867282630d3f9b78e64"
data58 = "19TbMSWwHvnxAKy12iNm3KdbGfzfaMFViT"

eq base58_encode(data), data58
eq base58_decode(data58), data


#### Addresses

hash = hex_decode "5cc87f4a3fdfe3a2346b6953267ca867282630d3"
address = "19TbMSWwHvnxAKy12iNm3KdbGfzfaMFViT"

eq address_to_hash160(address), hash
eq hash160_to_address(hash), address




console.log "OK"
