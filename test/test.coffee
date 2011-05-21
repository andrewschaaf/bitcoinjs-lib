
assert = require 'assert'
eq = (x, y) -> assert.equal JSON.stringify(x), JSON.stringify(y)

SHA256 = require './../crypto-js/sha256'
RIPEMD160 = require './../crypto-js/ripemd160'

{Crypto, hex_decode} = require './../crypto-js/crypto'
{ripemd160, sha256, hash160, hash256} = require './../cryptography'


#### Crypto

# console.log(require('crypto').createHash('ripemd160').update(new Buffer([1, 2, 3])).digest('hex'));
bytes = [1, 2, 3]
eq sha256(bytes), hex_decode("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81")
eq ripemd160(bytes), hex_decode("79f901da2609f020adadbf2e5f68a16c8c3f7d57")
eq hash160(bytes), ripemd160(sha256(bytes))
eq hash256(bytes), sha256(sha256(bytes))






console.log "OK"
