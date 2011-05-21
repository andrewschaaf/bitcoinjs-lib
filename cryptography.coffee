
SHA256 = require './crypto-js/sha256'
RIPEMD160 = require './crypto-js/ripemd160'

sha256    = (data) -> SHA256(data, {asBytes: true})
ripemd160 = (data) -> RIPEMD160(data, {asBytes: true})

hash160 = (data) -> ripemd160 sha256 data
hash256 = (data) -> sha256 sha256 data


module.exports =
  
  sha256: sha256
  ripemd160: ripemd160
  
  hash160: hash160
  hash256: hash256

