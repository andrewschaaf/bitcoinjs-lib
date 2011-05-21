
{ripemd160, sha256, hash160, hash256} = require './../cryptography'
{address_to_hash160, hash160_to_address} = require './../address'
{base58_encode, base58_decode} = require './../base58'


benchmap = (name, arr, f) ->
  t0 = new Date().getTime()
  
  for x in arr
    f(x)
  
  duration = new Date().getTime() - t0
  
  us = Math.round((duration / arr.length) * 1000)
  
  console.log " #{name}: #{us} microseconds"


hashes = for i in [0...256]
  [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, i]

hashes58 = (base58_encode(x) for x in hashes)
addresses = (hash160_to_address(x) for x in hashes)

benchmap 'base58_encode', hashes, base58_encode
benchmap 'base58_decode', hashes58, base58_encode
benchmap 'hash160_to_address', hashes, hash160_to_address
benchmap 'address_to_hash160', addresses, address_to_hash160

