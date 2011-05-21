
{hash256} = require './cryptography'
{base58_encode, base58_decode} = require './base58'
{base64_encode} = require './crypto-js/crypto'


address_to_hash160 = (string) ->
  
  bytes = base58_decode string
  hash = bytes.slice 0, 21
  
  checksum = hash256 hash
  if (checksum[0] != bytes[21] or
      checksum[1] != bytes[22] or
      checksum[2] != bytes[23] or
      checksum[3] != bytes[24])
    throw "Checksum validation failed!"
  
  version = hash.shift()
  if version != 0
    throw "Version #{version} not supported!";
  
  hash


hash160_to_address = (bytes) ->
  hash = bytes.slice 0
  hash.unshift 0 # version
  checksum = hash256(hash).slice 0, 4
  bytes = hash.concat checksum
  base58_encode bytes


class Address

  constructor: (bytes) ->
    if (typeof bytes) == "string"
      bytes = address_to_hash160 bytes
    @hash = bytes;
    @version = 0x00

  toString: () ->
    hash160_to_address @hash

  getHashBase64: () ->
    base64_encode @hash


module.exports =
  Address: Address
  address_to_hash160: address_to_hash160
  hash160_to_address: hash160_to_address

