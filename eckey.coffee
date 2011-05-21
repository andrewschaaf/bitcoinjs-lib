
{hash160} = require './cryptography'
{BigInteger, ECDSA, ecparams, rng} = reqiure './jsbn/combined'
{hex_encode, base64_encode, base64_decode} = require './crypto-js/crypto'


make_priv = () ->
  n = ecparams.getN()
  n1 = n.subtract BigInteger.ONE
  r = new BigInteger n.bitLength(), rng
  r.mod(n1).add BigInteger.ONE


pubPoint_from_priv = (priv) ->
  ecparams.getG().multiply priv

pub_from_priv = (priv) ->
  pubPoint_from_priv(priv).getEncoded()


class ECKey
  
  constructor: (input) ->
    @priv = if not input
      ECDSA.getBigRandom ecparams.getN()
    else if input instanceof BigInteger
      input
    else if Bitcoin.Util.isArray input
      BigInteger.fromByteArrayUnsigned input
    else if (typeof input) == "string"
      BigInteger.fromByteArrayUnsigned base64_decode input
  
  getPub: () ->
    if not @pub
      @pub = pub_from_priv @priv
    @pub
  
  getPubKeyHash: () ->
    if not @pubKeyHash
      @pubKeyHash = hash160 @getPub()
    @pubKeyHash
  
  getBitcoinAddress: () ->
    new Bitcoin.Address @getPubKeyHash()
  
  toString: (format) ->
    if format == 'base64'
      base64_encode @priv.toByteArrayUnsigned()
    else
      hex_encode @priv.toByteArrayUnsigned()
  
  sign: (hash) ->
    ECDSA.sign hash, @priv
  
  verify: (hash, sig) ->
    ECDSA.verify hash, sig, @getPub()

