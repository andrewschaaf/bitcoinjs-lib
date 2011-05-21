
{BigInteger} = require './jsbn/combined'


ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE = BigInteger.valueOf(58)

base58_encode = (input) ->
  bi = BigInteger.fromByteArrayUnsigned input
  chars = [];
  while bi.compareTo(BASE) >= 0
    mod = bi.mod BASE
    chars.unshift ALPHABET.charAt mod.intValue()
    bi = bi.subtract(mod).divide BASE
  chars.unshift ALPHABET.charAt bi.intValue()
  # Convert leading zeros too.
  for i in [0...input.length]
    if input[i] == 0x00
      chars.unshift ALPHABET.charAt 0
    else
      break
  chars.join ''


base58_decode = (input, resultSize = 25) ->
  bi = BigInteger.valueOf 0
  leadingZerosNum = 0
  for i in [(input.length - 1)..0]
    alphaIndex = ALPHABET.indexOf input.charAt i
    bi = bi.add(BigInteger.valueOf(alphaIndex).multiply(BASE.pow(input.length - 1 -i)))
  bytes = bi.toByteArrayUnsigned();
  for i in [0...(resultSize - bytes.length)]
    bytes.unshift 0
  bytes


module.exports =
  base58_encode: base58_encode
  base58_decode: base58_decode
