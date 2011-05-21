
  // BigInteger monkey patching
  BigInteger.valueOf = nbv;
  BigInteger.prototype.toByteArrayUnsigned = function () {
    var ba = this.toByteArray();
    if (ba.length) {
      if (ba[0] == 0) {
        ba = ba.slice(1);
      }
      return ba.map(function (v) {
        return (v < 0) ? v + 256 : v;
      });
    } else {
      // Empty array, nothing to do
      return ba;
    }
  };
  BigInteger.fromByteArrayUnsigned = function (ba) {
    if (!ba.length) {
      return ba.valueOf(0);
    } else if (ba[0] & 0x80) {
      // Prepend a zero so the BigInteger class doesn't mistake this
      // for a negative integer.
      return new BigInteger([0].concat(ba));
    } else {
      return new BigInteger(ba);
    }
  };

  return {
    BigInteger: BigInteger,
    ECDSA: ECDSA,
    ecparams: getSECCurveByName('secp256k1'),
    rng: new SecureRandom()
  };
})();

