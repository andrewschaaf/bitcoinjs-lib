
{Opcode, map} = require './opcode'
{base64_decode} = require './crypto-js/crypto'
{hash160} = require './cryptography'
{isArray} = require './util'


# Make opcodes available as pseudo-constants
for own name, code of map
  eval "var #{name} = #{code};"


class Script

  constructor: (data) ->
    @buffer = if not data
      []
    else if (typeof data) == "string"
      base64_decode data
    else if Bitcoin.Util.isArray data
      data
    else if data instanceof Script
      data.buffer;
    else
      throw new Error "Invalid script"
    @parse()

  parse: () ->
    self = this
    @chunks = []

    # Cursor
    i = 0

    # Read n bytes and store result as a chunk
    readChunk = (n) ->
      @chunks.push @buffer.slice(i, i + n)
      i += n

    while i < @buffer.length

      opcode = @buffer[i++]

      # Two byte opcode?
      if opcode >= 0xF0
        opcode = (opcode << 8) | this.buffer[i++];

      if 0 < opcode < OP_PUSHDATA1
        # Read some bytes of data, opcode value is the length of data
        readChunk opcode
      else if opcode == OP_PUSHDATA1
        len = @buffer[i++]
        readChunk len

      else if opcode == OP_PUSHDATA2
        len = (@buffer[i++] << 8) | @buffer[i++]
        readChunk len
      else if opcode == OP_PUSHDATA4
        len = ((@buffer[i++] << 24) |
               (@buffer[i++] << 16) |
               (@buffer[i++] << 8)  |
                @buffer[i++])
        readChunk len
      else
        @chunks.push opcode

  getOutType: () ->
    # Transfer to Bitcoin address
    if (  @chunks.length == 5 and
          @chunks[0] == OP_DUP and
          @chunks[1] == OP_HASH160 and
          @chunks[3] == OP_EQUALVERIFY and
          @chunks[4] == OP_CHECKSIG)
      'Address'
    # Transfer to IP address
    else if @chunks.length == 2 and chunks[1] == OP_CHECKSIG
      'Pubkey'
    else
      'Strange'

  simpleOutPubKeyHash: () ->
    type = @getOutType()
    if type == 'Address'
      return @chunks[2]
    else if type == 'Pubkey'
      return hash160 @chunks[0]
    throw new Error "Encountered non-standard scriptPubKey"

  getInType: () ->
    
    # Direct IP to IP transactions only have the public key in their scriptSig.
    if @chunks.length == 1
      return 'Pubkey'
    
    else if ( @chunks.length == 2 and
              isArray(@chunks[0]) and
              isArray(@chunks[1]))
      return 'Address'
    else
      console.log @chunks
      throw new Error "Encountered non-standard scriptSig"

  simpleInPubKey: () ->
    type = @getInType()
    if type == 'Address'
      return @chunks[1]
    else if type == 'Pubkey'
      return chunks[0]
    else
      throw new Error "Encountered non-standard scriptSig"

  simpleInPubKeyHash: () ->
    hash160 @simpleInPubKey()

  writeOp: (opcode) ->
    @buffer.push opcode
    @chunks.push opcode

  writeBytes: (data) ->
    if data.length < OP_PUSHDATA1
      @buffer.push data.length
    else if data.length <= 0xff
      @buffer.push OP_PUSHDATA1
      @buffer.push data.length
    else if data.length <= 0xffff
      @buffer.push OP_PUSHDATA2
      @buffer.push data.length & 0xff
      @buffer.push (data.length >>> 8) & 0xff
    else
      @buffer.push OP_PUSHDATA4
      @buffer.push data.length & 0xff
      @buffer.push (data.length >>> 8) & 0xff
      @buffer.push (data.length >>> 16) & 0xff
      @buffer.push (data.length >>> 24) & 0xff
    @buffer = @buffer.concat data
    @chunks.push data

  createOutputScript: (address) ->
    script = new Script()
    script.writeOp      OP_DUP
    script.writeOp      OP_HASH160
    script.writeBytes   address.hash
    script.writeOp      OP_EQUALVERIFY
    script.writeOp      OP_CHECKSIG
    script

  createInputScript: (signature, pubKey) ->
    script = new Script()
    script.writeBytes signature
    script.writeBytes pubKey
    script

  clone: () ->
    new Script @buffer

