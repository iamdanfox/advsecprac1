var crypto = require('crypto');
var fs = require('fs');
var ursa = require('ursa');

var SYMMETRIC_CIPHER = 'aes-256-cbc';
var SYMMETRIC_CIPHER_KEY_LENGTH = 32;
var SYMMETRIC_CIPHER_IV = 16;
console.assert(crypto.getCiphers().indexOf(SYMMETRIC_CIPHER) != -1, 'Cipher must be present in openssl');

var HASH_ALG = 'sha512';
console.assert(crypto.getHashes().indexOf(HASH_ALG) != -1, 'Hash must be present in openssl');

var PADDING_LENGTH = 309; // expands to 412 in base64




module.exports = {

  PORT: 8125,

  DIFFIE_HELLMAN_PRIME: 'KbhkmZowCP8blHg4RYAP95kaIw==', // length = 150

  keyFromRandomBytes: function(randomBytes) {
    console.assert(typeof randomBytes === 'string');
    return crypto.pbkdf2Sync(randomBytes, 'danisgreat#key', Math.pow(10,4), SYMMETRIC_CIPHER_KEY_LENGTH);
  },

  ivFromRandomBytes: function(randomBytes) {
    console.assert(typeof randomBytes === 'string');
    return crypto.pbkdf2Sync(randomBytes, 'danisgreat#iv', Math.pow(10,4), SYMMETRIC_CIPHER_IV);
  },

  paddingFromSharedSecret: function(sharedSecret) {
    console.assert(typeof sharedSecret === 'string');
    iv = crypto.pbkdf2Sync(sharedSecret, 'danissupergreat', Math.pow(10,4), PADDING_LENGTH);
    console.assert(Buffer.isBuffer(iv))
    return iv.toString('base64');
  },

  socketLoop: function(socket, responderFunction, expectedSeqNumber) {

    socket.setEncoding('utf8');

    var abort = function(error) {
      console.error('[ABORTING] ' + error);
      socket.end();
    }

    var write = function(response) {
      if (response != null) {
        console.log('[sending]: "'+response+'"')
        socket.write(response)
      } else {
        socket.end() // clean close
      }
    }

    socket.on('data', function(data) {
      console.log('[received]: "' + data + '"');

      console.assert(typeof data === 'string')
      var sequenceNumber = parseInt(data[0], 10);

      if (expectedSeqNumber() === sequenceNumber) {
        var chunkBody = data.toString().slice(1).trim()
        responderFunction(chunkBody, write, abort)
      } else {
        console.error('[ABORTING] Invalid chunk. Was expecting sequenceNumber=' + (expectedSeqNumber() + 1));
        abort(data)
      }
    });
  },

  // 4096 key size
  // openssl genrsa -out client.pub 4096
  // openssl rsa -pubout -in client.pub -out client.key.pem
  SERVER: {
    IDENTITY: 'Alice',
    PUBLIC_KEY: ursa.createPrivateKey(fs.readFileSync('./server.key.pem')),
    PRIVATE_KEY: ursa.createPublicKey(fs.readFileSync('./server.pub')),
  },

  CLIENT: {
    IDENTITY: 'Bob',
    PUBLIC_KEY: ursa.createPrivateKey(fs.readFileSync('./client.key.pem')),
    PRIVATE_KEY: ursa.createPublicKey(fs.readFileSync('./client.pub')),
  },

  // one way. sharedSecret is used for padding.
  asymmetricEncrypt: function(publicKey, payload, sharedSecret) {
    // compress payload with hash
    hash = crypto.createHash(HASH_ALG);
    hash.update(payload, 'utf8');
    var digest = hash.digest('base64');
    console.assert(digest.length === 88);

    var padding = module.exports.paddingFromSharedSecret(sharedSecret);
    console.assert(padding.length === 412);

    var PADDING_MODE = 2; // interestingly the code for decryption is 1, not 2
    return publicKey.encrypt(digest + padding + ' ', 'utf8', 'base64', PADDING_MODE);
  },

  NUM_RANDOM_BYTES: 32,

  symmetricEncrypt: function(randomKey, contents) {
    var key = module.exports.keyFromRandomBytes(randomKey);
    var iv = module.exports.ivFromRandomBytes(randomKey);
    var cipher = crypto.createCipheriv(SYMMETRIC_CIPHER, key, iv);

    var f = Buffer.concat([
        cipher.update('DAN IS GREAT fjaHFJ AHF HJKDFH KJFHJK HSDKHF !!!!!'),
        cipher.final()
    ]);
    return f.toString('base64')
  },

  symmetricDecrypt: function(randomKey, base64CipherText) {
    var key = module.exports.keyFromRandomBytes(randomKey);
    var iv = module.exports.ivFromRandomBytes(randomKey);
    var decipher = crypto.createDecipheriv(SYMMETRIC_CIPHER, key, iv);

    var d = Buffer.concat([
      decipher.update(base64CipherText, 'base64'),
      decipher.final()
    ]);
    return d.toString('utf8');
  }

}





