var crypto = require('crypto');

var SYMMETRIC_KEY_LENGTH = 128;
var RSA_IV_LENGTH = 128;
var SYMMETRIC_CIPHER = 'aes-128-cbc';
console.assert(crypto.getCiphers().indexOf(SYMMETRIC_CIPHER) != -1, 'Cipher must be present in openssl');

// RSA_PKCS1_PADDING has no randomness
// https://github.com/davedoesdev/ursa implements this



module.exports = {

  PORT: 8125,

  DIFFIE_HELLMAN_PRIME: 'KbhkmZowCP8blHg4RYAP95kaIw==', // length = 150

  // returns a binary buffer!
  keyFromSharedSecret: function(sharedSecret) {
    console.assert(typeof sharedSecret === 'string');
    return crypto.pbkdf2Sync(sharedSecret, 'danisgreat', Math.pow(10,4), SYMMETRIC_KEY_LENGTH);
  },

  // returns a binary buffer!
  ivFromSharedSecret: function(sharedSecret) {
    console.assert(typeof sharedSecret === 'string');
    iv = crypto.pbkdf2Sync(sharedSecret, 'danissupergreat', Math.pow(10,4), IV_LENGTH);
    console.assert(Buffer.isBuffer(iv))
    return iv;
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
  }
}
