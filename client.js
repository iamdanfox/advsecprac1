var net = require('net');
var crypto = require('crypto');
var shared = require('./shared.js');

var CLIENT_SECRET = 'I am super secret!';


var expectedSeqNumber = 0;

var diffieHellman = crypto.createDiffieHellman(shared.DIFFIE_HELLMAN_PRIME, 'base64');
var diffieHellmanSharedSecret;
var randomKey;

var respond = function(chunkBody, resolve, reject) {
  switch (expectedSeqNumber) {
    case 0:
      diffieHellman.generateKeys()
      expectedSeqNumber = expectedSeqNumber + 2;
      return resolve('1' + diffieHellman.getPublicKey('base64'));
      break;
    case 2:
      console.assert(typeof chunkBody === 'string', 'chunkBody must be a string')
      var serverPublicKey = new Buffer(chunkBody, 'base64');
      try {
        diffieHellmanSharedSecret = diffieHellman.computeSecret(serverPublicKey, 'base64').toString('base64');
        console.log('2. computed shared secret: '+diffieHellmanSharedSecret);

        // randomly choose a key
        crypto.randomBytes(shared.NUM_RANDOM_BYTES, function(ex, buf) {
          if (ex) return reject(ex)

          randomKey = buf.toString('base64');
          var asymmetricBit = shared.asymmetricEncrypt(
            shared.CLIENT.PUBLIC_KEY,
            CLIENT_SECRET,
            diffieHellmanSharedSecret
          );
          var v = shared.symmetricEncrypt(randomKey, shared.CLIENT.IDENTITY + asymmetricBit);

          expectedSeqNumber = expectedSeqNumber + 2;
          return resolve('3' + v);
        });
        return
      } catch (error) {
        reject(error)
      }
      break;
  }
}


var socket = net.connect({ port: shared.PORT }, function() {
  respond(null, socket.write.bind(this), null);
});

shared.socketLoop(socket, respond, function() {
  return expectedSeqNumber;
});
