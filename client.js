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
      console.assert(typeof chunkBody === 'string')
      var serverPublicKey = new Buffer(chunkBody, 'base64');
      try {
        diffieHellmanSharedSecret = diffieHellman.computeSecret(serverPublicKey, 'base64');
        console.log('2. computed shared secret: '+diffieHellmanSharedSecret.toString('base64'));
        expectedSeqNumber = expectedSeqNumber + 2;

        // // randomly choose a key
        // crypto.randomBytes(shared.NUM_RANDOM_BYTES, function(ex, buf) {
        //   if (ex) reject(ex)

        //   var randomKey = buf.toString('base64');
        //   var asymmetricBit = shared.asymmetricEncrypt(
        //     shared.CLIENT.PUBLIC_KEY,
        //     CLIENT_SECRET,
        //     diffieHellmanSharedSecret
        //   );
        //   var v = shared.symmetricEncrypt(randomKey, shared.CLIENT.IDENTITY + asymmetricBit);


          return resolve('3A')
        // })
        // return
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

