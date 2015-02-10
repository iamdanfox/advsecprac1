var net = require('net');
var crypto = require('crypto');
var shared = require('./shared.js');

var SERVER_SECRET = 'I am super secret!';


var server = net.createServer(function(socket) { //'connection' listener
  console.log('client connected');
  socket.setEncoding('utf8');

  var expectedSeqNumber = 1;

  var diffieHellmanSharedSecret;
  var receivedV;
  var randomKey;

  // should resolve with data to send to client.
  // `this` is the client's data
  // just received a chunk with seq no === `expectedSequenceNumber``
  // resolve with null to close cleanly.
  var respond = function(chunkBody, resolve, reject) {
    console.assert(typeof chunkBody === 'string')
    switch(expectedSeqNumber) {
      case 1:
        clientDiffieHellmanKey = new Buffer(chunkBody, 'base64');

        try {
          var diffieHellman = crypto.createDiffieHellman(shared.DIFFIE_HELLMAN_PRIME, 'base64');
          diffieHellman.generateKeys();

          diffieHellmanSharedSecret = diffieHellman.computeSecret(clientDiffieHellmanKey, 'base64').toString('base64');
          console.log('1. computed shared secret: ' + diffieHellmanSharedSecret.toString('base64'));

          expectedSeqNumber = expectedSeqNumber + 2;
          return resolve('2' + diffieHellman.getPublicKey('base64'));
        } catch (err) {
          // gettings loads of 'Error: Supplied key is too large'
          return reject(err)
        }
        break;
      case 3:
        receivedV = chunkBody;

        // randomly choose a key for the response
        crypto.randomBytes(shared.NUM_RANDOM_BYTES, function(ex, randomBuf) {
          if (ex) return reject(ex)

          randomKey = randomBuf.toString('base64');
          var asymmetricBit = shared.asymmetricEncrypt(
            shared.SERVER.PUBLIC_KEY,
            SERVER_SECRET,
            diffieHellmanSharedSecret
          );
          var v = shared.symmetricEncrypt(randomKey, shared.SERVER.IDENTITY + asymmetricBit);

          expectedSeqNumber = expectedSeqNumber + 2;
          return resolve('4' + v);
        });

        break;
      case 5:
        // receive the other's random key, perform the checks, send back my random key
        var othersRandomKey = chunkBody;

        // perform the checks (ie decrypt and check identity)
        var decryptedV = shared.symmetricDecrypt(othersRandomKey, receivedV);
        if (decryptedV.indexOf(shared.CLIENT.IDENTITY) !== -1) {
          // correctly formatted
          var theirRSAPart = decryptedV.substr(shared.CLIENT.IDENTITY.length);
          var compareRSAPart = shared.asymmetricEncrypt(
            shared.CLIENT.PUBLIC_KEY,
            SERVER_SECRET,
            diffieHellmanSharedSecret
          );

          if (theirRSAPart === compareRSAPart) {
            console.log('\n\n[PROTOCOL FINISHED]: same secrets');
          } else {
            console.log('\n\n[PROTOCOL FINISHED]: different secrets');
          }
          expectedSeqNumber = expectedSeqNumber + 2;
          return resolve('6' + randomKey);
        } else {
          expectedSeqNumber = null;
          console.log('[ABORTING PROTOCOL]: dishonesty suspected');
          return reject('Expected decryptedV to start with ' + shared.CLIENT.IDENTITY +
            ' instead, it started with ' + decryptedV.substr(0, shared.CLIENT.IDENTITY.length));
        }
        break;
    }
  };


  shared.socketLoop(socket, respond, function() {
    return expectedSeqNumber;
  });

  socket.on('end', function() {
    console.log('disconnected');
  });
});

server.listen(shared.PORT, function() {
  console.log('server bound to ' + shared.PORT);
});
