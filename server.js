var net = require('net');
var crypto = require('crypto');
var shared = require('./shared.js');

var SERVER_SECRET = 'I am super secret!';


var server = net.createServer(function(socket) { //'connection' listener
  console.log('client connected');
  socket.setEncoding('utf8');

  /* Expected server (B) flow:

    1. receive client's diffe hellman public key
      2. create server's diffie hellman, send public key, compute shared secret
    3. receive client's VA
      4. choose Kb, send VB
    5. receive Ka...
      - if not honest - abort
      - if honest
        - if Wa matches server's secret
          6. send kb
          - return true
        - else
          6. send kb
          - return false

  */

  var expectedSeqNumber = 1;

  var diffieHellmanSharedSecret;

  // should resolve with data to send to client.
  // `this` is the client's data
  // just received a chunk with seq no === `expectedSequenceNumber``
  // resolve with null to close cleanly.
  var respond = function(body, resolve, reject) {
    console.assert(typeof body === 'string')
    switch(expectedSeqNumber) {
      case 1:
        clientDiffieHellmanKey = new Buffer(body, 'base64');

        try {
          var diffieHellman = crypto.createDiffieHellman(shared.DIFFIE_HELLMAN_PRIME, 'base64');
          diffieHellman.generateKeys();

          diffieHellmanSharedSecret = diffieHellman.computeSecret(clientDiffieHellmanKey, 'base64');
          console.log('1. computed shared secret: ' + diffieHellmanSharedSecret.toString('base64'));

          expectedSeqNumber = expectedSeqNumber + 2;
          return resolve('2' + diffieHellman.getPublicKey('base64'));
        } catch (err) {
          // gettings loads of 'Error: Supplied key is too large'
          return reject(err)
        }
        break;
      case 3:


        expectedSeqNumber = expectedSeqNumber + 2;
        resolve('4SEND 5');
        break;
      case 5:
        expectedSeqNumber = null;
        resolve();
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
