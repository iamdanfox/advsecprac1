var net = require('net');
var crypto = require('crypto');

var SERVER_SECRET = 'I am super secret!';
var PORT = 8125;
var DIFFIE_HELLMAN_PRIME = 'KbhkmZowCP8blHg4RYAP95kaIw=='; // length = 150

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
          var diffieHellman = crypto.createDiffieHellman(DIFFIE_HELLMAN_PRIME, 'base64');
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

  // handle sequence stuff, aborts if necessary
  socket.on('data', function(chunk) {
    console.assert(typeof chunk === 'string');

    var sequenceNumber = parseInt(chunk[0], 10);
    var chunkBody = chunk.slice(1).toString().trim(); // trailing whitespace!
    console.log('received chunk: "' + chunkBody + '"');
    if ( expectedSeqNumber === sequenceNumber) {
      console.log('advanced to expectedSeqNumber ' + expectedSeqNumber + '... responding');

      respond(chunkBody, function(response){
        if (response != null) {
          socket.write(response)
        } else {
          console.log('finishing')
          socket.end()
        }
      }, function(error){
        console.error('[ARBORTING] ' + error);
        socket.end()
      })
    } else {
      console.error('[ABORTING] Invalid chunk. Was expecting sequenceNumber=' + (expectedSeqNumber + 1));
      console.log('Received: "' + chunk + '"');
      socket.end()
    }
  });

  socket.on('end', function() {
    console.log('disconnected');
  });
});

server.listen(PORT, function() {
  console.log('server bound to ' + PORT);
});
