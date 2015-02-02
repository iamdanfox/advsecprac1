var net = require('net');
var crypto = require('crypto');

var CLIENT_SECRET = 'I am super secret!';
var PORT = 8125;
var DIFFIE_HELLMAN_PRIME = 'KbhkmZowCP8blHg4RYAP95kaIw=='; // length = 150



var expectedSeqNumber = 0;

var diffieHellman = crypto.createDiffieHellman(DIFFIE_HELLMAN_PRIME, 'base64');
var diffieHellmanSharedSecret;

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
        return resolve('3A')
      } catch (error) {
        reject(error)
      }
      break;
  }
}



var socket;

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

socket = net.connect({ port: PORT }, function() {
  respond(null, write, abort)
});

socket.setEncoding('utf8');

socket.on('data', function(data) {
  console.log('[received]: "' + data + '"');

  console.assert(typeof data === 'string')
  var sequenceNumber = parseInt(data[0], 10);
  var chunkBody = data.toString().slice(1).trim()

  if (expectedSeqNumber === sequenceNumber) {
    respond(chunkBody, write, abort)
  } else {
    console.error('[ABORTING] Invalid chunk. Was expecting sequenceNumber=' + (expectedSeqNumber + 1));
    console.log('Received: "' + chunk + '"');
    socket.end()
  }
});
