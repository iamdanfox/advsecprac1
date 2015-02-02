var net = require('net');
var crypto = require('crypto');

var CLIENT_SECRET = 'I am super secret!';
var PORT = 8125;
var DIFFIE_HELLMAN_PRIME = 'KbhkmZowCP8blHg4RYAP95kaIw=='; // length = 150



var expectedSeqNumber = 0;

var diffieHellman = crypto.createDiffieHellman(DIFFIE_HELLMAN_PRIME, 'base64');
var diffieHellmanSharedSecret;

var socket = net.connect({ port: PORT }, function() {
  // do step 1
  diffieHellman.generateKeys()
  socket.write('1' + diffieHellman.getPublicKey('base64'));
  expectedSeqNumber = 2;
});

socket.setEncoding('utf8');

socket.on('data', function(data) {
  console.assert(typeof data === 'string')

  var sequenceNumber = parseInt(data[0], 10);
  var chunkBody = data.toString().slice(1).trim()
  console.assert(typeof chunkBody === 'string')

  if (expectedSeqNumber === sequenceNumber) {
    // proceed
    var serverPublicKey = new Buffer(chunkBody, 'base64');
    diffieHellmanSharedSecret = diffieHellman.computeSecret(serverPublicKey, 'base64');
    console.log('computed shared secret: '+diffieHellmanSharedSecret.toString('base64'));
  } else {
    console.error('[ABORTING] Invalid chunk. Was expecting sequenceNumber=' + (expectedSeqNumber + 1));
    console.log('Received: "' + chunk + '"');
    socket.end()
  }
});
