var net = require('net');
var crypto = require('crypto');

var CLIENT_SECRET = 'I am super secret!';
var PORT = 8125;
var DIFFIE_HELLMAN_PRIME = 'KbhkmZowCP8blHg4RYAP95kaIw=='; // length = 150





var diffieHellman = crypto.createDiffieHellman(DIFFIE_HELLMAN_PRIME, 'base64');
var diffieHellmanSharedSecret;

var client = net.connect({ port: PORT }, function() {
  // do step 1
  diffieHellman.generateKeys()
  client.write('1' + diffieHellman.getPublicKey('base64'));
});

client.on('data', function(data) {
  var chunkBody = data.toString().slice(1).trim()
  console.assert(typeof chunkBody === 'string')
  var serverPublicKey = new Buffer(chunkBody, 'base64');

  diffieHellmanSharedSecret = diffieHellman.computeSecret(serverPublicKey, 'base64');
  console.log('computed shared secret: '+diffieHellmanSharedSecret.toString('base64'));
});
