var crypto = require('crypto');

module.exports = {

  PORT: 8125,

  DIFFIE_HELLMAN_PRIME: 'KbhkmZowCP8blHg4RYAP95kaIw==', // length = 150

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

// crypto.pbkdf2Sync('hello, world', 'danisgreat', 20000, 128).toString('base64')