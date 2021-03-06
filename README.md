Advanced Security Practical 1
=============================

The brief was to design a zero-knowledge protocol to allow two parties to
determine whether they hold the same secret.  (ie the "socialist millionaires problem")

Assumptions
-----------

 * A and B have a secure channel.  (Some other protocol required for Dolev-Yao resistance - e.g. TLS)
 * Both parties know each other's public keys.

Objectives
----------

 * If A and B use the truthful values of their secrets sA, sB, at least once, then after completing the protocol:
   * either: A and B both hold the same truth value for (sA == sB)
   * or: one party knows the other has behaved dishonestly
 * Neither party can determine the other's secret (short of a brute force attack).

Protocol overview
-----------------

It is a fact that one party will determine the truth value of (sA == sB) before
the other.  This protocol ensures that the second party can detect any
dishonesty from the first.

 1. Perform Diffie-Hellman Key Exchange to agree on some `sharedPadding`.
 2. A and B choose symmetric encryption keys `kA` and `kB`.
 3. A and B send `v = SymmetricEncrypt(kX, identityX||payload)`
    where `kX = kA or kB`, `payload = RSAEncrypt(publicKeyX, sX, sharedPadding)``
    Note that neither party can decrypt the value of 'v' that they receive.
 4. A and B send their chosen `kA` and `kB` from step 2.
     * The receiving party can check that this decrypts the `v` that they received correctly (and thereby detect dishonesty)
     * Finally, the receiving part can encrypt their secret with the other party's public key and the agreed `sharedPadding` to determine whether (sA == sB)

Implementation description
--------------------------

(Written for node version v0.10.31). First run `npm install`.

Then run `node server.js` in one shell and `node client.js` from another.

The client will initiate the protocol with the server.  The server's key pair is `server.key.pem` and `server.pub`; the client will never attempt to access `server.key.pem` and vice versa.

Both `server.js` and `client.js` are structured as primitive state machines.  Messages are passed back and forth in base64 encoding for ease of debugging.  Each message starts with a sequence number (from 1 to 6).


Analysis
--------

 * If the protocol is truncated, one participant can learn the value of (sA == sB) without the other learning anything.
   This is unavoidable.
 * This does leak information about the length of the secrets since they are encrypted with RSA. (Could be solved by a compression function, although this introduces a probability of collisions.)
 * If secrets are pooled from a very small domain, brute force attacks become very feasible.
 * Approximate equality is impossible.

 * Dishonest B can't lean sA since sA is only ever transmitted encrypted with A's public key (which the dishonest B can't decrypt).
 * A semi-dishonest member is detected after sending their kX (because it must decrypt their v correctly).  Given the first transmission was truthful, this assurance relies on the difficulty of finding another decryption key kX' that decrypts v to a string of the correct format.
 * Doesn't require repeats for useful probability guarantees.  (6 messages exchanged gives strong probability)
 * Secure channel assumption prevents MITM/impersonation attacks
 * The Diffie-Hellman key exchange at the beginning makes the protocol replay resistant.
