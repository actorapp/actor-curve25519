package im.actor.crypto.primitives.hmac;

import im.actor.crypto.primitives.ByteStrings;
import im.actor.crypto.primitives.Digest;

import static im.actor.crypto.primitives.ByteStrings.merge;
import static im.actor.crypto.primitives.ByteStrings.substring;

public class HMAC {
    public static void hmac(byte[] secret, byte[] message, int offset, int length, byte[] dest, int destOffset, Digest digest) {
        byte[] fixedSecret = new byte[digest.getHashSize()];
        if (secret.length > digest.getHashSize()) {
            digest.hash(secret, 0, secret.length, fixedSecret, 0);
        } else if (secret.length < digest.getHashSize()) {
            ByteStrings.write(fixedSecret, 0, secret, 0, secret.length);
            for (int i = secret.length; i < fixedSecret.length; i++) {
                fixedSecret[i] = 0;
            }
        } else {
            fixedSecret = secret;
        }

        // Paddings
        byte[] outerKeyPad = new byte[digest.getHashSize()];
        byte[] innerKeyPad = new byte[digest.getHashSize()];
        for (int i = 0; i < outerKeyPad.length; i++) {
            outerKeyPad[i] = (byte) (0x5c ^ fixedSecret[i]);
            innerKeyPad[i] = (byte) (0x36 ^ fixedSecret[i]);
        }

        // Inner digest
        // digest(i_key_pad ∥ message)
        byte[] innnerHash = new byte[digest.getHashSize()];
        digest.hash(merge(innerKeyPad, substring(message, offset, length)), 0, outerKeyPad.length, innnerHash, 0);

        // Outer digest
        // digest(o_key_pad ∥ digest(i_key_pad ∥ message))
        digest.hash(merge(outerKeyPad, innnerHash), 0, digest.getHashSize() * 2, dest, destOffset);
    }
}
