package im.actor.crypto.primitives;

import im.actor.crypto.primitives.hmac.HMAC;

public class PRF {
    public static byte[] calculate(byte[] secret, String label, byte[] seed, int length, Digest digest) {
        // PRF(secret: bytes, label: string, seed: bytes) = P_HASH(secret, bytes(label) + seed);
        // P_HASH(secret, seed) = HASH(secret, A(1) + seed) + HASH(secret, A(2) + seed) + HASH(secret, A(3) + seed) + ...
        //    where A():
        //    A(0) = seed
        //    A(i) = HMAC_HASH(secret, A(i-1))
        byte[] rSeed = ByteStrings.merge(label.getBytes(), seed);
        byte[] res = new byte[length];
        byte[] A = rSeed;
        byte[] tHash = new byte[digest.getHashSize()];
        int offset = 0;
        while (offset * 32 < length) {

            // Update A
            HMAC.hmac(secret, A, 0, A.length, tHash, 0, digest);
            A = new byte[digest.getHashSize()];
            ByteStrings.write(A, 0, tHash, 0, A.length);

            // Writing digest
            digest.hash(ByteStrings.merge(secret, A, rSeed), 0, secret.length + A.length + rSeed.length, tHash, 0);
            ByteStrings.write(res, offset * digest.getHashSize(), tHash, 0, Math.min(tHash.length, res.length - offset * digest.getHashSize()));
            offset++;
        }
        return res;
    }
}