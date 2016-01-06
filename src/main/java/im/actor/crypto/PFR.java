package im.actor.crypto;

import im.actor.crypto.impl.ByteStrings;

public class PFR {
    public static byte[] calculate(byte[] secret, String label, byte[] seed) {
        // PRF(secret: bytes, label: string, seed: bytes) = P_SHA256(secret, bytes(label) + seed);
        // P_SHA256(secret, seed) = SHA256(secret, A(1) + seed) + SHA256(secret, A(2) + seed) + SHA256(secret, A(3) + seed) + ...
        //    where A():
        //    A(0) = seed
        //    A(i) = HMAC_hash(secret, A(i-1))
        byte[] rSeed = ByteStrings.merge(label.getBytes(), seed);
        byte[] res = new byte[256];
        byte[] A = rSeed;
        for (int i = 0; i < 8; i++) {
            A = SHA256.calc(secret, A);
            byte[] p = SHA256.calc(secret, A, rSeed);
            int offset = i * 32;
            for (int j = 0; j < 32; j++) {
                res[offset + j] = p[j];
            }
        }
        return res;
    }
}