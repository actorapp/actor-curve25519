package im.actor.crypto.primitives.hkdf;

import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.hmac.HMAC;
import im.actor.crypto.primitives.util.ByteStrings;

/**
 * HKDF implementation based on RFC 5869: https://tools.ietf.org/html/rfc5869
 */
public class HKDF {

    public static byte[] deriveSecrets(byte[] keyMaterial, byte[] salt, byte[] info, int outputLength) {
        byte[] prk = hkdfExtract(salt, keyMaterial);
        return hkdfExpand(prk, info, outputLength);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] keyMaterial) {
        HMAC hmac = new HMAC(salt, new SHA256());
        hmac.reset();
        hmac.update(keyMaterial, 0, keyMaterial.length);
        byte[] res = new byte[32];
        hmac.doFinal(res, 0);
        return res;
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int outputSize) {
        byte[] res = new byte[outputSize];
        HMAC hmac = new HMAC(prk, new SHA256());

        byte[] prevHash = new byte[0];
        int offset = 0;
        int index = 0;
        byte[] indexB = new byte[1];
        while (offset < res.length) {
            hmac.reset();
            hmac.update(prevHash, 0, prevHash.length);
            hmac.update(info, 0, info.length);
            indexB[0] = (byte) index;
            hmac.update(indexB, 0, 1);

            byte[] result = new byte[32];
            hmac.doFinal(result, 0);

            ByteStrings.write(res, index * 32, result, 0, Math.min(outputSize - index * 32 + 32, 32));

            prevHash = res;
        }

        return res;
    }
}
