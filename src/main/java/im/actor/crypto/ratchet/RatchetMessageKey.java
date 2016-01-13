package im.actor.crypto.ratchet;

import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.hmac.HMAC;
import im.actor.crypto.primitives.kdf.HKDF;
import im.actor.crypto.primitives.util.ByteStrings;

public class RatchetMessageKey {

    public static RatchetMessageKey buildKey(byte[] rootChainKey, int index) {
        HMAC hmac = new HMAC(rootChainKey, new SHA256());
        byte[] indx = ByteStrings.intToBytes(index);
        hmac.update(indx, 0, indx.length);
        byte[] messageKey = new byte[32];
        hmac.doFinal(messageKey, 0);
        byte[] messageKeyExt = new HKDF(new SHA256()).deriveSecrets(messageKey, 64);
        byte[] cipherKey = ByteStrings.substring(messageKeyExt, 0, 16);
        byte[] macKey = ByteStrings.substring(messageKeyExt, 16, 16);
        return new RatchetMessageKey(cipherKey, macKey);
    }

    private final byte[] cipherKey;
    private final byte[] macKey;

    public RatchetMessageKey(byte[] cipherKey, byte[] macKey) {
        this.cipherKey = cipherKey;
        this.macKey = macKey;
    }

    public byte[] getCipherKey() {
        return cipherKey;
    }

    public byte[] getMacKey() {
        return macKey;
    }
}
