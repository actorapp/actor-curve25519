package im.actor.crypto;

import im.actor.crypto.impl.ByteStrings;
import im.actor.crypto.impl.hash.SHA256;
import im.actor.crypto.impl.hmac.HMAC;
import im.actor.crypto.impl.padding.TLSPadding;

public class ActorProto {

    public static byte[] createKuznechikPackage(byte[] macKey, byte[] content) {
        int paddingLength = 0;
        int length =/*Hash size*/ 32 + /*Length prefix*/ 4 + content.length + /*padding length prefix*/1;
        if (length % 32 != 0) {
            paddingLength = 32 - length % 32;
            length += paddingLength;
        }

        byte[] res = new byte[length];
        ByteStrings.write(res, 0, ByteStrings.intToBytes(content.length), 0, 4);
        ByteStrings.write(res, 4, content, 0, content.length);

        HMAC.hmac(macKey, res, 0, content.length + 4, res, content.length + 4, new SHA256());
        new TLSPadding().padding(res, res.length - paddingLength, paddingLength);

        return res;
    }

    public static byte[] readKuznechikPackage(byte[] macKey, byte[] pkg) {
        byte[] hmac = new byte[32];
        int length = ByteStrings.bytesToInt(pkg);
        HMAC.hmac(macKey, pkg, 4, length, hmac, 0, new SHA256());
        for (int i = 0; i < 32; i++) {
            if (hmac[i] != pkg[length + 4 + i]) {
                throw new RuntimeException("Broken package!");
            }
        }
        // TODO: Padding check
        return ByteStrings.substring(pkg, 4, length);
    }
}
