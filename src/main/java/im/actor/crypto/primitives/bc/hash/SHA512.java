package im.actor.crypto.primitives.bc.hash;

import im.actor.crypto.primitives.Digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512 implements Digest {

    private SHA512Digest sha512Digest = new SHA512Digest();

    @Override
    public int getHashSize() {
        return sha512Digest.getDigestSize();
    }

    @Override
    public void hash(byte[] src, int offset, int length, byte[] dest, int destOffset) {
        sha512Digest.reset();
        sha512Digest.update(src, offset, length);
        sha512Digest.doFinal(dest, destOffset);
    }
}
