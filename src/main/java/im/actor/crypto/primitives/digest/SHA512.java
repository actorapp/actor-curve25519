package im.actor.crypto.primitives.digest;

import im.actor.crypto.primitives.Digest;

public class SHA512 implements Digest {

    private SHA512Digest sha512Digest = new SHA512Digest();

    @Override
    public int getDigestSize() {
        return sha512Digest.getDigestSize();
    }

    @Override
    public void hash(byte[] src, int offset, int length, byte[] dest, int destOffset) {
        sha512Digest.reset();
        sha512Digest.update(src, offset, length);
        sha512Digest.doFinal(dest, destOffset);
    }
}
