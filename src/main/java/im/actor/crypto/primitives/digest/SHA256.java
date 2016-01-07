package im.actor.crypto.primitives.digest;

import im.actor.crypto.primitives.Digest;

public class SHA256 implements Digest {

    private SHA256Digest sha256Digest = new SHA256Digest();

    @Override
    public int getDigestSize() {
        return sha256Digest.getDigestSize();
    }

    @Override
    public void hash(byte[] src, int offset, int length, byte[] dest, int destOffset) {
        sha256Digest.reset();
        sha256Digest.update(src, offset, length);
        sha256Digest.doFinal(dest, destOffset);
    }
}