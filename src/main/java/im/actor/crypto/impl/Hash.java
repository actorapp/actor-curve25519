package im.actor.crypto.impl;

public interface Hash {

    int getHashSize();

    void hash(byte[] src, int offset, int length, byte[] dest, int destOffset);
}
