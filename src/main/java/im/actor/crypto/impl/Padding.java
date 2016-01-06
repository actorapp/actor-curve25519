package im.actor.crypto.impl;

public interface Padding {
    void padding(byte[] src, int offset, int length);
}
