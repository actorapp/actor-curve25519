package im.actor.crypto.impl.padding;

import im.actor.crypto.impl.Padding;

public class ZeroPadding implements Padding {
    @Override
    public void padding(byte[] src, int offset, int length) {
        for (int i = 0; i < length; i++) {
            src[i + offset] = 0;
        }
    }
}
