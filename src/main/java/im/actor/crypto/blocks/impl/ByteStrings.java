package im.actor.crypto.blocks.impl;

public class ByteStrings {

    public static byte[] substring(byte[] data, int offset, int size) {
        byte[] res = new byte[size];
        for (int i = 0; i < size; i++) {
            res[i] = data[i + offset];
        }
        return res;
    }

    public static byte[] merge(byte[]... data) {
        int size = 0;
        for (byte[] d : data) {
            size += d.length;
        }
        byte[] res = new byte[size];
        int offset = 0;
        for (byte[] d : data) {
            for (int i = 0; i < d.length; i++) {
                res[offset++] = d[i];
            }
        }
        return res;
    }
}
