package im.actor.crypto;

public class Tools {

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

    public static boolean isEquals(byte[] data1, byte[] data2) {
        if (data1.length != data2.length) {
            return false;
        }
        for (int i = 0; i < data1.length; i++) {
            if (data1[i] != data2[i]) {
                return false;
            }
        }
        return true;
    }
}
