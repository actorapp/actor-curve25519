package im.actor.crypto.primitives.streebog;

import im.actor.crypto.primitives.util.ByteStrings;

/**
 * 512-bit variable
 */
public class Streebog512 {

    private byte[] value;

    public Streebog512(byte[] value) {
        this.value = value;
    }

    public Streebog512() {
        this.value = new byte[64];
    }

    public byte[] getBytes() {
        return value;
    }

    public void setBytes(byte[] value) {
        this.value = value;
    }

    public byte getByte(int index) {
        return value[index];
    }

    public void setByte(int index, byte v) {
        value[index] = v;
    }

    public int getWord16(int index) {
        return (value[index * 2] & 0xFF) + ((value[index * 2 + 1] & 0xFF) << 8);
    }

    public void setWord16(int index, int val) {
        value[index * 2] = (byte) (val & 0xFF);
        value[index * 2 + 1] = (byte) ((val & 0xFF) >> 8);
    }

    public long getWord64(int index) {
        return ByteStrings.bytesToLong(value, index * 8);
    }

    public void setWord64(int index, long val) {
        ByteStrings.write(value, index * 8, ByteStrings.longToBytes(val), 0, 8);
    }
}
