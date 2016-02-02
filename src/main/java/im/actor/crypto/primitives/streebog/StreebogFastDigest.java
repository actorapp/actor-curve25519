package im.actor.crypto.primitives.streebog;

import im.actor.crypto.primitives.util.ByteStrings;
import im.actor.crypto.primitives.util.Pack;

public class StreebogFastDigest {

    private final int hashLength;
    private byte[] h = new byte[64];
    private byte[] m = new byte[64];
    private byte[] e = new byte[64];

    private long[] tmpT = new long[8];
    private long[] tmpS = new long[8];
    private long[] tmpK = new long[8];

    private int pt;
    private long n;

    public StreebogFastDigest(int hashLength) {
        this.hashLength = hashLength;
        reset();
    }

    public void reset() {
        // IV:: 01010.. for 256-bit hash, 0000... for 512-bit hash
        // memset(&sbx->h, hlen == 32 ? 0x01 : 0x00, 64);
        // memset(&sbx->e, 0x00, 64);
        for (int i = 0; i < 64; i++) {
            if (hashLength == 32) {
                h[i] = (byte) 0x01;
            } else {
                h[i] = (byte) 0x00;
            }
            e[i] = (byte) 0x00;
        }

        // sbx->pt = 63;
        // sbx->n = 0;
        pt = 63;
        n = 0;
    }

    public void update(byte[] in, int offset, int length) {

        // j = sbx->pt;
        int j = pt;
        for (int i = 0; i < length; i++) {
            m[j--] = in[offset + i];

            // compress
            // if (j < 0) {
            if (j < 0) {
                // streebog_g(&sbx->h, &sbx->m, sbx->n);
                streebog_g(h, m, n);
                // sbx->n += 0x200;
                n += 0x200;

                // epsilon summation
                // c = 0;
                int c = 0;

                // for (j = 63; j >= 0; j--) {
                for (j = 63; j >= 0; j--) {
                    // c += sbx->e.b[j] + sbx->m.b[j];
                    c += (e[j] & 0xFF) + (m[j] & 0xFF);
                    // sbx->e.b[j] = c & 0xFF;
                    e[j] = (byte) (c & 0xFF);
                    // c >>= 8;
                    c >>= 8;
                }

                // j = 63;
                j = 63;
            }
        }

        // sbx->pt = j;
        pt = j;

    }

    public void doFinal(byte[] out, int offset) {

        m[pt] = 1;
        for (int i = 0; i < pt; i++) {
            m[i] = 0;
        }

        streebog_g(h, m, n);

        int c = 0;
        for (int i = 63; i >= 0; i--) {
            c += (e[i] & 0xFF) + (m[i] & 0xFF);
            e[i] = (byte) (c & 0xFF);
            c >>= 8;
        }


        for (int j = 0; j < 64; j++) {
            m[j] = (byte) 0x00;
        }

        // sbx->n += (63 - sbx->pt) << 3;      // total bits
        n += (63 - pt) << 3;
        for (int i = 63; n > 0; i--) {
            // sbx->m.b[i] = sbx->n & 0xFF;
            m[i] = (byte) (n & 0xFF);
            // sbx->n >>= 8;
            n >>= 8;
        }

        // streebog_g(&sbx->h, &sbx->m, 0);
        // streebog_g(&sbx->h, &sbx->e, 0);
        streebog_g(h, m, 0);
        streebog_g(h, e, 0);

        // copy the result
        // memcpy(hash, &sbx->h, sbx->hlen);
        for (int j = 0; j < hashLength; j++) {
            out[offset + j] = h[j];
        }

        // clear out sensitive stuff
        reset();
    }

    //    #define SBOG_LPSti64 \
//            (sbob_sl64[0][t.b[i]] ^     sbob_sl64[1][t.b[i + 8]] ^  \
//    sbob_sl64[2][t.b[i + 16]] ^ sbob_sl64[3][t.b[i + 24]] ^ \
//    sbob_sl64[4][t.b[i + 32]] ^ sbob_sl64[5][t.b[i + 40]] ^ \
//    sbob_sl64[6][t.b[i + 48]] ^ sbob_sl64[7][t.b[i + 56]])

    private static long SBOG_LPSti64(long[] v, int index) {
        return SBOG_LPSti64(Pack.longToBigEndian(v), index);
    }

    private static long SBOG_LPSti64(byte[] t, int i) {
        return (StreebogTables.sbob_sl64[0][t[i] & 0xFF] ^
                StreebogTables.sbob_sl64[1][t[i + 8] & 0xFF] ^
                StreebogTables.sbob_sl64[2][t[i + 16] & 0xFF] ^
                StreebogTables.sbob_sl64[3][t[i + 24] & 0xFF] ^
                StreebogTables.sbob_sl64[4][t[i + 32] & 0xFF] ^
                StreebogTables.sbob_sl64[5][t[i + 40] & 0xFF] ^
                StreebogTables.sbob_sl64[6][t[i + 48] & 0xFF] ^
                StreebogTables.sbob_sl64[7][t[i + 56] & 0xFF]);
    }

    private void streebog_g(byte[] h, byte[] m, long n) {

        long[] hl = new long[8];
        long[] ml = new long[8];
        Pack.bigEndianToLong(h, 0, hl);
        Pack.bigEndianToLong(m, 0, ml);

        tmpT[0] = hl[0];
        tmpT[1] = hl[1];
        tmpT[2] = hl[2];
        tmpT[3] = hl[3];
        tmpT[4] = hl[4];
        tmpT[5] = hl[5];
        tmpT[6] = hl[6];
        tmpT[7] = hl[7];

        byte[] tt = Pack.longToBigEndian(tmpT);
        for (int i = 63; n > 0; i--) {
            // t.b[i] ^= n & 0xFF;
            tt[i] = (byte) (tt[i] ^ ((byte) (n & 0xFF)));
            // n >>= 8;
            n >>= 8;
        }
        Pack.bigEndianToLong(tt, 0, tmpT);

        tmpK[0] = SBOG_LPSti64(tmpT, 0);
        tmpK[1] = SBOG_LPSti64(tmpT, 1);
        tmpK[2] = SBOG_LPSti64(tmpT, 2);
        tmpK[3] = SBOG_LPSti64(tmpT, 3);
        tmpK[4] = SBOG_LPSti64(tmpT, 4);
        tmpK[5] = SBOG_LPSti64(tmpT, 5);
        tmpK[6] = SBOG_LPSti64(tmpT, 6);
        tmpK[7] = SBOG_LPSti64(tmpT, 7);

        tmpS[0] = ml[0];
        tmpS[1] = ml[1];
        tmpS[2] = ml[2];
        tmpS[3] = ml[3];
        tmpS[4] = ml[4];
        tmpS[5] = ml[5];
        tmpS[6] = ml[6];
        tmpS[7] = ml[7];

        for (int r = 0; r < 12; r++) {

            tmpT[0] = tmpS[0] ^ tmpK[0];
            tmpT[1] = tmpS[1] ^ tmpK[1];
            tmpT[2] = tmpS[2] ^ tmpK[2];
            tmpT[3] = tmpS[3] ^ tmpK[3];
            tmpT[4] = tmpS[4] ^ tmpK[4];
            tmpT[5] = tmpS[5] ^ tmpK[5];
            tmpT[6] = tmpS[6] ^ tmpK[6];
            tmpT[7] = tmpS[7] ^ tmpK[7];


            tmpS[0] = SBOG_LPSti64(tmpT, 0);
            tmpS[1] = SBOG_LPSti64(tmpT, 1);
            tmpS[2] = SBOG_LPSti64(tmpT, 2);
            tmpS[3] = SBOG_LPSti64(tmpT, 3);
            tmpS[4] = SBOG_LPSti64(tmpT, 4);
            tmpS[5] = SBOG_LPSti64(tmpT, 5);
            tmpS[6] = SBOG_LPSti64(tmpT, 6);
            tmpS[7] = SBOG_LPSti64(tmpT, 7);

            tmpT[0] = tmpK[0] ^ StreebogTables.sbob_rc64[r][0];
            tmpT[1] = tmpK[1] ^ StreebogTables.sbob_rc64[r][1];
            tmpT[2] = tmpK[2] ^ StreebogTables.sbob_rc64[r][2];
            tmpT[3] = tmpK[3] ^ StreebogTables.sbob_rc64[r][3];
            tmpT[4] = tmpK[4] ^ StreebogTables.sbob_rc64[r][4];
            tmpT[5] = tmpK[5] ^ StreebogTables.sbob_rc64[r][5];
            tmpT[6] = tmpK[6] ^ StreebogTables.sbob_rc64[r][6];
            tmpT[7] = tmpK[7] ^ StreebogTables.sbob_rc64[r][7];

            tmpK[0] = SBOG_LPSti64(tmpT, 0);
            tmpK[1] = SBOG_LPSti64(tmpT, 1);
            tmpK[2] = SBOG_LPSti64(tmpT, 2);
            tmpK[3] = SBOG_LPSti64(tmpT, 3);
            tmpK[4] = SBOG_LPSti64(tmpT, 4);
            tmpK[5] = SBOG_LPSti64(tmpT, 5);
            tmpK[6] = SBOG_LPSti64(tmpT, 6);
            tmpK[7] = SBOG_LPSti64(tmpT, 7);
        }

        hl[0] = hl[0] ^ tmpS[0] ^ tmpK[0] ^ ml[0];
        hl[1] = hl[1] ^ tmpS[1] ^ tmpK[1] ^ ml[1];
        hl[2] = hl[2] ^ tmpS[2] ^ tmpK[2] ^ ml[2];
        hl[3] = hl[3] ^ tmpS[3] ^ tmpK[3] ^ ml[3];
        hl[4] = hl[4] ^ tmpS[4] ^ tmpK[4] ^ ml[4];
        hl[5] = hl[5] ^ tmpS[5] ^ tmpK[5] ^ ml[5];
        hl[6] = hl[6] ^ tmpS[6] ^ tmpK[6] ^ ml[6];
        hl[7] = hl[7] ^ tmpS[7] ^ tmpK[7] ^ ml[7];

        Pack.longToBigEndian(hl, h, 0);
    }
}
