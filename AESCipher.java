package aes;

/**
 * AES Cipher - ho tro 128/192/256 bit
 * CBC mode, PKCS7 padding, Base64, Hex
 * TU VIET HOAN TOAN - khong dung thu vien crypto
 * IV co dinh = 0 (an voi nguoi dung, khong hien thi)
 */
public class AESCipher {

    private final AESCore core = new AESCore();
    private int keyBits;
    private static final byte[] ZERO_IV = new byte[16];

    // ── Constructor: chon kich thuoc khoa ──
    public AESCipher(int keyBits) {
        if (keyBits != 128 && keyBits != 192 && keyBits != 256)
            throw new IllegalArgumentException("keyBits phai la 128, 192 hoac 256!");
        this.keyBits = keyBits;
    }

    public int getKeyBits() {
        return keyBits;
    }

    public int getKeyBytes() {
        return keyBits / 8;
    }

    // =========================================================
    // SINH KHOA NGAU NHIEN theo kich thuoc da chon
    // Dung LCG tu cai dat - khong dung SecureRandom
    // =========================================================
    public byte[] generateKey() {
        int n = getKeyBytes();
        byte[] key = new byte[n];
        long seed = System.nanoTime() ^ (long) (new Object().hashCode()) << 32;
        for (int i = 0; i < n; i++) {
            seed = seed * 6364136223846793005L + 1442695040888963407L;
            key[i] = (byte) ((seed >>> 33) & 0xFF);
        }
        return key;
    }

    // =========================================================
    // PKCS7 PADDING
    // =========================================================
    byte[] addPadding(byte[] data) {
        int padLen = 16 - (data.length % 16);
        byte[] out = new byte[data.length + padLen];
        for (int i = 0; i < data.length; i++)
            out[i] = data[i];
        for (int i = data.length; i < out.length; i++)
            out[i] = (byte) padLen;
        return out;
    }

    byte[] removePadding(byte[] data) throws Exception {
        if (data.length == 0)
            throw new Exception("Du lieu rong!");
        int padLen = data[data.length - 1] & 0xFF;
        if (padLen < 1 || padLen > 16)
            throw new Exception("Padding khong hop le!");
        for (int i = data.length - padLen; i < data.length; i++)
            if ((data[i] & 0xFF) != padLen)
                throw new Exception("Padding sai! Kiem tra lai khoa.");
        byte[] out = new byte[data.length - padLen];
        for (int i = 0; i < out.length; i++)
            out[i] = data[i];
        return out;
    }

    // =========================================================
    // CBC MA HOA — IV co dinh = {0,0,...,0}
    // Ci = AES_Encrypt(Pi XOR Ci-1), C0 dung IV
    // =========================================================
    public byte[] encryptCBC(byte[] plaintext, byte[] key) throws Exception {
        validateKey(key);
        int[][] rk = core.keyExpansion(key);
        byte[] pad = addPadding(plaintext);
        byte[] ct = new byte[pad.length];
        byte[] prev = ZERO_IV;
        for (int i = 0; i < pad.length; i += 16) {
            byte[] block = new byte[16];
            for (int j = 0; j < 16; j++)
                block[j] = (byte) (pad[i + j] ^ prev[j]);
            prev = core.encryptBlock(block, rk);
            for (int j = 0; j < 16; j++)
                ct[i + j] = prev[j];
        }
        return ct;
    }

    // =========================================================
    // CBC GIAI MA
    // Pi = AES_Decrypt(Ci) XOR Ci-1
    // =========================================================
    public byte[] decryptCBC(byte[] ciphertext, byte[] key) throws Exception {
        validateKey(key);
        if (ciphertext.length % 16 != 0)
            throw new Exception("Ciphertext khong hop le (khong phai boi so 16 bytes)!");
        int[][] rk = core.keyExpansion(key);
        byte[] pad = new byte[ciphertext.length];
        byte[] prev = ZERO_IV;
        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] block = new byte[16];
            for (int j = 0; j < 16; j++)
                block[j] = ciphertext[i + j];
            byte[] dec = core.decryptBlock(block, rk);
            for (int j = 0; j < 16; j++)
                pad[i + j] = (byte) (dec[j] ^ prev[j]);
            prev = block;
        }
        return removePadding(pad);
    }

    private void validateKey(byte[] key) throws Exception {
        if (key == null)
            throw new Exception("Khoa null!");
        if (key.length != getKeyBytes())
            throw new Exception("Khoa sai do dai! Can " + keyBits + " bit (" + getKeyBytes() + " bytes), co "
                    + (key.length * 8) + " bit.");
    }

    // =========================================================
    // BASE64 ENCODE - tu cai dat
    // =========================================================
    private static final char[] B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    public String base64Encode(byte[] data) {
        int len = data.length;
        char[] out = new char[((len + 2) / 3) * 4];
        int idx = 0;
        for (int i = 0; i < len; i += 3) {
            int b0 = data[i] & 0xFF;
            int b1 = (i + 1 < len) ? data[i + 1] & 0xFF : 0;
            int b2 = (i + 2 < len) ? data[i + 2] & 0xFF : 0;
            out[idx++] = B64[b0 >> 2];
            out[idx++] = B64[(b0 & 0x03) << 4 | b1 >> 4];
            out[idx++] = (i + 1 < len) ? B64[(b1 & 0x0F) << 2 | b2 >> 6] : '=';
            out[idx++] = (i + 2 < len) ? B64[b2 & 0x3F] : '=';
        }
        return new String(out);
    }

    // =========================================================
    // BASE64 DECODE - tu cai dat
    // =========================================================
    public byte[] base64Decode(String s) throws Exception {
        s = s.trim();
        int len = s.length();
        if (len % 4 != 0)
            throw new Exception("Chuoi Base64 khong hop le!");
        int[] dec = new int[128];
        for (int i = 0; i < 128; i++)
            dec[i] = -1;
        for (int i = 0; i < 64; i++)
            dec[B64[i]] = i;
        int pad = 0;
        if (s.charAt(len - 1) == '=')
            pad++;
        if (s.charAt(len - 2) == '=')
            pad++;
        byte[] out = new byte[(len / 4) * 3 - pad];
        int idx = 0;
        for (int i = 0; i < len; i += 4) {
            int c0 = dec[s.charAt(i)], c1 = dec[s.charAt(i + 1)];
            int c2 = s.charAt(i + 2) == '=' ? 0 : dec[s.charAt(i + 2)];
            int c3 = s.charAt(i + 3) == '=' ? 0 : dec[s.charAt(i + 3)];
            if (c0 < 0 || c1 < 0)
                throw new Exception("Ky tu Base64 khong hop le!");
            int v = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
            if (idx < out.length)
                out[idx++] = (byte) ((v >> 16) & 0xFF);
            if (idx < out.length)
                out[idx++] = (byte) ((v >> 8) & 0xFF);
            if (idx < out.length)
                out[idx++] = (byte) (v & 0xFF);
        }
        return out;
    }

    // =========================================================
    // HEX ENCODE / DECODE - tu cai dat
    // =========================================================
    public String toHex(byte[] data) {
        char[] hex = "0123456789ABCDEF".toCharArray();
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            out[2 * i] = hex[(data[i] >> 4) & 0xF];
            out[2 * i + 1] = hex[data[i] & 0xF];
        }
        return new String(out);
    }

    public byte[] fromHex(String hex) throws Exception {
        hex = hex.trim().toUpperCase().replaceAll("\\s+", "");
        if (hex.length() % 2 != 0)
            throw new Exception("Hex phai co so ky tu chan!");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0)
                throw new Exception("Ky tu hex khong hop le!");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    // =========================================================
    // STRING <-> BYTE[]
    // =========================================================
    public byte[] toBytes(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (Exception e) {
            return s.getBytes();
        }
    }

    public String toString(byte[] b) {
        try {
            return new String(b, "UTF-8");
        } catch (Exception e) {
            return new String(b);
        }
    }
}
