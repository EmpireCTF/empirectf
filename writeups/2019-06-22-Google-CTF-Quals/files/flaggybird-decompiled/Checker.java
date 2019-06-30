package com.google.ctf.game;

import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Checker {
    private static final byte[] a = new byte[]{(byte) 46, (byte) 50, (byte) 92, (byte) -111, (byte) -55, (byte) 20, (byte) 120, (byte) -77, (byte) 92, (byte) 46, (byte) 12, (byte) -74, (byte) 91, (byte) 120, (byte) 81, (byte) -58, (byte) -6, (byte) -104, (byte) -123, (byte) 90, (byte) 119, (byte) -61, (byte) -65, (byte) -45, (byte) -16, (byte) 8, (byte) 64, (byte) -68, (byte) -103, (byte) -84, (byte) -30, (byte) 107};
    private static final byte[] b = new byte[]{(byte) -30, (byte) 1, (byte) 9, (byte) -29, (byte) -92, (byte) 104, (byte) -52, (byte) -82, (byte) 42, (byte) -116, (byte) 1, (byte) -58, (byte) 92, (byte) -56, (byte) -25, (byte) 62};
    private static final byte[] c = new byte[]{(byte) -113, (byte) -47, (byte) -15, (byte) 105, (byte) -18, (byte) 14, (byte) -118, (byte) 122, (byte) 103, (byte) 93, (byte) 120, (byte) 70, (byte) -36, (byte) -82, (byte) 109, (byte) 113, (byte) 36, (byte) -127, (byte) 19, (byte) -35, (byte) -68, (byte) 21, (byte) -20, (byte) -69, (byte) 7, (byte) 94, (byte) -115, (byte) 58, (byte) -105, (byte) -10, (byte) -77, (byte) -62, (byte) 106, (byte) 86, (byte) -44, (byte) -24, (byte) -46, (byte) 112, (byte) 37, (byte) 3, (byte) -34, (byte) -51, (byte) -35, (byte) 90, (byte) -93, (byte) -59, (byte) 12, (byte) -35, (byte) 125, (byte) -33, (byte) -6, (byte) -109, (byte) -100, (byte) 25, Byte.MAX_VALUE, (byte) 126, (byte) -81, (byte) -73, (byte) -50, (byte) -61, (byte) 84, (byte) 32, Byte.MAX_VALUE, (byte) -126, (byte) -81, (byte) -20, (byte) -116, (byte) -82, (byte) 38, (byte) 119, (byte) 27, (byte) 7, (byte) 122, (byte) -2, (byte) -30, (byte) 58, (byte) 98, (byte) -17, (byte) 66, (byte) -103, (byte) 116, (byte) -83, (byte) -36, (byte) 106, (byte) 121, (byte) -23, (byte) -40, (byte) 125, (byte) -27, (byte) -37, (byte) -95, (byte) -59, (byte) -70, (byte) 61, (byte) 71, (byte) 43, (byte) -55, (byte) -22, (byte) -8, (byte) -72, (byte) 50, (byte) -19, (byte) -77, (byte) 37, (byte) 78, (byte) -37, (byte) 126, (byte) 119, (byte) 31, (byte) -37, (byte) 70, (byte) 41, (byte) 64, (byte) -97, (byte) -28, (byte) 68, (byte) -14, (byte) -41, (byte) -17, (byte) -94, (byte) 3, (byte) 2, (byte) 31, (byte) -85, (byte) -86, (byte) 84, (byte) -34, (byte) -58, (byte) 115, (byte) -14, (byte) 87, (byte) 62, (byte) 52, (byte) 103, (byte) -28, (byte) -89, (byte) 3, (byte) 104, (byte) 19, (byte) 61, (byte) -7, (byte) -53, (byte) -15, (byte) 28, (byte) -108, (byte) -85, (byte) -106, (byte) 3, (byte) -77, (byte) -11, (byte) 37, (byte) -65, (byte) -107, (byte) -61, (byte) 53, (byte) -3, (byte) -68, (byte) 105, (byte) -101, (byte) -118, (byte) -44, (byte) 69, (byte) -63, (byte) -81, (byte) -57, (byte) 74, (byte) -86, (byte) 76, (byte) 27, (byte) -58, (byte) 91, (byte) 64, (byte) 60, (byte) -86, (byte) 3, (byte) 5, (byte) -108, (byte) -44, (byte) 77, (byte) -80, (byte) 50, (byte) 119, (byte) 109, (byte) 107, (byte) -43, (byte) -93, (byte) -87, (byte) -42, (byte) 32, (byte) 66, (byte) 27, (byte) -64, (byte) 38, (byte) -44, (byte) 50, (byte) -108, (byte) -21, (byte) -70, (byte) -102, (byte) -63, (byte) -120, (byte) 118, (byte) 7, (byte) 89, (byte) -106, (byte) 66, (byte) -3, (byte) -10, (byte) 93, (byte) -9, (byte) 3, (byte) 13, (byte) 35, (byte) 37, (byte) -19, (byte) 116, (byte) 47, (byte) 29, (byte) 91, (byte) -30, (byte) 69, (byte) -49, (byte) 109, (byte) 72, (byte) 6, (byte) 36, (byte) 58, (byte) -63, (byte) 107, (byte) 48, (byte) 70, Byte.MAX_VALUE, (byte) -127, (byte) 51, (byte) -110, (byte) 48, (byte) -73, (byte) -62, (byte) -118, (byte) 59, (byte) -27, (byte) 30, (byte) -109, (byte) -42, (byte) -109, (byte) -54, (byte) -22, (byte) 95, (byte) 123, (byte) -89, (byte) -62, (byte) -99, (byte) -62, (byte) 66, (byte) 60, (byte) 126, (byte) -52, (byte) -117, (byte) -98, (byte) -95, (byte) 2, (byte) -93, (byte) -93, (byte) -30, (byte) 85, (byte) -113, (byte) -77, (byte) -60, (byte) -83, (byte) -4, (byte) -50, (byte) 52, (byte) 113, (byte) 62, (byte) -104, (byte) -124, (byte) 56, (byte) 89, (byte) -62, (byte) 108, (byte) 35, (byte) -10, (byte) 90, (byte) -42, (byte) -26, (byte) 114, (byte) 11, (byte) -49, (byte) -18, (byte) 56, (byte) -60, (byte) -87, (byte) -118, (byte) -106, (byte) -76, (byte) -103, (byte) -53, (byte) -7, (byte) -54, (byte) -70, (byte) -120, (byte) -92, (byte) -29, (byte) -17, (byte) -106, (byte) 80, (byte) -3, (byte) -18, (byte) -44, (byte) 115, (byte) -31, (byte) 57, (byte) -57, (byte) 60, (byte) 94, (byte) -6, (byte) 18, (byte) -56, (byte) -27, (byte) -17};

    Checker() {
    }

    private byte[] a(byte[] bArr, byte[] bArr2) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(b);
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            instance.init(2, secretKeySpec, ivParameterSpec);
            return instance.doFinal(bArr2);
        } catch (Exception unused) {
            return null;
        }
    }

    /* Access modifiers changed, original: 0000 */
    public byte[] a(byte[] bArr) {
        if (nativeCheck(bArr)) {
            try {
                if (Arrays.equals(MessageDigest.getInstance("SHA-256").digest(bArr), a)) {
                    return a(bArr, c);
                }
            } catch (Exception unused) {
            }
        }
        return null;
    }

    public native boolean nativeCheck(byte[] bArr);
}
