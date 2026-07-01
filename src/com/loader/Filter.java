package com.loader;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Filter {
    private static byte[] encryption_key = "burpr0x!".getBytes();

    private static byte[] decrypt(byte[] data) {
        try {
            SecretKeySpec spec = new SecretKeySpec(encryption_key, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(2, spec);
            return cipher.doFinal(data);
        }
        catch (Exception var3) {
            var3.printStackTrace();
            throw new RuntimeException(var3);
        }
    }

    public static void BurpFilter(Object[] obj) {
        byte[] data = (byte[])obj[0];
        byte[] decode = Base64.getDecoder().decode(data);
        byte[] decrypt = Filter.decrypt(decode);
        String str = new String(decrypt);
        String[] strs = str.split("\u0000");
        obj[0] = Arrays.copyOf(strs, strs.length - 2);
    }
}

