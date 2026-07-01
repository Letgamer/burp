package com.loader;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Keygen {
    private static final String privateKey2048 = "30820238020100300D06092A864886F70D0101010500048202223082021E02010002820101009D9DF9EB49890DE8F193C89598584BC947BA83727B2D89AA8BE3A4689130FE2E948967D40B656762F9989E59C9655E28E33FD4B4A544126FDD90A566BB61C2D7C74A6829265767B56E28FD2214D4BEB3B1DA4722BC394E2E6AFA0F1689FA9DB442643DDDA84997C5AD15B57EE5BD1A357CABF6ED4CAAA5FB8872E07C8F5FAE1C573C1214DD273C6D8887D7E993208D75118CC2305D60AA337B0999B69988322A8FAA9FBFF49AB70B71723E1CBD79D12640AF19E6FBC28C05E6630414DBAD9AEF912D0AC53E40B7F48EE29BFE1DEFCFB0BDB1B6C5BF8B06DCCA15FA1FC3F468952D481070C92C386D3CE6187B062038A6CA822D352ECEBEAC195918F9BB5C3AC3020100028201005DAD71C754BA3F692E835E1903259F4D6EF33C82C3110A9C316E47DDDA455B1D062D306787AA6A2B1A1B8A29E517F941A5E6DF1DCA87CDC96CCF366EFB799C1B31185915F3F2C8F1BD1A61706B1F1284AC7506087004432235748F991EC2B40E59D3482DC08294D0E9115900A5BCA1A21E89FA45896677262B2FD39A54805273162D655F1AB4392CE4E01A4DD63F7EF387B79D53B73BBE45EA7D9BE64A627CFB3DAE2843E85ED3697672BD4832F5EEB4C18C4D15FEB550E0B5A7018A3CD39A9FD4BDA35A6F88BD00CCBC787419AD57C54FA823EC3D7662710B03C2622E9E2DE546B21CA1C76672B1CC6BD92871A0F96051E31CB060E0DDB4022BEB2897A88761020100020100020100020100020100";
    private static final String privateKey1024 = "30820136020100300D06092A864886F70D0101010500048201203082011C020100028181008D187233EB87AB60DB5BAE8453A7DE035428EB177EC8C60341CAB4CF487052751CA8AFF226EA3E98F0CEEF8AAE12E3716B8A20A24BDE20703865C9DBD9543F92EA6495763DFD6F7507B8607F2A14F52694BB9793FE12D3D9C5D1C0045262EA5E7FA782ED42568C6B7E31019FFFABAEFB79D327A4A7ACBD4D547ACB2DC9CD04030201000281807172A188DBAD977FE680BE3EC9E0E4E33A4D385208F0383EB02CE3DAF33CD520332DF362BA2588B58292710AC9D2882C4F329DF0C11DD66944FF9B21F98A031ED27C19FE2BCF8A09AD3E254A0FD7AB89E0D1E756BCF37ED24D42D1977EA7C1C78ABF4D13F752AE48B426A2DC98C5D13B2313609FAA6441E835DC61D17A01D1A9020100020100020100020100020100";
    private static final byte[] encryption_key = "burpr0x!".getBytes();

    public static String generateActivationResponse(String licenseID, String username, String osname) {
        ArrayList<String> activationResponse = new ArrayList<String>();
        activationResponse.add("0.4315672535134567"); // nonce
        activationResponse.add(Keygen.generateMachineID()); // machineID
        activationResponse.add("activation"); // action
        activationResponse.add(licenseID);
        activationResponse.add("True"); // success
        activationResponse.add(""); // error message
        activationResponse.add("2026.5"); // version
        activationResponse.add(Keygen.generateBlob(licenseID, username, osname)); //blob
        activationResponse.add(Keygen.getSign(privateKey2048, Keygen.getSignatureBytes(activationResponse), "SHA256withRSA"));
        activationResponse.add(Keygen.getSign(privateKey1024, Keygen.getSignatureBytes(activationResponse), "SHA1withRSA"));
        return Keygen.prepareArray(activationResponse);
    }

    private static byte[] getSignatureBytes(List<String> list) {
        try {
            ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
            for (String item : list) {
                outputBuffer.write(item.getBytes());
                outputBuffer.write(0);
            }
            return outputBuffer.toByteArray();
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to generate signature bytes", e);
        }
    }

    private static String getSign(String privateKeyHex, byte[] data, String signatureAlgorithm) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(Keygen.getPriKeyByHex(privateKeyHex));
            signature.update(data);
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to generate signature using " + signatureAlgorithm, e);
        }
    }

    public static RSAPrivateKey getPriKeyByHex(String hexString) {
        BigInteger hexValue = new BigInteger(hexString, 16);
        byte[] privateKeyBytes = hexValue.toByteArray();
        return Keygen.getPriKeyByBytes(privateKeyBytes);
    }

    public static RSAPrivateKey getPriKeyByBytes(byte[] privateKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to load RSA private key from bytes", e);
        }
    }

    public static String[] generateLicense() {
        ArrayList<String> licenseData = new ArrayList<String>();
        String licenseID = Keygen.generateLicenseID();
        licenseData.add(licenseID); // license ID
        licenseData.add("license"); // license type
        licenseData.add(""); // license name shown in the UI
        licenseData.add("4102415999000"); // expiration date (unix timestamp)
        licenseData.add("1"); // commercial license
        licenseData.add("full"); // license type
        licenseData.add(Keygen.getSign(privateKey2048, Keygen.getSignatureBytes(licenseData), "SHA256withRSA"));
        licenseData.add(Keygen.getSign(privateKey1024, Keygen.getSignatureBytes(licenseData), "SHA1withRSA"));
        return new String[]{licenseID, Keygen.prepareArray(licenseData)};
    }

    private static String generateLicenseID() {
        String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder licenseId = new StringBuilder();
        Random random = new Random();
        while (licenseId.length() < 32) {
            int index = (int)(random.nextFloat() * (float)CHARS.length());
            licenseId.append(CHARS.charAt(index));
        }
        return licenseId.toString();
    }

    private static String generateMachineID() {
        String CHARS = "0123456789abcdef";
        StringBuilder machineId = new StringBuilder();
        Random random = new Random();
        while (machineId.length() < 16) {
            int index = (int)(random.nextFloat() * (float)CHARS.length());
            machineId.append(CHARS.charAt(index));
        }
        return machineId.toString();
    }

    public static String generateBlob(String licenseID, String username, String osname) {
        // This is a value introduced in Version 1.4.06 of Burp Suite
        String blob = "751a8be34c1a9ed9633d04be3ba075a7" + licenseID + osname + username;
        try {
            // Use SHA-1 to hash the blob and then encode it in Base64
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest(blob.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generatePrefsKey(String licenseID) {
        // Generate a raw MD4 hash of the license ID
        MD4 md4 = new MD4();
        byte[] result = md4.engineDigest(licenseID);
        // Then encode the raw MD4 hash in Base64 to get the final key
        return Base64.getEncoder().encodeToString(result);
    }

    private static String prepareArray(ArrayList<String> items) {
        try {
            ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
            for (int i = 0; i < items.size() - 1; ++i) {
                outputBuffer.write(items.get(i).getBytes());
                outputBuffer.write(0);
            }
            outputBuffer.write(items.get(items.size() - 1).getBytes());
            return new String(Base64.getEncoder().encode(Keygen.encrypt(outputBuffer.toByteArray())));
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to prepare array for encoding", e);
        }
    }

    private static byte[] encrypt(byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryption_key, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(1, keySpec);
            return cipher.doFinal(data);
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to encrypt data using DES", e);
        }
    }

    public static String[] decodePayload(String payload) {
        try {
            ArrayList<String> ar = Keygen.getParamsList(payload);

            if (ar == null) {
                throw new IllegalArgumentException("Payload parsing returned null");
            }

            if (ar.isEmpty()) {
                throw new IllegalArgumentException("Payload parsing returned empty result");
            }

            return ar.toArray(new String[0]);

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode payload", e);
        }
    }

    private static ArrayList<String> getParamsList(String data) {
        byte[] rawBytes = Keygen.decrypt(Base64.getDecoder().decode(data));
        ArrayList<String> parameters = new ArrayList<String>();
        int startIndex = 0;
        for (int i = 0; i < rawBytes.length; ++i) {
            if (rawBytes[i] != 0) continue;
            parameters.add(new String(rawBytes, startIndex, i - startIndex));
            startIndex = i + 1;
        }
        parameters.add(new String(rawBytes, startIndex, rawBytes.length - startIndex));
        return parameters;
    }

    private static byte[] decrypt(byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryption_key, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(2, keySpec);
            return cipher.doFinal(data);
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to decrypt data using DES", e);
        }
    }
}

