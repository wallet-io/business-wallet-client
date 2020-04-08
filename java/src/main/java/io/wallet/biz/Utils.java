package io.wallet.biz;

import java.util.HashMap;
import java.util.Map;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;

// import okio.ByteString;

class Utils {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static Map<String, String> generateKey() {
        ECKey key = new ECKey();
        String privHex = bytes2Hex(key.getPrivKeyBytes());
        String pubHex = bytes2Hex(key.getPubKey());

        Map<String, String> ret = new HashMap<String, String>();
        ret.put("privateKey", privHex);
        ret.put("publicKey", pubHex);
        return ret;
    }

    public static String ecKeySign(String content, String key) {
        ECKey eckey = ECKey.fromPrivate(hex2bytes(key));
        return bytes2Hex(eckey.sign(Sha256Hash.wrap(hash(content))).encodeToDER());
    }

    public static Boolean ecPubKeyVerify(String content, String sign, String pubkey) throws SignatureDecodeException {

        ECKey key = ECKey.fromPublicOnly(hex2bytes(pubkey));
        return key.verify(hash(content), hex2bytes(sign));
    }

    private static byte[] hash(String content) {
        return Sha256Hash.hash(content.getBytes());
    }

    private static byte[] hex2bytes(String s) {
        // return ByteString.decodeHex(s).toByteArray();
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytes2Hex(byte[] bytes) {
        // return ByteString.of(b).hex();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}