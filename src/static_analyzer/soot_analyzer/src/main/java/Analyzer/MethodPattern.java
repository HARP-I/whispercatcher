package Analyzer;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class MethodPattern {

    public static final Set<String> jsonMethods = new HashSet<>(Arrays.asList(
            "put",
            "optString"
    ));

    public static final Set<String> encMethods = new HashSet<>(Arrays.asList(
            "encrypt",
            "decrypt",
            "encode",
            "decode",
            "doFinal",
            "enc",
            "dec",
            "digest",
            "aes",
            "rsa",
            "digest"
    ));
    public static final Set<String> encChain = new HashSet<>(Arrays.asList(
            "java.lang.String.getBytes",
            "javax.crypto.Cipher.init",
            "javax.crypto.Cipher.getInstance",
            "javax.crypto.Cipher.doFinal",
            "android.util.Base64.encode",
            "android.util.Base64.decode",
            "java.security.MessageDigest.getInstance",
            "java.security.MessageDigest.digest"
    ));

    public static final Set<String> escapeJavaMethods = new HashSet<>(Collections.singletonList(
            "java.lang.Integer"
    ));

    public static boolean matchJSONMethods(String name) {
        return jsonMethods.contains(name);
    }
}
