package efecta.easypgp.Crypt;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import sun.misc.BASE64Encoder;

public class GenerateKeys {
    public String[] generate() {

        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            BASE64Encoder b64 = new BASE64Encoder();

            SecureRandom random = new SecureRandom();
            generator.initialize(2048, random);

            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            String sPub = b64.encode(pubKey.getEncoded());
            String sPriv = b64.encode(privKey.getEncoded());

            String[] ret = new String[2];
            ret[0] = sPub;
            ret[1] = sPriv;
            return ret;


        } catch (Exception e) {
            throw new IllegalArgumentException();
        }
    }
}
