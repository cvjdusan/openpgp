package etf.openpgp.cd170169d;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.encoders.Hex;

public class KeyHandler {

    private static final String RSA_ALG = "RSA";
    private static final String provider = "BC";

    private PGPPublicKeyRingCollection pgpPublicKeyRings;
    private PGPSecretKeyRingCollection pgpSecretKeyRings;

    public KeyHandler() throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        pgpPublicKeyRings = new JcaPGPPublicKeyRingCollection(new ArrayList<>());
        pgpSecretKeyRings = new JcaPGPSecretKeyRingCollection(new ArrayList<>());
    }


    public void createKeyRing(String name, String email, String password, int keySize, boolean encrypt) throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALG, provider);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_SIGN, keyPair, new Date());

        PGPDigestCalculator pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        BcPGPContentSignerBuilder keySignerBuilder =  new BcPGPContentSignerBuilder(
                pgpKeyPair.getPublicKey().getAlgorithm(), 
                HashAlgorithmTags.SHA1);

        BcPBESecretKeyEncryptorBuilder encryptorBuilder =  new BcPBESecretKeyEncryptorBuilder(
                PGPEncryptedData.AES_128, pgpDigestCalculator);

        PBESecretKeyEncryptor keyEncryptor =  encryptorBuilder.build(password.toCharArray());

        String username = name + " <" + email + ">";

        PGPKeyRingGenerator pgpKeyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPair,
                username,
                pgpDigestCalculator,
                null,
                null,
                keySignerBuilder,
                keyEncryptor
        );

        if(encrypt) {
            KeyPairGenerator keyPairGenerator1 = KeyPairGenerator.getInstance(RSA_ALG, provider);
            keyPairGenerator1.initialize(keySize);
            KeyPair keyPair1 = keyPairGenerator1.generateKeyPair();
            PGPKeyPair pgpKeyPair1 = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, keyPair1, new Date());
            pgpKeyRingGenerator.addSubKey(pgpKeyPair1);
        }

        PGPPublicKeyRing publicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();
        PGPSecretKeyRing secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();

        pgpPublicKeyRings = JcaPGPPublicKeyRingCollection.addPublicKeyRing(pgpPublicKeyRings, publicKeyRing);
        pgpSecretKeyRings = JcaPGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRings, secretKeyRing);
    }

    public PGPPublicKeyRingCollection getPgpPublicKeyRings() {
        return pgpPublicKeyRings;
    }

    public PGPSecretKeyRingCollection getPgpSecretKeyRings() {
        return pgpSecretKeyRings;
    }

    public void deletePublicKey(Long keyLongId) throws PGPException {
        PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRings.getPublicKeyRing(keyLongId);
        pgpPublicKeyRings = JcaPGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRings, pgpPublicKeyRing);
        String fp = Hex.toHexString(pgpPublicKeyRing.getPublicKey().getFingerprint()).toUpperCase();
     //   File f = new File("src/etf/openpgp/cd170169d/openpgp/keys/public/" + fp + ".asc");
     //   f.delete();
    }

    public void deletePrivateKey(String password, Long keyLongId) throws PGPException {
        PGPSecretKeyRing pgpSecretKeyRing = pgpSecretKeyRings.getSecretKeyRing(keyLongId);

        JcePBESecretKeyDecryptorBuilder decryptorBuilder = new JcePBESecretKeyDecryptorBuilder();

        pgpSecretKeyRing.getSecretKey().extractPrivateKey(decryptorBuilder.build(password.toCharArray()));

        pgpSecretKeyRings = JcaPGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRings, pgpSecretKeyRing);

        String fp = Hex.toHexString(pgpSecretKeyRing.getPublicKey().getFingerprint()).toUpperCase();
        //   File f = new File("src/etf/openpgp/cd170169d/openpgp/keys/public/" + fp + ".asc");
        //   f.delete();
    }
}
