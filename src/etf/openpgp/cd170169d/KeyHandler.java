package etf.openpgp.cd170169d;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

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

public class KeyHandler {

    private static final String RSA_ALG = "RSA";
    private static final String provider = "BC";

    private PGPPublicKeyRingCollection publicKeyRings;
    private PGPSecretKeyRingCollection secretKeyRings;

    public KeyHandler() throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        publicKeyRings = new JcaPGPPublicKeyRingCollection(new ArrayList<>());
        secretKeyRings = new JcaPGPSecretKeyRingCollection(new ArrayList<>());
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

        publicKeyRings = JcaPGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, publicKeyRing);
        secretKeyRings = JcaPGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, secretKeyRing);
    }

    public PGPPublicKeyRingCollection getPublicKeyRings() {
        return publicKeyRings;
    }

    public PGPSecretKeyRingCollection getSecretKeyRings() {
        return secretKeyRings;
    }



}
