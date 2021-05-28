package etf.openpgp.cd170169d;

import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.sun.deploy.security.SelectableSecurityManager;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class PGPKeyHandler {

    private static final String RSA_ALG = "RSA";
    private static final String AES_ALG = "AES";
    private static final String DESede_ALG = "DESede";
    private static final String provider = "BC";

    private PGPPublicKeyRingCollection pgpPublicKeyRings;
    private PGPSecretKeyRingCollection pgpSecretKeyRings;

    public PGPKeyHandler() throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        pgpPublicKeyRings = new PGPPublicKeyRingCollection(new ArrayList<>());
        pgpSecretKeyRings = new PGPSecretKeyRingCollection(new ArrayList<>());
    }


    public void createKeyRing(String name, String email, String password, int keySize, boolean encrypt) throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALG, provider);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN, keyPair, new Date());
        PGPDigestCalculator pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        BcPGPContentSignerBuilder keySignerBuilder = new BcPGPContentSignerBuilder(
                pgpKeyPair.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA1);

        BcPBESecretKeyEncryptorBuilder encryptorBuilder = new BcPBESecretKeyEncryptorBuilder(
                PGPEncryptedData.AES_128, pgpDigestCalculator);

        PBESecretKeyEncryptor keyEncryptor = encryptorBuilder.build(password.toCharArray());

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

        if (encrypt) {
            KeyPairGenerator keyPairGenerator1 = KeyPairGenerator.getInstance(RSA_ALG, provider);
            keyPairGenerator1.initialize(keySize);
            KeyPair keyPair1 = keyPairGenerator1.generateKeyPair();
            PGPKeyPair pgpKeyPair1 = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, keyPair1, new Date());
            pgpKeyRingGenerator.addSubKey(pgpKeyPair1);
        }

        PGPPublicKeyRing publicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();
        PGPSecretKeyRing secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();

        addToPublicKeyRings(publicKeyRing);
        addToPrivateKeyRings(secretKeyRing);
    }

    public void addToPublicKeyRings(PGPPublicKeyRing publicKeyRing) {
        pgpPublicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPublicKeyRings, publicKeyRing);
    }

    public void addToPrivateKeyRings(PGPSecretKeyRing secretKeyRing) {
        pgpSecretKeyRings = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRings, secretKeyRing);
    }

    public PGPPublicKeyRingCollection getPgpPublicKeyRings() {
        return pgpPublicKeyRings;
    }

    public PGPSecretKeyRingCollection getPgpSecretKeyRings() {
        return pgpSecretKeyRings;
    }

    public PGPPublicKeyRing getPublicKeyRing(Long keyLongId) throws PGPException {
        return pgpPublicKeyRings.getPublicKeyRing(keyLongId);
    }

    public PGPSecretKeyRing getPrivateKeyRing(Long keyLongId) throws PGPException {
        return pgpSecretKeyRings.getSecretKeyRing(keyLongId);
    }

    public void decryptKeyFromFile(InputStream in) throws Exception {
        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));

        Object o = pgpF.nextObject();

        PGPPublicKeyRing publicKeyRing = null;
        PGPSecretKeyRing secretKeyRing = null;

        if (o instanceof PGPPublicKeyRing) {
            publicKeyRing = (PGPPublicKeyRing) o;
        } else {
            secretKeyRing = (PGPSecretKeyRing) o;
        }

        if (publicKeyRing != null) {
            addToPublicKeyRings(publicKeyRing);
        } else if (secretKeyRing != null) {
            addToPrivateKeyRings(secretKeyRing);
        }

    }

    public void deletePublicKey(Long keyLongId) throws PGPException {
        PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRings.getPublicKeyRing(keyLongId);
        pgpPublicKeyRings = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRings, pgpPublicKeyRing);
        String fp = Hex.toHexString(pgpPublicKeyRing.getPublicKey().getFingerprint()).toUpperCase();

        //   File f = new File("src/etf/openpgp/cd170169d/openpgp/keys/public/" + fp + ".asc");
        //   f.delete();
    }

    public void deletePrivateKey(String password, Long keyLongId) throws PGPException {
        PGPSecretKeyRing pgpSecretKeyRing = pgpSecretKeyRings.getSecretKeyRing(keyLongId);

        JcePBESecretKeyDecryptorBuilder decryptorBuilder = new JcePBESecretKeyDecryptorBuilder();

        pgpSecretKeyRing.getSecretKey().extractPrivateKey(decryptorBuilder.build(password.toCharArray()));

        pgpSecretKeyRings = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRings, pgpSecretKeyRing);

        String fp = Hex.toHexString(pgpSecretKeyRing.getPublicKey().getFingerprint()).toUpperCase();
        //   File f = new File("src/etf/openpgp/cd170169d/openpgp/keys/public/" + fp + ".asc");
        //   f.delete();
    }

    public OutputStream radix64(FileOutputStream file){
        return new ArmoredOutputStream(file);
    }

    public OutputStream encrypt(OutputStream out, int alg, List<PGPPublicKeyRing> publicKeys) throws NoSuchAlgorithmException, PGPException, IOException {

            if(alg == 0)
                alg = SymmetricKeyAlgorithmTags.TRIPLE_DES;
            else
                alg = SymmetricKeyAlgorithmTags.AES_128;

            JcePGPDataEncryptorBuilder pgpDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(alg)
                    .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom())
                    .setProvider(provider);

            KeyGenerator keyGenerator = null;

            switch (alg) {
                case SymmetricKeyAlgorithmTags.TRIPLE_DES:
                    keyGenerator = KeyGenerator.getInstance(DESede_ALG);
                    keyGenerator.init(168);
                    break;
                case SymmetricKeyAlgorithmTags.AES_128:
                    keyGenerator = KeyGenerator.getInstance(AES_ALG);
                    keyGenerator.init(128);
                    break;
                default:
                    break;
            }
            //keyGenarator.generateKey() to je sessionKey
            pgpDataEncryptorBuilder.build(keyGenerator.generateKey().getEncoded());

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(pgpDataEncryptorBuilder);
            for (PGPPublicKeyRing publicKey : publicKeys) {

                Iterator<PGPPublicKey> it = publicKey.getPublicKeys();

                PGPPublicKey next = it.next();

                if (!it.hasNext()) throw new PGPException("Ne moze jer nema RSA subkey.");

                PGPPublicKey subKey = it.next();

                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(subKey));
            }
            return encryptedDataGenerator.open(out, new byte[16 * 1024]);

    }

    public OutputStream compress(OutputStream outEnc) throws IOException {

        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        return compressedDataGenerator.open(outEnc);
    }

    public void sendMessage(String text, boolean enc, boolean sign, boolean comp, boolean radix,
                            int alg, String password, FileOutputStream file, PGPSecretKeyRing secretKey,
                            List<PGPPublicKeyRing> publicKeys) throws NoSuchAlgorithmException, PGPException, IOException, SignatureException {

        OutputStream out;

        OutputStream outEnc = null;
        OutputStream outComp = null;
        PGPOnePassSignature signature = null;
        PGPSignatureGenerator signatureGenerator = null;

        if(radix)
            out = radix64(file);
        else
            out = file;

        if(enc)
            outEnc = encrypt(out, alg, publicKeys);
        else
            outEnc = out;

        if(comp)
            outComp = compress(outEnc);
        else
            outComp = outEnc;

        if(sign)
            sign(signatureGenerator, signature, secretKey, outComp, password);

        File tmpFile = File.createTempFile("etf/openpgp/cd170169d/pgp", null);
        FileWriter writer = new FileWriter(tmpFile);
        writer.write(text.toCharArray());
        writer.close();

     //   PGPUtil.writeFileToLiteralData(outComp, PGPLiteralDataGenerator.UTF8, tmpFile, new byte[16 * 1024]);
        myWriteToFileToLiteralData(outComp, PGPLiteralDataGenerator.UTF8, tmpFile, new byte[16 * 1024], signatureGenerator);

        outComp.close();
        outEnc.close();
        out.close();
    }

    private void sign(PGPSignatureGenerator signatureGenerator, PGPOnePassSignature signature, PGPSecretKeyRing secretKey, OutputStream outComp, String password) throws PGPException, IOException {
        signatureGenerator = new PGPSignatureGenerator (new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA256));
        PGPPrivateKey privateKey = null;

        try {
            privateKey = secretKey.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));
        } catch (Exception e) {
            throw new PGPException("Pogresna sifra");
        }

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

        subpacketGenerator.setSignerUserID(false, secretKey.getPublicKey().getUserIDs().next().getBytes());

        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        signature = signatureGenerator.generateOnePassVersion(false);

        signature.encode(outComp);

    }

    public static void myWriteToFileToLiteralData(OutputStream out, char fileType, File file, byte[] buffer, PGPSignatureGenerator signatureGenerator) throws IOException, SignatureException, PGPException {
        PGPLiteralDataGenerator literalDataGenerator = null;
        BufferedInputStream in = null;
        try {
            literalDataGenerator = new PGPLiteralDataGenerator();
            OutputStream literalOut = literalDataGenerator.open(out, fileType, file.getName(), new Date(file.lastModified()), buffer);
            in = new BufferedInputStream(new FileInputStream(file), buffer.length);
            byte[] buf = new byte[buffer.length];
            int len;

            while ((len = in.read(buf)) > 0) {
                literalOut.write(buf, 0, len);
                if (signatureGenerator != null)
                    signatureGenerator.update(buf, 0, len);
            }

            literalOut.close();
        } finally {
                if (literalDataGenerator != null) {
                    literalDataGenerator.close();
                }
                if (in != null) {
                    in.close();
                }
            }
        }
    }




