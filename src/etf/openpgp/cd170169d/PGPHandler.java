package etf.openpgp.cd170169d;

import java.awt.*;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.List;


import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.swing.*;
import javax.swing.plaf.basic.BasicComboBoxRenderer;

/**
 * Klasa koja upravlja bouncy castle metodama (kljucevi, enkriptovanje, dekriptovanje)
 *
 */

public class PGPHandler {

    class ItemRenderer extends BasicComboBoxRenderer {
        @Override
        public Component getListCellRendererComponent(JList list, Object value,
                                                      int index, boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected,
                    cellHasFocus);
            if (value != null) {
                Key item = (Key) value;
                setText(" " + item.getEmail() + "" + item.getId());
            }
            if (index == -1) {
                Key item = (Key) value;
                setText(" " + item.getEmail() + "" + item.getId());
            }
            return this;
        }
    }

    private static final String RSA_ALG = "RSA";
    private static final String AES_ALG = "AES";
    private static final String DESede_ALG = "DESede";
    private static final String provider = "BC";
    private static final String stringPublicDir = "src/etf/openpgp/cd170169d/publicKeys/";
    private static final String stringPrivateDir = "src/etf/openpgp/cd170169d/privateKeys/";
    private static final int bufferSize = 16384;

    private PGPPublicKeyRingCollection pgpPublicKeyRings;
    private PGPSecretKeyRingCollection pgpSecretKeyRings;

    public PGPHandler() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        pgpPublicKeyRings = new PGPPublicKeyRingCollection(new ArrayList<>());
        pgpSecretKeyRings = new PGPSecretKeyRingCollection(new ArrayList<>());
        importFromDir();
    }

    /**
     * Importovanje kljuceva iz fajlova prilikom pokrenja aplikacije
     *
     * @throws Exception
     */

    public void importFromDir() throws Exception {
        File pub = new File(stringPublicDir);
        File priv = new File(stringPrivateDir);
        FileInputStream inputStream;

        if (pub.isDirectory() && pub.listFiles() != null) {
            for (final File fileEntry : pub.listFiles()) {
                inputStream = new FileInputStream(fileEntry);
                importKeyFromFiles(inputStream);
                inputStream.close();
            }
        }

        if (priv.isDirectory() && priv.listFiles() != null) {
            for (final File fileEntry : priv.listFiles()) {
                inputStream = new FileInputStream(fileEntry);
                importKeyFromFiles(inputStream);
                inputStream.close();
            }
        }

    }

    /**
     * Kreiranje key ringova
     *
     * @param name
     * @param email
     * @param password
     * @param keySize
     * @param encrypt
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     * @throws NoSuchProviderException
     */

    public void createKeyRing(String name, String email, String password, int keySize, boolean encrypt)
            throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALG, provider);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN, keyPair, new Date());
        PGPDigestCalculator pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        BcPGPContentSignerBuilder keySignerBuilder = new BcPGPContentSignerBuilder(
                pgpKeyPair.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA256);

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

        // za sad uvek true
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
        
        savePublic(publicKeyRing);
        savePrivate(secretKeyRing);
    }

    /**
     * Cuvanje privatnog kljuca u fajl
     *
     * @param ring
     */

    private void savePrivate(PGPSecretKeyRing ring) {
        String name = Hex.toHexString(ring.getPublicKey().getFingerprint()).toUpperCase();
        File file = new File(stringPrivateDir + name + ".asc");
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(file);
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream);
            ring.encode(armoredOutputStream);
            armoredOutputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Cuvanje javnog kljuca u fajl
     *
     * @param ring
     */

    private void savePublic(PGPPublicKeyRing ring) {
        String name = Hex.toHexString(ring.getPublicKey().getFingerprint()).toUpperCase();
        File file = new File(stringPublicDir + name + ".asc");
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(file);
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileOutputStream);
            ring.encode(armoredOutputStream);
            armoredOutputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Dodavanje u listu javnih kljuceva
     *
     * @param publicKeyRing
     */

    public void addToPublicKeyRings(PGPPublicKeyRing publicKeyRing) {
        pgpPublicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPublicKeyRings, publicKeyRing);
    }

    /**
     * Dodavanje u listu privatnih kljuceva
     *
     * @param secretKeyRing
     */

    public void addToPrivateKeyRings(PGPSecretKeyRing secretKeyRing) {
        pgpSecretKeyRings = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRings, secretKeyRing);
    }

    /**
     * Dohvatanje liste javnih kljuceva
     *
     * @return
     */

    public PGPPublicKeyRingCollection getPgpPublicKeyRings() {
        return pgpPublicKeyRings;
    }

    /**
     * Dohvatanje liste privatnih kljuceva
     *
     * @return
     */

    public PGPSecretKeyRingCollection getPgpSecretKeyRings() {
        return pgpSecretKeyRings;
    }

    /**
     * Dohvatanje javnog kljuca na osnovu long id-a
     *
     * @param keyLongId
     * @return
     * @throws PGPException
     */

    public PGPPublicKeyRing getPublicKeyRing(Long keyLongId) throws PGPException {
        return pgpPublicKeyRings.getPublicKeyRing(keyLongId);
    }

    /**
     * Dohvatanje privatnog kljuca na osnovu long id-a
     *
     * @param keyLongId
     * @return
     * @throws PGPException
     */

    public PGPSecretKeyRing getPrivateKeyRing(Long keyLongId) throws PGPException {
        return pgpSecretKeyRings.getSecretKeyRing(keyLongId);
    }

    /**
     * Import jednog kljuca iz fajla
     *
     * @param in
     * @throws Exception
     */

    public void decryptKeyFromFile(InputStream in) throws Exception {
        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));

        Object object = pgpF.nextObject();

        PGPPublicKeyRing publicKeyRing = null;
        PGPSecretKeyRing secretKeyRing = null;

        if (object instanceof PGPPublicKeyRing) {
            publicKeyRing = (PGPPublicKeyRing) object;
        } else {
            secretKeyRing = (PGPSecretKeyRing) object;
        }

        if (publicKeyRing != null) {
            addToPublicKeyRings(publicKeyRing);
        } else if (secretKeyRing != null) {
            addToPrivateKeyRings(secretKeyRing);
        }

    }

    /**
     * Import vise kljuceva iz fajla
     *
     * @param in
     * @throws Exception
     */

    public void importKeyFromFiles(InputStream in) throws Exception{
        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));

        while (true) {
            Object object = pgpF.nextObject();

            if(object == null) break;

            PGPPublicKeyRing publicKeyRing = null;
            PGPSecretKeyRing secretKeyRing = null;

            if (object instanceof PGPPublicKeyRing) {
                publicKeyRing = (PGPPublicKeyRing) object;
            } else {
                secretKeyRing = (PGPSecretKeyRing) object;
            }

            if (publicKeyRing != null) {
                addToPublicKeyRings(publicKeyRing);
            } else if (secretKeyRing != null) {
                addToPrivateKeyRings(secretKeyRing);
            }
        }
    }

    /**
     * Brisanje javnog kljuca
     *
     * @param keyLongId
     * @throws PGPException
     */

    public void deletePublicKey(Long keyLongId) throws PGPException {
        PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRings.getPublicKeyRing(keyLongId);
        pgpPublicKeyRings = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRings, pgpPublicKeyRing);
        String name = Hex.toHexString(pgpPublicKeyRing.getPublicKey().getFingerprint()).toUpperCase();

        File f = new File(stringPublicDir + name + ".asc");
        f.delete();
    }

    /**
     * Brisanje privatnog kljuca
     *
     * @param password
     * @param keyLongId
     * @throws PGPException
     */

    public void deletePrivateKey(String password, Long keyLongId) throws PGPException {
        PGPSecretKeyRing pgpSecretKeyRing = pgpSecretKeyRings.getSecretKeyRing(keyLongId);

        JcePBESecretKeyDecryptorBuilder decryptorBuilder = new JcePBESecretKeyDecryptorBuilder();

        pgpSecretKeyRing.getSecretKey().extractPrivateKey(decryptorBuilder.build(password.toCharArray()));

        pgpSecretKeyRings = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRings, pgpSecretKeyRing);

        String fp = Hex.toHexString(pgpSecretKeyRing.getPublicKey().getFingerprint()).toUpperCase();
        File f = new File(stringPrivateDir + fp + ".asc");
        f.delete();
    }

    /**
     * Primanje poruke i njeno dekriptivanje, dohvatanje potpisa, provere integriteta...
     *
     * @param f
     * @return
     * @throws IOException
     * @throws PGPException
     */

    public Message receive(File f) throws IOException, PGPException {
        byte[] stream = null;

        FileInputStream file = new FileInputStream(f);
        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(file));
        Object object = null;
        String msg = null;


        List<String> verifiers = new ArrayList<>();
        List<Long> invalidKeys = new ArrayList<>();

        boolean verified = true;
        boolean sign = false;

        PGPOnePassSignatureList allSigns = null;

        while(true){

            try {
                object = factory.nextObject();
            } catch (Exception e){
                throw new PGPException("Integritet poruke je narusen");
            }

            System.out.println("RADI");

            if(object == null)
                break;

            // znaci jeste enkriptovana
            if(object instanceof PGPEncryptedDataList){
                System.out.println("USAO U ENCTDATALIST");
                PGPEncryptedDataList encList = (PGPEncryptedDataList) object;
                ArrayList<PGPSecretKeyRing> privateRings = new ArrayList<>();

                // dobijamo sve kljuceve privatne na osnovu poruke
                encList.forEach(l -> {
                    PGPPublicKeyEncryptedData d = (PGPPublicKeyEncryptedData)l;
                    try {
                        PGPSecretKeyRing secretKeyRing = getPrivateKeyRing(d.getKeyID());
                        if(secretKeyRing!=null){
                            privateRings.add(secretKeyRing);
                        }
                    } catch (PGPException e) {
                        e.printStackTrace();
                    }
                });

                if (privateRings.size() != 0) {
                    JPanel panel = new JPanel();
                    JLabel label = new JLabel("Enter a password:");
                    JComboBox<Key> comboBox = new JComboBox<>();
                    JPasswordField pass = new JPasswordField(10);
                    panel.add(label);
                    panel.add(pass);
                    String[] options = new String[]{"OK", "Cancel"};
                    comboBox.removeAllItems();

                    for (PGPSecretKeyRing keyRing : privateRings) {
                        String userID[] = keyRing.getPublicKey().getUserIDs().next().split(" ");
                        String name = userID[0];
                        String email = userID[1];
                        String id = Long.toHexString(keyRing.getPublicKey().getKeyID()).toUpperCase();
                        comboBox.addItem(new Key(name, email, id, keyRing));
                    }

                    comboBox.addActionListener(e -> {
                        JComboBox c = (JComboBox) e.getSource();
                        Key item = (Key) c.getSelectedItem();
                        System.out.println(item.getEmail() + " : " + item.getId());
                    });


                    comboBox.setRenderer(new ItemRenderer());

                    panel.add(comboBox);

                    int option = JOptionPane.showOptionDialog(null, panel, "The title",
                            JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                            null, options, options[1]);

                    if (option == 0) {
                        char[] ps = pass.getPassword();
                        System.out.println("Your password is: " + new String(ps));

                        String password = new String(ps);
                        Key key = (Key) comboBox.getSelectedItem();

                        PGPSecretKeyRing selectedRing = (PGPSecretKeyRing) key.getRing();
                        PGPPublicKeyEncryptedData selectedData = null;
                        
                        long id = selectedRing.getPublicKey().getKeyID();
                        for(int i = 0; i < encList.size(); i++){
                            PGPPublicKeyEncryptedData d = (PGPPublicKeyEncryptedData) encList.get(i);;
                            PGPSecretKeyRing secretKeyRing = getPrivateKeyRing(d.getKeyID());
                            if(id == secretKeyRing.getPublicKey().getKeyID()) {
                                selectedData = d;
                                break;
                            }
                        }
                        
                        Iterator<PGPSecretKey> it = selectedRing.getSecretKeys();

                        PGPSecretKey skip = it.next();

                        if (!it.hasNext())
                            throw new PGPException("Nema subkey za dekripciju!");

                        PGPSecretKey secretKey = it.next();

                        try {
                            PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));
                            InputStream plain = selectedData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
                            factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(plain));

                            if (selectedData.isIntegrityProtected() &&
                                    selectedData.verify() == false) {
                                throw new PGPException("Data integrity check greska!");
                            }

                        } catch (PGPException e) {
                            throw new PGPException("Pogresna sifra!");
                        }

                    }
                } else
                    throw new PGPException("Nije nadjen privatni kljuc.");
            }

            if(object instanceof PGPCompressedData){
                System.out.println("USAO U KOMPR");
                PGPCompressedData c = (PGPCompressedData) object;
                factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(c.getDataStream()));
            }

            if(object instanceof PGPOnePassSignatureList){
                sign = true;
                System.out.println("USAO U ONEPASS");
                allSigns = (PGPOnePassSignatureList) object;
                allSigns.forEach(o -> {
                    long id = o.getKeyID();
                    try {
                        PGPPublicKeyRing publicKeyRing = getPublicKeyRing(id);

                        if(publicKeyRing != null){
                            PGPPublicKey publicKey = publicKeyRing.getPublicKey();
                            o.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                        }
                        else{
                            invalidKeys.add(id);
                        }
                    } catch (PGPException e) {
                        e.printStackTrace();
                    }
                });
            }

            if(object instanceof PGPLiteralData){
                System.out.println("USAO U PGPLITERAL");
                PGPLiteralData literalData = (PGPLiteralData) object;

                InputStream data = literalData.getInputStream();

                stream = new byte[data.available()];

                data.read(stream);

                msg = new String(stream);

                if (allSigns != null) {
                    for (int i = 0; i < allSigns.size(); i++) {
                        PGPOnePassSignature onePassSignature = allSigns.get(i);
                        if (!invalidKeys.contains(onePassSignature.getKeyID()))
                            onePassSignature.update(stream);
                    }
                }
            }

            if (object instanceof PGPSignatureList) {
                System.out.println("USAO U SIGLIST");
                PGPSignatureList signs = (PGPSignatureList) object;

                for (int i = 0; i < signs.size(); i++) {
                    PGPSignature signature = signs.get(i);
                    if (allSigns != null){
                        int position = allSigns.size() - i - 1;
                        PGPOnePassSignature ops = allSigns.get(position);
                        if (invalidKeys.contains(signature.getKeyID()) || !ops.verify(signature)) {
                            verified = false;
                        } else {
                            PGPPublicKeyRing ring = pgpPublicKeyRings.getPublicKeyRing(signature.getKeyID());
                            String username = ring.getPublicKey().getUserIDs().next();
                            verifiers.add(username);
                        }
                    }
                    else {
                        PGPPublicKeyRing publicKeyRing = getPublicKeyRing(signature.getKeyID());
                        if (publicKeyRing == null){
                            throw new PGPException("Nije nadjen javni kljuc");
                        }

                        signature.init(new BcPGPContentVerifierBuilderProvider(), publicKeyRing.getPublicKey());
                        signature.update(stream);

                        if (signature.verify()){
                            PGPPublicKeyRing ring = pgpPublicKeyRings.getPublicKeyRing(publicKeyRing.getPublicKey().getKeyID());
                            String username = ring.getPublicKey().getUserIDs().next();
                            verifiers.add(username);
                        }
                        else{
                            verified = false;
                        }
                    }
                }
            }
        }

        if(!verified)
            throw new PGPException("Potpis nije validan ili nemate javni kljuc!");

        Message pgpMessage = new Message(msg, verifiers, invalidKeys, verified, sign);

        return pgpMessage;
    }

    /**
     * Enkriptovanje streama
     *
     * @param alg
     * @param publicKeys
     * @param stream
     * @return
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     * @throws IOException
     */

    public byte [] encrypt(int alg, List<PGPPublicKeyRing> publicKeys, byte [] stream) throws NoSuchAlgorithmException, PGPException, IOException {

            if(alg == 0) {
                alg = SymmetricKeyAlgorithmTags.TRIPLE_DES;
            }
            else {
                alg = SymmetricKeyAlgorithmTags.AES_128;
            }

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

            JcePGPDataEncryptorBuilder pgpDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(alg)
                    .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom())
                    .setProvider(provider);


            //keyGenarator.generateKey() to je sessionKey
            pgpDataEncryptorBuilder.build(keyGenerator.generateKey().getEncoded());

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(pgpDataEncryptorBuilder);
            for (PGPPublicKeyRing publicKey : publicKeys) {

                Iterator<PGPPublicKey> it = publicKey.getPublicKeys();

                PGPPublicKey skip = it.next();

                if (!it.hasNext())
                    throw new PGPException("Ne moze jer nema RSA subkey.");

                PGPPublicKey subKey = it.next();

                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(subKey));
            }


            ByteArrayOutputStream fileStream = new ByteArrayOutputStream();
            OutputStream outputStream = encryptedDataGenerator.open(fileStream, new byte[bufferSize]);
            outputStream.write(stream);
            outputStream.close();

            stream = fileStream.toByteArray();
            fileStream.close();

            return stream;
    }

    /**
     * Kompresovanje poruke
     *
     * @param stream
     * @return
     * @throws IOException
     */

    public byte[] compress(byte [] stream) throws IOException {
        ByteArrayOutputStream fileStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream fileOutput;

        fileOutput = compressedDataGenerator.open(fileStream);
        fileOutput.write(stream);
        fileOutput.close();

        stream = fileStream.toByteArray();

        fileStream.close();

        return stream;
    }

    /**
     * Potpisivanje poruke
     *
     * @param secretKey
     * @param password
     * @param stream
     * @return
     * @throws PGPException
     * @throws IOException
     */

    private byte [] sign(PGPSecretKeyRing secretKey, String password, byte[] stream) throws PGPException, IOException {

        PGPPrivateKey privateKey = null;


        // privateKey posiljaoca
        try {
            privateKey = secretKey.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));
        } catch (Exception e) {
            throw new PGPException("Pogresna sifra");
        }

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator (new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider(provider));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

        subpacketGenerator.setSignerUserID(false, secretKey.getPublicKey().getUserIDs().next().getBytes());

        signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

        PGPOnePassSignature pgpOnePassSignature = signatureGenerator.generateOnePassVersion(false);

        signatureGenerator.update(stream);

        PGPSignature signature = signatureGenerator.generate();

        ByteArrayOutputStream fileStream = new ByteArrayOutputStream();

        pgpOnePassSignature.encode(fileStream);

        fileStream.write(myWriteToFileLiteralData(stream));

        signature.encode(fileStream);

        stream = fileStream.toByteArray();

        fileStream.close();

        return stream;
    }

    /**
     * Stvaranje literalnog paketa
     *
     * @param stream
     * @return
     * @throws IOException
     */

    public byte[] myWriteToFileLiteralData(byte [] stream) throws IOException {
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        ByteArrayOutputStream fileStream = new ByteArrayOutputStream();
        File tempFile = File.createTempFile("etf/openpgp/cd170169d/pgp", null);
        FileWriter fileWriter = new FileWriter(tempFile);
        fileWriter.write(String.valueOf(stream));
        fileWriter.close();
        OutputStream literalOut = literalDataGenerator.open(fileStream, PGPLiteralDataGenerator.UTF8, tempFile.getName(), new Date(tempFile.lastModified()), new byte[16 * 1024]);
        literalOut.write(stream);
        literalOut.close();
        stream = fileStream.toByteArray();
        fileStream.close();
        return stream;
    }

    /**
     * Slanje poruke i njego potpisivivanje, enkriptovanje, kompresija, radix u zavisnosti od
     * zelje korisnika
     *
     * @param text
     * @param enc
     * @param sign
     * @param comp
     * @param radix
     * @param alg
     * @param password
     * @param file
     * @param secretKey
     * @param publicKeys
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     * @throws IOException
     * @throws SignatureException
     */

    public void sendMessage(String text, boolean enc, boolean sign, boolean comp, boolean radix,
                            int alg, String password, FileOutputStream file, PGPSecretKeyRing secretKey,
                            List<PGPPublicKeyRing> publicKeys) throws NoSuchAlgorithmException, PGPException, IOException, SignatureException {

        byte [] stream = text.getBytes();

        if(sign) {
            stream = sign(secretKey, password, stream);
        } else {
            // writeToFileLiteralData
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            ByteArrayOutputStream fileStream = new ByteArrayOutputStream();
            File tempFile = File.createTempFile("etf/openpgp/cd170169d/pgp", null);
            FileWriter fileWriter = new FileWriter(tempFile);
            fileWriter.write(text.toCharArray());
            fileWriter.close();
            OutputStream literalOut = literalDataGenerator.open(fileStream, PGPLiteralDataGenerator.UTF8, tempFile.getName(), new Date(tempFile.lastModified()), new byte[bufferSize]);
            literalOut.write(stream);
            literalOut.close();
            stream = fileStream.toByteArray();
            fileStream.close();
        }

        if(comp) {
            stream = compress(stream);
        }

        if(enc) {
            stream = encrypt(alg, publicKeys, stream);
        }

        if(radix){
            ByteArrayOutputStream fileStream2 = new ByteArrayOutputStream();
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(fileStream2);
            armoredOutputStream.write(stream);
            armoredOutputStream.close();
            stream = fileStream2.toByteArray();
            fileStream2.close();
        }

        file.write(stream);
        file.close();
    }

}




