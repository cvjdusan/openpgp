package etf.openpgp.cd170169d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Glavna klasa aplikacije
 */

public class OpenPGP {
    private PGPHandler keyHandler;

    private JFrame frame;
    private JTabbedPane tabbedPane;
    private JPanel panelShowKeys, panelGenerateKeys, panelMessage;

    private JTable publicTable, privateTable;
    private KeyTableModel publicModel, privateModel;

    // JList za izbor javnih kljuceva kod slanja poruka
    private JList listPublic;
    private JComboBox listPrivate;

    public OpenPGP() throws Exception {
        keyHandler = new PGPHandler();
        initFrame();
        refreshAllTables(); // Prvi put, ako ima kljuceva u folderima
    }

    /**
     * Metoda koja inicijalizuje glavni frejm aplikacije
     *
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    private void initFrame() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException, IOException {
        frame = new JFrame();
        frame.setTitle("openPGP");

        initPanels();
        frame.add(tabbedPane);

        frame.setResizable(false);
        frame.pack();
        frame.setSize(new Dimension(1000, 600));
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.dispose();
            }
        });

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    /**
     * Metoda koja dodaje glavne panele frejmu
     *
     * @throws IOException
     */

    private void initPanels() throws IOException {
        tabbedPane = new JTabbedPane();

        initPanelGenerateKeys();
        initPanelShowKeys();
        initPanelMessage();

        tabbedPane.add(panelShowKeys, "Prikaz kljuceva");
        tabbedPane.add(panelGenerateKeys, "Generisanje kljuceva");
        tabbedPane.add(panelMessage, "Poruke");
    }

    /**
     * Metoda koja inicijalizuje panel za slanje i prijem poruka
     *
     * @throws IOException
     */
    private void initPanelMessage() throws IOException {
        panelMessage = new JPanel(new BorderLayout());
        JPanel north = new JPanel(new FlowLayout());
        JPanel center = new JPanel(new BorderLayout());


        JButton receive = new JButton("Prijem");
        JButton send = new JButton("Slanje");
        JButton enterMsg = new JButton("Izaberi fajl");

        JCheckBox enc = new JCheckBox("Enkripcija");
        enc.setBounds(100,100, 50,50);
        JCheckBox sign = new JCheckBox("Potpis");
        sign.setBounds(100,150, 50,50);
        JCheckBox comp = new JCheckBox("Kompresija");
        comp.setBounds(100,100, 50,50);
        JCheckBox radix64 = new JCheckBox("Radix64");
        radix64.setBounds(100,150, 50,50);

        StringBuilder msg = new StringBuilder();
        enterMsg.addActionListener(l -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Specify a file...");
            int userSelection = chooser.showSaveDialog(frame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                String withExtension = chooser.getSelectedFile().getAbsolutePath(); //+ ".asc";
                FileInputStream file = null;
                try {
                    file = new FileInputStream(withExtension);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }
                Scanner myReader = new Scanner(file);
                while (myReader.hasNextLine()) {
                    String data = myReader.nextLine();
                    msg.append(data + "\n");
                   // System.out.println(data);
                }
                myReader.close();
                try {
                    file.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                JOptionPane.showMessageDialog(frame, msg);
            }
        });


        JPanel encPanel = new JPanel(new FlowLayout());
        encPanel.add(new JLabel("Izaberite parametre enkripcije: "));
        encPanel.setVisible(false);

        listPublic = new JList();
        listPublic.setVisibleRowCount(5);
        JScrollPane scrollPane = new JScrollPane(listPublic);

        enc.addChangeListener(arg0 -> {
            encPanel.setVisible(enc.isSelected());
            if (enc.isSelected()) {
                scrollPane.repaint();
                scrollPane.revalidate();
            }
        });

        String[] listString1 = { "3DES", "AES128"};
        JComboBox algList = new JComboBox(listString1);
      //  firstList.setPreferredSize(new Dimension(40, 40));
        algList.setSelectedIndex(0);
        final int[] alg = new int[1];
        algList.addActionListener(e -> alg[0] = algList.getSelectedIndex());
        alg[0] = algList.getSelectedIndex();
        encPanel.add(algList);
        encPanel.add(scrollPane);

        JPanel signPanel = new JPanel(new FlowLayout());
        signPanel.add(new JLabel("Izaberite parametre potpisivanja: "));

        listPrivate = new JComboBox();
      //  listPrivate.setSelectedIndex(0);
        final int[] op2 = new int[1];
        listPrivate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                op2[0] = listPrivate.getSelectedIndex();
            }
        });

        signPanel.add(listPrivate);
        JTextField passw = new JTextField();
        signPanel.add(new JLabel("Sifra: "));
        passw.setPreferredSize(new Dimension(100, 30));
        signPanel.add(passw);
        signPanel.setVisible(false);
        sign.addChangeListener(arg0 ->
        {
            signPanel.setVisible(sign.isSelected());
        });

        north.add(enterMsg);
        north.add(enc);
        north.add(sign);
        north.add(comp);
        north.add(radix64);
        north.add(send);

        encPanel.setBorder(new EmptyBorder(50, 10, 10, 10));
        signPanel.setBorder(new EmptyBorder(10, 10, 150, 10));
        center.add(encPanel, BorderLayout.NORTH);
        center.add(signPanel, BorderLayout.SOUTH);

        send.addActionListener(l -> {
            PGPSecretKeyRing s = null;
            ArrayList<PGPPublicKeyRing> list = new ArrayList<>();
            String password = "";
            boolean err = false;
            if(enc.isSelected()) {
                if(listPublic.isSelectionEmpty()) {
                    showMessage("Niste odabrali kljuceve za enk");
                    err = true;
                }
                else {
                    ArrayList<String> lis = (ArrayList<String>) listPublic.getSelectedValuesList();
                    lis.forEach(elem -> {
                        //showMessage(elem.split(" ")[2]
                        String id = elem.split(" ")[2];
                        try {
                            list.add(keyHandler.getPublicKeyRing(publicModel.getKeyLongId(id)));
                        } catch (PGPException e) {
                            e.printStackTrace();
                        }
                    });
                }
            }

            if(sign.isSelected()){
                String id = listPrivate.getSelectedItem().toString().split(" ")[2];
                try {
                    s = keyHandler.getPrivateKeyRing(privateModel.getKeyLongId(id));
                } catch (PGPException e) {
                    e.printStackTrace();
                }
                password = passw.getText();
                if(password.equals("")) {
                    err = true;
                    showMessage("Sifra ne sme biti prazna.");
                }
                // s = listPrivate.
            }

            if(err == false) {
                JFileChooser chooser2 = new JFileChooser();
                chooser2.setDialogTitle("Specify a file...");
                int userSelection = chooser2.showSaveDialog(frame);
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    String withExtension = chooser2.getSelectedFile().getAbsolutePath() + ".pgp";
                    try {
                        FileOutputStream file = new FileOutputStream(withExtension);

                            keyHandler.sendMessage(msg.toString(), enc.isSelected(), sign.isSelected(), comp.isSelected(), radix64.isSelected(), alg[0], password, file,
                                    s, list);


                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                        showMessage(e.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                        showMessage(e.getMessage());
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        showMessage(e.getMessage());
                    } catch (SignatureException e) {
                        e.printStackTrace();
                        showMessage(e.getMessage());
                    } catch (PGPException e) {
                        e.printStackTrace();
                        showMessage(e.getMessage());
                    }
                }
            }
        });


        north.add(receive);
        receive.addActionListener(l -> {
            JFileChooser chooser3 = new JFileChooser();
            chooser3.setDialogTitle("Specify a file...");
            int userSelection = chooser3.showSaveDialog(frame);
            if (userSelection == JFileChooser.APPROVE_OPTION){
                File f = new File(chooser3.getSelectedFile().getAbsolutePath());
                try {
                    Message m = keyHandler.receive(f);
                    showSaveFilePane(m);
                } catch (IOException e) {
                    showMessage(e.getMessage());
                //   e.printStackTrace();
                } catch (PGPException e) {
                    showMessage(e.getMessage());
                 //   e.printStackTrace();
                }
            }
        });


        panelMessage.add(north, BorderLayout.NORTH);
        panelMessage.add(center, BorderLayout.CENTER);
   }

    /**
     * Metoda koja nudi opciju za prikaz i cuvanje poruke
     *
     * @param m
     * @throws IOException
     */

    private void showSaveFilePane(Message m) throws IOException {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel label = new JLabel();
        JLabel ver = new JLabel();


//        label.setText("<html> Potpis: " + (m.sign == true ? "Ima" : "Nije potpisana") + "<br/> " +
//                "Invalidni kljucevi: " + m.keysNotFound.toString() + "<br/>" + "Validna poruka: " + m.isVerified + "<br/></html>");

        label.setText("<html> Potpis: " + (m.sign ? "Postoji" : "Nije potpisana") + "<br/> " +
              //  "Sim algoritam:" + codeToString(m.alg) +
                "<br/>" + "Validna poruka: " + m.isVerified + "<br/></html>");

        ver.setText("Validan potpis od: " + m.verifiers.toString());

        panel.add(label, BorderLayout.NORTH);
        panel.add(ver, BorderLayout.SOUTH);
        String[] options = new String[]{"Sacuvaj", "Cancel"};
        int option = JOptionPane.showOptionDialog(null, panel, "The title",
                JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                null, options, options[1]);

        if(option == 0){
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Specify a file to save");

            int userSelection = chooser.showSaveDialog(frame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                String withExtension = chooser.getSelectedFile().getAbsolutePath() + ".txt";
                FileOutputStream file = new FileOutputStream( withExtension );
                file.write(m.msg.getBytes());
                file.close();
                showMessage("Uspeh.");
            }
        }
    }

    /**
     * Metoda koja inicijalizuje panel koji prikazuje kljuceve
     *
     */

    private void initPanelShowKeys() {
        JPanel p1 = new JPanel(new BorderLayout(5,5));
        JPanel p2 = new JPanel(new BorderLayout(5,5));
        JPanel south = new JPanel(new FlowLayout());
        panelShowKeys = new JPanel(new BorderLayout());

        publicModel = new KeyTableModel();
        privateModel = new KeyTableModel();

        publicTable = new JTable();
        privateTable = new JTable();

        createPopupMenu();

        publicTable.setModel(publicModel);
        privateTable.setModel(privateModel);

        JScrollPane sp1 = new JScrollPane(publicTable);
        JScrollPane sp2 = new JScrollPane(privateTable);

        p1.add(sp1, BorderLayout.CENTER);
        p1.add(new JLabel("Javni", JLabel.CENTER), BorderLayout.NORTH);
        p2.add(sp2, BorderLayout.CENTER);
        p2.add(new JLabel("Privatni", JLabel.CENTER), BorderLayout.NORTH);

        JButton imp = new JButton("Uvezi kljuc");

        imp.addActionListener(click -> {
            try {
                importKeyRing();
                refreshAllTables();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        south.add(imp);
        panelShowKeys.add(p1, BorderLayout.WEST);
        panelShowKeys.add(p2, BorderLayout.EAST);
        panelShowKeys.add(south, BorderLayout.SOUTH);
//        tabbedPane.addChangeListener(new ChangeListener() {
//            public void stateChanged(ChangeEvent e) {
//                if(tabbedPane.getSelectedIndex() == 0) {
//                    try {
//                        getAndShowKeys(panelGridKeys);
//                    } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
//                        noSuchAlgorithmException.printStackTrace();
//                    } catch (PGPException pgpException) {
//                        pgpException.printStackTrace();
//                    } catch (NoSuchProviderException noSuchProviderException) {
//                        noSuchProviderException.printStackTrace();
//                    }
//                }
//            }
//        });
    }

    /**
     * Pomocna metoda koja se koristi za prikaz kljuceva
     *
     */

    private void createPopupMenu(){
        final JPopupMenu popupMenuPublic = new JPopupMenu();
        final JPopupMenu popupMenuPrivate = new JPopupMenu();

        JMenuItem deleteItem = new JMenuItem("Obrisi");
        JMenuItem exportItem = new JMenuItem("Eksportuj");

        popupMenuPublic.add(deleteItem);
        popupMenuPublic.add(exportItem);
        publicTable.setComponentPopupMenu(popupMenuPublic);

        setPopupMenuListeners(popupMenuPublic, publicTable, publicModel);
        setPopupMenuListeners(popupMenuPrivate, privateTable, privateModel);

        deleteItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String id = publicTable.getValueAt(publicTable.getSelectedRow(), 2).toString();
                deleteAndRefreshPublic(id);
            }
        });

        exportItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String id = publicTable.getValueAt(publicTable.getSelectedRow(), 2).toString();
                try {
                    exportPublicKey(id);
                } catch (IOException | PGPException ioException) {
                    ioException.printStackTrace();
                }
            }
        });

        JMenuItem deleteItem1 = new JMenuItem("Obrisi");
        JMenuItem exportItem1 = new JMenuItem("Eksportuj");

        deleteItem1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String id = privateTable.getValueAt(privateTable.getSelectedRow(), 2).toString();
                JPanel panel = new JPanel();
                JLabel label = new JLabel("Unesite lozinku:");
                JPasswordField pass = new JPasswordField(10);
                panel.add(label);
                panel.add(pass);
                String[] options = new String[]{"OK", "Cancel"};
                int option = JOptionPane.showOptionDialog(null, panel, "The title",
                        JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                        null, options, options[1]);
                if(option == 0) {
                    char[] password = pass.getPassword();
                    deleteAndRefreshPrivate(String.valueOf(password),id);
                }
            }
        });

        exportItem1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String id = privateTable.getValueAt(privateTable.getSelectedRow(), 2).toString();
                try {
                    exportPrivateKey(id);
                } catch (IOException | PGPException ioException) {
                    ioException.printStackTrace();
                }
            }
        });

        popupMenuPrivate.add(deleteItem1);
        popupMenuPrivate.add(exportItem1);
        privateTable.setComponentPopupMenu(popupMenuPrivate);
    }

    /**
     * Opcija za uvoz kljuca
     *
     * @throws Exception
     */

    private void importKeyRing() throws Exception {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Specify a file to save");

        int userSelection = chooser.showSaveDialog(frame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
//            String fingerprint = Hex.toHexString(publicKeyRing.getPublicKey().getFingerprint()).toUpperCase();
            String withExtension = chooser.getSelectedFile().getAbsolutePath(); //+ ".asc";
            FileInputStream file = new FileInputStream(withExtension);
            keyHandler.decryptKeyFromFile(file);
            file.close();
            showMessage("Uspeh.");
        }
    }

    /**
     * Eksportovanje iz tabele sa javnim kljucevima
     *
     * @param id
     * @throws IOException
     * @throws PGPException
     */

    private void exportPublicKey(String id) throws IOException, PGPException {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Specify a file to save");

        // TODO: create and change KeyTableModel getKeyRing()?
        PGPPublicKeyRing publicKeyRing = keyHandler.getPublicKeyRing(publicModel.getKeyLongId(id));

        int userSelection = chooser.showSaveDialog(frame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
//            String fingerprint = Hex.toHexString(publicKeyRing.getPublicKey().getFingerprint()).toUpperCase();
            String withExtension = chooser.getSelectedFile().getAbsolutePath() + ".asc";
            FileOutputStream file = new FileOutputStream( withExtension );
            ArmoredOutputStream output = new ArmoredOutputStream(file);
            publicKeyRing.encode(output);
            output.close();
            file.close();
            showMessage("Uspeh.");
        }
    }

    /**
     * Eksportovanje iz tabele sa privatnim kljucevima
     *
     * @param id
     * @throws IOException
     * @throws PGPException
     */

    private void exportPrivateKey(String id) throws IOException, PGPException {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Specify a file to save");

        PGPSecretKeyRing privateKeyRing = keyHandler.getPrivateKeyRing(privateModel.getKeyLongId(id));

        int userSelection = chooser.showSaveDialog(frame);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
//            String fingerprint = Hex.toHexString(publicKeyRing.getPublicKey().getFingerprint()).toUpperCase();
            String withExtension = chooser.getSelectedFile().getAbsolutePath() + ".asc";
            FileOutputStream file = new FileOutputStream( withExtension );
            ArmoredOutputStream output = new ArmoredOutputStream(file);
            privateKeyRing.encode(output);
            output.close();
            file.close();
            showMessage("Uspeh.");
        }
    }

    /**
     * Brisanje kljuca i refresh public tabele
     *
     * @param id
     */

    private void deleteAndRefreshPublic(String id) {
        try {
            keyHandler.deletePublicKey(publicModel.getKeyLongId(id));
        } catch (PGPException pgpException) {
            pgpException.printStackTrace();
        }
        publicModel.deleteKey(id);
        refreshPublicTable();

        publicTable.repaint();
        publicTable.revalidate();
    }

    /**
     * Brisanje kljuca uz proveru sifre i refresh privatne  tabele
     *
     * @param password
     * @param id
     */

    private void deleteAndRefreshPrivate(String password, String id) {
        try {
            keyHandler.deletePrivateKey(password, privateModel.getKeyLongId(id));
        } catch (PGPException pgpException) {
            showMessage("Pogresna sifra!");
            //pgpException.printStackTrace();
        }
        privateModel.deleteKey(id);
        refreshPrivateTable();

        privateTable.repaint();
        privateTable.revalidate();
    }

    /**
     * Pomocna metoda za inicijalizaciju listenera menija
     *
     * @param popupMenu
     * @param table
     * @param tableModel
     */

    private void setPopupMenuListeners(JPopupMenu popupMenu, JTable table, KeyTableModel tableModel){

        popupMenu.addPopupMenuListener(new PopupMenuListener() {

            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        int rowAtPoint = table.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), table));
                        if (rowAtPoint > -1) {
                            table.setRowSelectionInterval(rowAtPoint, rowAtPoint);
                        }
                    }
                });
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                // TODO Auto-generated method stub

            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // TODO Auto-generated method stub

            }
        });
    }

    /**
     * Inicijalizaja panela za generisanje kljuceva
     *
     */

    private final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);

    private boolean validateMail(String emailStr) {
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        return matcher.find();
    }

    private String codeToString(int alg) {
        String algS = "Nepoznat za ovu aplikaciju.";

        if(alg == 1)
            algS = "IDEA";
        else if(alg == 2)
            algS = "3DES";
        else if(alg == 3)
            algS = "CAST5";
        else if(alg == 7)
            algS = "AES128";
        else if(alg == 0){
            algS = "Nema";
        }

        return algS;
    }

    private void initPanelGenerateKeys(){

        panelGenerateKeys = new JPanel(new BorderLayout());

        JTextField name = new JTextField();
        JTextField email = new JTextField();
        JPasswordField password = new JPasswordField();

        JPanel panel = new JPanel();
        panel.setBorder(new EmptyBorder(100,0,0,0));
        JPanel panel1 = new JPanel(new GridLayout(0, 2, 10, 10));
        panel1.setPreferredSize( new Dimension(400, 150) );

        JLabel label = new JLabel("Ime");
        panel1.add(label);
        panel1.add(name);

        label = new JLabel("Email");
        panel1.add(label);
        panel1.add(email);

        label = new JLabel("Lozinka");
        panel1.add(label);
        panel1.add(password);

        label = new JLabel("Velicina kljuca");
        panel1.add(label);

        String[] listString1 = { "1024", "2048", "4096"};
        JComboBox firstList = new JComboBox(listString1);
        firstList.setSelectedIndex(0);
        panel1.add(firstList);

        final int[] op1 = new int[1];

        firstList.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                op1[0] = firstList.getSelectedIndex();
            }
        });

        op1[0] = firstList.getSelectedIndex();

        JButton button = new JButton("Generisi");
        button.setPreferredSize(new Dimension(100, 50));
        panel1.add(new JLabel());
        panel1.add(button);

        button.addActionListener(e -> {
            try {
                if(!name.getText().equals("") && !email.getText().equals("") && password.getPassword().length != 0
                && validateMail(email.getText())){
                    keyHandler.createKeyRing(name.getText(), email.getText(), String.valueOf(password.getPassword()),
                            Integer.parseInt(listString1[op1[0]]), true);
                    refreshAllTables();
                    showMessage("Uspeh.");
                } else {
                    showMessage("Greska. Polja nisu validna.");
                }
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                noSuchAlgorithmException.printStackTrace();
            } catch (PGPException pgpException) {
                pgpException.printStackTrace();
            } catch (NoSuchProviderException noSuchProviderException) {
                noSuchProviderException.printStackTrace();
            }
        });

        panel.add(panel1);
        panelGenerateKeys.add(panel, BorderLayout.CENTER);
    }

    /**
     * Prikaz poruke korisniku
     *
     * @param msg
     */

    public void showMessage(String msg){
        JOptionPane.showMessageDialog(null, msg);
    }

    /**
     * Pomocne metode za refresovanje tabela
     *
     */

    public void refreshAllTables(){
        refreshPublicTable();
        refreshPrivateTable();
    }

    public void refreshPublicTable(){
        KeyTableModel modelPublic = (KeyTableModel) publicTable.getModel();
        modelPublic.clearList();

        PGPPublicKeyRingCollection pc = keyHandler.getPgpPublicKeyRings();
        DefaultListModel model = new DefaultListModel();

        pc.forEach(p -> {
            Key k = createKeyPublic(p);
            modelPublic.add(k);
            model.addElement(k.getName() + " " + k.getEmail() + " " + k.getId());
        });


        listPublic.setModel(model);
    }

    public void refreshPrivateTable(){
        KeyTableModel modelPrivate = (KeyTableModel) privateTable.getModel();
        modelPrivate.clearList();
        ArrayList<String> list = new ArrayList<>();

        PGPSecretKeyRingCollection pc = keyHandler.getPgpSecretKeyRings();
        pc.forEach(p -> {
            Key k = createKeySecret(p);
            modelPrivate.add(k);
            list.add(k.getName() + " " + k.getEmail() + " " + k.getId());
        });

        listPrivate.setModel(new DefaultComboBoxModel(list.toArray()));
    }

    /**
     * Kreiranje kljuca koji ce se ubaciti u odgorajuci ring
     *
     * @param p
     * @return
     */

    public Key createKeyPublic(PGPPublicKeyRing p){
        String[] temp = p.getPublicKey().getUserIDs().next().split(" ");
        String name = temp[0];
        String email = temp[1];
        String keyId = Long.toHexString(p.getPublicKey().getKeyID()).toUpperCase();
        return new Key(name, email, keyId, p);
    }

    public Key createKeySecret(PGPSecretKeyRing p){
        String[] temp = p.getSecretKey().getUserIDs().next().split(" ");
        String name = temp[0];
        String email = temp[1];
        String keyId = Long.toHexString(p.getSecretKey().getKeyID()).toUpperCase();
        return new Key(name, email, keyId, p);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    new OpenPGP();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

    }
}
