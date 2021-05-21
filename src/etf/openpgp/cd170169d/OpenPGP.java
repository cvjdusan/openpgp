package etf.openpgp.cd170169d;

import org.bouncycastle.openpgp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class OpenPGP {
    private KeyHandler keyHandler;

    private JFrame frame;
    private JTabbedPane tabbedPane;
    private JPanel panelShowKeys, panelGenerateKeys, panelSendMessage;

    private JTable publicTable, privateTable;
    private KeyTableModel publicModel, privateModel;

    public OpenPGP() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException, IOException {
        keyHandler = new KeyHandler();
        initFrame();
    }

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

    private void initPanels(){
        tabbedPane = new JTabbedPane();

        initPanelGenerateKeys();
        initPanelShowKeys();

        tabbedPane.add(panelShowKeys, "Prikaz kljuceva");
        tabbedPane.add(panelGenerateKeys, "Generisanje kljuceva");
        tabbedPane.add(panelSendMessage, "Poruke");
    }

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
                JOptionPane.showMessageDialog(frame,
                        publicTable.getValueAt(publicTable.getSelectedRow(), 0).toString());
            }
        });

        exportItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(frame,
                        publicTable.getValueAt(publicTable.getSelectedRow(), 0).toString() + "EX");
            }
        });

        JMenuItem deleteItem1 = new JMenuItem("Obrisi");
        JMenuItem exportItem1 = new JMenuItem("Eksportuj");

        deleteItem1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(frame,
                        privateTable.getValueAt(privateTable.getSelectedRow(), 0).toString());
            }
        });

        exportItem1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(frame,
                        privateTable.getValueAt(privateTable.getSelectedRow(), 0).toString() + "EX");
            }
        });

        popupMenuPrivate.add(deleteItem1);
        popupMenuPrivate.add(exportItem1);
        privateTable.setComponentPopupMenu(popupMenuPrivate);
    }

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
                if(name.getText().equals("") || email.getText().equals("") || password.getPassword().length == 0){
                   showMessage("Greska. Postoje prazna polja.");
                } else {
                    keyHandler.createKeyRing(name.getText(), email.getText(), String.valueOf(password.getPassword()),
                            Integer.parseInt(listString1[op1[0]]), true);
                    refreshAllTables();
                    showMessage("Uspeh.");
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

    public void showMessage(String msg){
        JOptionPane.showMessageDialog(null, msg);
    }

    public void refreshAllTables(){
        refreshPublicTable();
        refreshPrivateTable();
    }

    public void refreshPublicTable(){
        KeyTableModel modelPublic = (KeyTableModel) publicTable.getModel();
        modelPublic.clearList();

        PGPPublicKeyRingCollection pc = keyHandler.getPublicKeyRings();
        pc.forEach(p -> {
            Key k = createKeyPublic(p);
            modelPublic.add(k);
        });
    }

    public void refreshPrivateTable(){
        KeyTableModel modelPrivate = (KeyTableModel) privateTable.getModel();
        modelPrivate.clearList();

        PGPSecretKeyRingCollection pc = keyHandler.getSecretKeyRings();
        pc.forEach(p -> {
            Key k = createKeySecret(p);
            modelPrivate.add(k);
        });

    }

    public Key createKeyPublic(PGPPublicKeyRing p){
        String[] temp = p.getPublicKey().getUserIDs().next().split(" ");
        String name = temp[0];
        String email = temp[1];
        String keyId = Long.toHexString(p.getPublicKey().getKeyID()).toUpperCase();
        return new Key(name, email, keyId);
    }

    public Key createKeySecret(PGPSecretKeyRing p){
        String[] temp = p.getSecretKey().getUserIDs().next().split(" ");
        String name = temp[0];
        String email = temp[1];
        String keyId = Long.toHexString(p.getSecretKey().getKeyID()).toUpperCase();
        return new Key(name, email, keyId);
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    new OpenPGP();
                } catch (NoSuchAlgorithmException | PGPException | NoSuchProviderException | IOException e) {
                    e.printStackTrace();
                }
            }
        });

    }
}
