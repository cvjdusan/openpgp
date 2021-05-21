package etf.openpgp.cd170169d;

import org.bouncycastle.openpgp.PGPException;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
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

        // Column Names


        // Initializing the JTable

        publicModel = new KeyTableModel();
        privateModel = new KeyTableModel();

        publicTable = new JTable();
        privateTable = new JTable();

        publicTable.setModel(publicModel);
        privateTable.setModel(privateModel);

     //   j.setTableHeader(new JTableHeader());
       // j2.setTableHeader(new JTableHeader());
        JScrollPane sp1 = new JScrollPane(publicTable);
        JScrollPane sp2 = new JScrollPane(privateTable);

        p1.add(sp1, BorderLayout.CENTER);
        p1.add(new JLabel("Javni", JLabel.CENTER), BorderLayout.NORTH);
        p2.add(sp2, BorderLayout.CENTER);
        p2.add(new JLabel("Privatni", JLabel.CENTER), BorderLayout.NORTH);

        JButton imp = new JButton("Uvezi kljuc");

        imp.addActionListener(click -> {
            KeyTableModel model = (KeyTableModel) publicTable.getModel();
            model.refresh();
           // publicModel.addRow(new String[]{"Dusa", "lele", "mika"});
           // publicModel.fireTableDataChanged();
        });


        south.add(imp);
        panelShowKeys.add(p1, BorderLayout.WEST);
        panelShowKeys.add(p2, BorderLayout.EAST);
        panelShowKeys.add(south, BorderLayout.SOUTH);


     //   panelGridKeys.setAutoscrolls(true);

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

    private void getAndShowKeys(JPanel panelGridKeys) throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {




        //        PGPPublicKeyRingCollection pc = keyHandler.getPublicKeyRings();
//        pc.forEach(p -> {
//            String[] temp = p.getPublicKey().getUserIDs().next().split(" ");
//            String name = temp[0];
//            String email = temp[1];
//            String keyId = Long.toHexString(p.getPublicKey().getKeyID()).toUpperCase();
//            JLabel l = new JLabel(name + " " + email + "" + keyId);
//            JCheckBox c = new JCheckBox();
//            panelGridKeys.add(l);
//            panelGridKeys.add(c);
//        });

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
