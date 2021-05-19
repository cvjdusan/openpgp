package etf.openpgp.cd170169d;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class OpenPGP {

    private JFrame frame;
    private JTabbedPane tabbedPane;
    private JScrollPane panelShowKeys;
    private JPanel panelGenerateKeys;
    private KeyHandler keyHandler;

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
    }

    private void initPanelShowKeys() {
        JPanel panelGridKeys = new JPanel(new GridLayout(0, 2));
        panelShowKeys = new JScrollPane(panelGridKeys);
        panelGridKeys.setAutoscrolls(true);

        tabbedPane.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                if(tabbedPane.getSelectedIndex() == 0) {
                    try {
                        getAndShowKeys(panelGridKeys);
                    } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                        noSuchAlgorithmException.printStackTrace();
                    } catch (PGPException pgpException) {
                        pgpException.printStackTrace();
                    } catch (NoSuchProviderException noSuchProviderException) {
                        noSuchProviderException.printStackTrace();
                    }
                }
            }
        });
    }

    private void getAndShowKeys(JPanel panelGridKeys) throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {
        //keyHandler.createKeyRing("a","a","a", 1024, false);
        PGPPublicKeyRingCollection pc = keyHandler.getPublicKeyRings();
        pc.forEach(p -> {
            String[] temp = p.getPublicKey().getUserIDs().next().split(" ");
            String name = temp[0];
            String email = temp[1];
            String keyId = Long.toHexString(p.getPublicKey().getKeyID()).toUpperCase();
            JLabel l = new JLabel(name + " " + email + "" + keyId);
            JCheckBox c = new JCheckBox();
            panelGridKeys.add(l);
            panelGridKeys.add(c);
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
        firstList.setSelectedIndex(1);
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

        button.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    keyHandler.createKeyRing(name.getText(), email.getText(), password.getText(),
                            Integer.parseInt(listString1[op1[0]]), false);
                } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                    noSuchAlgorithmException.printStackTrace();
                } catch (PGPException pgpException) {
                    pgpException.printStackTrace();
                } catch (NoSuchProviderException noSuchProviderException) {
                    noSuchProviderException.printStackTrace();
                }
            }
        });

        panel.add(panel1);
        panelGenerateKeys.add(panel, BorderLayout.CENTER);
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
