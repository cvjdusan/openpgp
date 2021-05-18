package etf.openpgp.cd170169;

import org.bouncycastle.openpgp.PGPException;

import javax.swing.*;
import java.awt.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class OpenPGP extends JPanel {

    private JFrame frame;

    public OpenPGP() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {
        initFrame();

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void initFrame() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {
        frame = new JFrame();
        frame.setTitle("openPGP");
        frame.setResizable(false);
        frame.pack();
        frame.setSize(new Dimension(1000, 600));

        KeyHandler k = new KeyHandler();
        k.createKeyRing("dusan", "cvdusan@outlook.com", "123", 1024, false);

    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    new OpenPGP();
                } catch (NoSuchAlgorithmException | PGPException | NoSuchProviderException e) {
                    e.printStackTrace();
                }
            }
        });

    }
}
