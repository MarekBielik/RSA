import exceptions.RSAException;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.util.Scanner;

/**
 * Created by marek on 3/11/16.
 */
public class MainWindow {
    private JButton OKButton;
    private JPanel panel1;
    private JButton saveKeyPairButton;
    private JButton loadPublicKeyButton;
    private JButton loadPrivateKeyButton;
    private JButton encryptFileButton;
    private JButton decryptFileButton;
    private JLabel pubKeyNLabel;
    private JLabel pubKeyELabel;
    private JLabel privKeyELabel;
    private JTextField chunkSizeTextField;
    private JLabel chunkSizeLabel;

    public MainWindow() {
        prepareGui();
        OKButton.addActionListener(new KeyGenButtonListener());
        saveKeyPairButton.addActionListener(new SaveKeyPairButtonListener());
        loadPublicKeyButton.addActionListener(new LoadPublicKeyButtonListener());
        loadPrivateKeyButton.addActionListener(new LoadPrivateKeyButtonListener());
        encryptFileButton.addActionListener(new EncryptFileButtonListener());
        decryptFileButton.addActionListener(new DecryptFileButtonListener());
    }

    public void prepareGui() {
        JFrame frame = new JFrame("RSA");
        frame.setContentPane(panel1);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }


    private class KeyGenButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            Main.rsa.createKeyPair();
            try {
                pubKeyNLabel.setText("modulus N: " + Main.rsa.getN());
                pubKeyELabel.setText("public exponent: " + Main.rsa.getE());
                privKeyELabel.setText("private exponent:" + Main.rsa.getD());
            } catch (RSAException ex) {
                JOptionPane.showMessageDialog(null, ex.geteMessage());
            }
        }
    }

    private class SaveKeyPairButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(new java.io.File("."));
            chooser.setDialogTitle("Save the key pair");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);

            if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                try (FileWriter pubFile = new FileWriter(chooser.getSelectedFile() + "/publicKey.txt");
                     FileWriter privFile = new FileWriter(chooser.getSelectedFile() + "/privateKey.txt")) {
                    try {
                        pubFile.write(Main.rsa.getN() + "\n");
                        pubFile.write(Main.rsa.getE());

                        privFile.write(Main.rsa.getN() + "\n");
                        privFile.write(Main.rsa.getD());
                    } catch (RSAException ex) {
                        JOptionPane.showMessageDialog(null, ex.geteMessage());
                    }

                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, ex.getMessage());
                }
            }
        }
    }

    private class LoadPublicKeyButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(new java.io.File("."));
            chooser.setDialogTitle("Load the the public key");

            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try (Scanner input = new Scanner(new FileReader(chooser.getSelectedFile()))) {
                    Main.rsa.setN(input.nextBigInteger());
                    Main.rsa.setE(input.nextBigInteger());
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, ex.getMessage());
                }

                try {
                    pubKeyNLabel.setText("modulus N: " + Main.rsa.getN());
                    pubKeyELabel.setText("public exponent: " + Main.rsa.getE());
                } catch (RSAException ex) {
                    JOptionPane.showMessageDialog(null, ex.geteMessage());
                }
            }
        }
    }

    private class LoadPrivateKeyButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(new java.io.File("."));
            chooser.setDialogTitle("Load the the private key");

            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try (Scanner input = new Scanner(new FileReader(chooser.getSelectedFile()))) {
                    Main.rsa.setN(input.nextBigInteger());
                    Main.rsa.setD(input.nextBigInteger());
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, ex.getMessage());
                }

                try {
                    pubKeyNLabel.setText("modulus N: " + Main.rsa.getN());
                    privKeyELabel.setText("private exponent:" + Main.rsa.getD());
                } catch (RSAException ex) {
                    JOptionPane.showMessageDialog(null, ex.geteMessage());
                }
            }
        }
    }

    private class EncryptFileButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(new java.io.File("."));
            chooser.setDialogTitle("File to encrypt");

            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try (OutputStream outputStream = new FileOutputStream(
                        chooser.getSelectedFile().getPath() + "Encrypted")) {

                    //get the chunk size from the user
                    int chunkSize = Integer.valueOf(chunkSizeTextField.getText());
                    if (chunkSize < Main.rsa.getMinChunkSize() ||
                            chunkSize > Main.rsa.getMaxChunkSize()) {
                        JOptionPane.showMessageDialog(null, "Wrong chunk size");
                        return;
                    }

                    Main.rsa.setChunkSize(chunkSize);
                    byte[] inputData = Files.readAllBytes(chooser.getSelectedFile().toPath());
                    ByteArrayOutputStream outputData = Main.rsa.encryptFile(inputData);
                    outputData.writeTo(outputStream);

                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, ex.getMessage());
                } catch (RSAException rsaE) {
                    JOptionPane.showMessageDialog(null, rsaE.geteMessage());
                } catch (NumberFormatException chunkE) {
                    JOptionPane.showMessageDialog(null, "Wrong chunk size " + chunkE.getMessage());
                }
            }
        }
    }

    private class DecryptFileButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(new java.io.File("."));
            chooser.setDialogTitle("File to decrypt");

            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try (OutputStream outputStream = new FileOutputStream(
                             chooser.getSelectedFile().getPath() + "Decrypted")) {

                    //read the data
                    byte[] inputData = Files.readAllBytes(chooser.getSelectedFile().toPath());

                    //encrypt and write the data
                    Main.rsa.decryptFile(inputData).writeTo(outputStream);

                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, ex.getMessage());
                } catch (RSAException rsaE) {
                    JOptionPane.showMessageDialog(null, rsaE.geteMessage());
                }
            }
        }
    }
}
