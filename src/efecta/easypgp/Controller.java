package efecta.easypgp;

import efecta.easypgp.Crypt.Encryption;
import efecta.easypgp.Crypt.Decryption;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;

public class Controller {
    @FXML
    private AnchorPane primaryPane;
    @FXML
    private Pane topmostPane;
    @FXML
    private Button btnClose, btnMin, btnEncrypt, btnDecrypt;
    @FXML
    private TextArea encryptMessage, publicKey, encryptedMessage, decryptMessage, privateKey, decryptedMessage;
    @FXML
    private PasswordField passwordField;

    private double xOffset, yOffset; // window dragging

    @FXML
    private void initialize() {

        topmostPane.setOnMousePressed(event -> {
            xOffset = event.getSceneX();
            yOffset = event.getSceneY();
        });
        topmostPane.setOnMouseDragged(event -> {
            primaryPane.getScene().getWindow().setX(event.getScreenX() - xOffset);
            primaryPane.getScene().getWindow().setY(event.getScreenY() - yOffset);
        });

        btnClose.setOnMouseClicked(event ->
                Main.primaryStage.close());

        btnMin.setOnMouseClicked(event ->
            Main.primaryStage.setIconified(true));

        encryptedMessage.setEditable(false);
        decryptedMessage.setEditable(false);

        btnEncrypt.setOnMousePressed(event -> {
            PGPPublicKey key;

            try {
                key = Encryption.readPublicKey(new ByteArrayInputStream(publicKey.getText().getBytes(StandardCharsets.UTF_8)));
            } catch (IOException | PGPException e) {
                throw new IllegalArgumentException("Error reading encryption key.");
            }

            try {
                // writes the content from encryptMessage to a temporary file
                File outputFile = File.createTempFile("tmp", null);
                FileWriter outWriter = new FileWriter(outputFile);
                outWriter.write(encryptMessage.getText().toCharArray());
                outWriter.close();

                // new file to save the encrypted content
                File encryptedFile = File.createTempFile("tmp", null);
                FileOutputStream out = new FileOutputStream(encryptedFile);

                Encryption.encryptFile(out, outputFile.getAbsolutePath(), key, true);
                out.close();

                encryptedMessage.setText(new String(Files.readAllBytes(Paths.get(encryptedFile.getAbsolutePath()))));

                // remove the files content before deleting them
                new PrintWriter(outputFile.getAbsolutePath()).close();
                new PrintWriter(encryptedFile.getAbsolutePath()).close();
                outputFile.delete();
                encryptedFile.delete();

            } catch (IOException | NoSuchProviderException | PGPException e) {
                throw new IllegalArgumentException("Error encrypting the message.");
            }



        });

        btnDecrypt.setOnMousePressed(event -> {
            try {
                // read the input fields
                InputStream in = new ByteArrayInputStream(decryptMessage.getText().getBytes(StandardCharsets.UTF_8));
                InputStream keyIn = new ByteArrayInputStream(privateKey.getText().getBytes(StandardCharsets.UTF_8));

                // outputstream to store the decrypted message
                ByteArrayOutputStream out = new ByteArrayOutputStream();

                Decryption.decryptFile(in, out, keyIn, passwordField.getText().toCharArray());
                decryptedMessage.setText(out.toString());

                // close the streams
                in.close();
                keyIn.close();
                out.close();
            } catch (Exception e) {
                throw new IllegalArgumentException("Error decrypting the message.");
            }
        });
    }
}