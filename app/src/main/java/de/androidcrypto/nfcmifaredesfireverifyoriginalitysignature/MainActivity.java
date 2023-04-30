package de.androidcrypto.nfcmifaredesfireverifyoriginalitysignature;

import static de.androidcrypto.nfcmifaredesfireverifyoriginalitysignature.Utils.base64Decoding;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.NfcA;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    EditText tagId, tagSignature, publicKeyNxp, readResult;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte, tagSignatureByte, publicKeyByte;
    boolean signatureVerified = false;

    // generate this value once for a curve by using createHeadForNamedCurve
    // e.g. secp224r1 length 224 or NIST P-256 length 256
    private static byte[] SECP224R1_HEAD = base64Decoding("ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE"); // this is the header of secp224r1

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tagId = findViewById(R.id.etVerifyTagId);
        tagSignature = findViewById(R.id.etVerifySignature);
        publicKeyNxp = findViewById(R.id.etVerifyPublicKey);
        readResult = findViewById(R.id.etVerifyResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        // ultralight ev1: publicKeyNxp.setText("0490933bdcd6e99b4e255e3da55389a827564e11718e017292faf23226a96614b8"); // Ultralight EV1
        publicKeyNxp.setText("040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D");
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");

        NfcA nfcA = null;

        try {
            nfcA = NfcA.get(tag);
            if (nfcA != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is Nfca compatible",
                            Toast.LENGTH_SHORT).show();
                });

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    readResult.setText("");
                    readResult.setBackgroundColor(getResources().getColor(R.color.white));
                });

                nfcA.connect();

                System.out.println("*** tagId: " + Utils.bytesToHex(tag.getId()));

                // tag ID
                tagIdByte = tag.getId();
                runOnUiThread(() -> {
                    tagId.setText(Utils.bytesToHex(tagIdByte));
                });

                byte[] response = new byte[0];

                try {
                    String commandString = "3C00"; // read signature
                    byte[] commandByte = Utils.hexStringToByteArray(commandString);
                    try {
                        response = nfcA.transceive(commandByte); // response should be 16 bytes = 4 pages
                        if (response == null) {
                            // either communication to the tag was lost or a NACK was received
                            writeToUiAppend(readResult, "ERROR: null response");
                            return;
                        } else if ((response.length == 1) && ((response[0] & 0x00A) != 0x00A)) {
                            // NACK response according to Digital Protocol/T2TOP
                            // Log and return
                            writeToUiAppend(readResult, "ERROR: NACK response: " + Utils.bytesToHex(response));
                            return;
                        } else {
                            // success: response contains (P)ACK or actual data
                            writeToUiAppend(readResult, "SUCCESS: response: " + Utils.bytesToHex(response));
                            //System.out.println("write to page " + page + ": " + bytesToHex(response));
                            tagSignatureByte = response.clone();
                            runOnUiThread(() -> {
                                tagSignature.setText(Utils.bytesToHex(tagSignatureByte));
                            });
                        }
                    } catch (TagLostException e) {
                        // Log and return
                        System.out.println("*** TagLostException");
                        runOnUiThread(() -> {
                            readResult.setText("ERROR: Tag lost exception or command not recognized");
                        });
                        return;
                    } catch (IOException e) {
                        writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
                        System.out.println("*** IOException");
                        e.printStackTrace();
                        return;
                    }
                } finally {
                    try {
                        nfcA.close();
                    } catch (IOException e) {
                        writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
            e.printStackTrace();
        }

        // now we are going to verify


        // get the public key
        String publicKeyString = publicKeyNxp.getText().toString();
        byte[] w = Utils.hexStringToByteArray("1DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743");
        //byte[] w = Utils.hexStringToByteArray("8A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410");
        //byte[] w = Utils.hexStringToByteArray("1DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743"); // desfireEv3
        //byte[] w = Utils.hexStringToByteArray("0E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D");
        //byte[] w = Utils.hexStringToByteArray(publicKeyString); // the publicKey string contains a leading 04 - trim it off
        //w = Arrays.copyOfRange(w, 1, w.length);
        ECPublicKey key = null;
        try {
            key = generateP256PublicKeyFromFlatW(w);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        try {
            signatureVerified = checkEcdsaSignatureEcPubKey(key, tagSignatureByte, tagIdByte);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        writeToUiAppend(readResult, "SignatureVerified: " + signatureVerified);
        runOnUiThread(() -> {
            if (signatureVerified) {
                readResult.setBackgroundColor(getResources().getColor(R.color.light_background_green));
            } else {
                readResult.setBackgroundColor(getResources().getColor(R.color.light_background_red));
            }
        });
    }

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     * @param w a 64 byte uncompressed EC point consisting of just a 256-bit X and Y
     * @return an <code>ECPublicKey</code> that the point represents
     */
    public ECPublicKey generateP256PublicKeyFromFlatW(byte[] w) throws InvalidKeySpecException {
        byte[] encodedKey = new byte[SECP224R1_HEAD.length + w.length];
        System.arraycopy(SECP224R1_HEAD, 0, encodedKey, 0, SECP224R1_HEAD.length);
        System.arraycopy(w, 0, encodedKey, SECP224R1_HEAD.length, w.length);
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
        return (ECPublicKey) eckf.generatePublic(ecpks);
    }

    public boolean checkEcdsaSignatureEcPubKey(final ECPublicKey
                                                              ecPubKey, final byte[]
                                                              signature, final byte[] data)
            throws NoSuchAlgorithmException
    {
        try {
            //final PublicKey publicKey = keyFac.generatePublic(ecPubKey);
            final Signature dsa = Signature.getInstance("NONEwithECDSA");
            dsa.initVerify(ecPubKey);
            dsa.update(data);
            return dsa.verify(derEncodeSignatureSecp224r1(signature));
        } catch (final SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static byte[] derEncodeSignatureSecp224r1(final byte[] signature) {
        // split into r and s
        final byte[] r = Arrays.copyOfRange(signature, 0, 28);
        final byte[] s = Arrays.copyOfRange(signature, 28, 56);
        /* code for secp128r1
        final byte[] r = Arrays.copyOfRange(signature, 0, 16);
        final byte[] s = Arrays.copyOfRange(signature, 16, 32);
        */
        int rLen = r.length;
        int sLen = s.length;
        if ((r[0] & 0x80) != 0) {
            rLen++;
        }
        if ((s[0] & 0x80) != 0) {
            sLen++;
        }
        final byte[] encodedSig = new byte[rLen + sLen + 6]; // 6 T and L bytes
        encodedSig[0] = 0x30; // SEQUENCE
        encodedSig[1] = (byte) (4 + rLen + sLen);
        encodedSig[2] = 0x02; // INTEGER
        encodedSig[3] = (byte) rLen;
        encodedSig[4 + rLen] = 0x02; // INTEGER
        encodedSig[4 + rLen + 1] = (byte) sLen;

        // copy in r and s
        encodedSig[4] = 0;
        encodedSig[4 + rLen + 2] = 0;
        System.arraycopy(r, 0, encodedSig, 4 + rLen - r.length, r.length);
        System.arraycopy(s, 0, encodedSig, 4 + rLen + 2 + sLen - s.length,
                s.length);

        return encodedSig;
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }
}