package de.androidcrypto.nfcmifaredesfireverifyoriginalitysignature;

import static de.androidcrypto.nfcmifaredesfireverifyoriginalitysignature.Utils.base64Decoding;
import static de.androidcrypto.nfcmifaredesfireverifyoriginalitysignature.Utils.hexStringToByteArray;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    ScrollView scrollView;
    EditText tagId, tagType, tagSignature, publicKeyNxp, readResult;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte, tagSignatureByte;
    boolean signatureVerified = false;
    // ultralight ev1: publicKeyNxp.setText("0490933bdcd6e99b4e255e3da55389a827564e11718e017292faf23226a96614b8"); // Ultralight EV1
    final String PublicKeyNxpDESFire_Light = "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D";
    final String PublicKeyNxpDESFire_Ev2 = "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A";
    final String PublicKeyNxpDESFire_Ev3 = "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743";
    private byte[] publicKeyNxpByte;

    // generate this value once for a curve by using createHeadForNamedCurve
    // e.g. secp224r1 length 224 or NIST P-256 length 256
    private static byte[] SECP224R1_HEAD = base64Decoding("ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE"); // this is the header of secp224r1

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        scrollView = findViewById(R.id.ScrollView);
        tagId = findViewById(R.id.etVerifyTagId);
        tagType = findViewById(R.id.etVerifyTagType);
        tagSignature = findViewById(R.id.etVerifySignature);
        publicKeyNxp = findViewById(R.id.etVerifyPublicKey);
        readResult = findViewById(R.id.etVerifyResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        publicKeyNxp.setText("the public key depends on the DESFire tyg type");
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        IsoDep isoDep = null;

        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is IsoDep compatible",
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

                isoDep.connect();

                // tag ID
                tagIdByte = tag.getId();
                runOnUiThread(() -> {
                    tagId.setText(Utils.bytesToHex(tagIdByte));
                });

                byte[] response = new byte[0];

                try {
                    // get the tag version to use the matching public key
                    byte[] getVersion = getVersion(isoDep);
                    // if there is no version info it is no DESFire Light, EV2 or EV3
                    if (getVersion == null) {
                        writeToUiAppend(readResult, "Error when getting the version, aborted");
                        return;
                    }
                    VersionInfo versionInfo = new VersionInfo(getVersion);
                    writeToUiAppend(readResult, versionInfo.dump());
                    // hardwareType 1 = DESFire, 8 = DESFire Light
                    // hardwareVersionMajor 18 = EV2, 51 = EV3
                    boolean isSupported = false;

                    if (versionInfo.getHardwareType() == 8) {
                        // DESFire Light
                        publicKeyNxpByte = hexStringToByteArray(PublicKeyNxpDESFire_Light);
                        isSupported = true;
                        runOnUiThread(() -> {
                            publicKeyNxp.setText(PublicKeyNxpDESFire_Light);
                            tagType.setText("DESFire Light");
                        });
                    } else if (versionInfo.getHardwareType() == 1) {
                        // DESFire EV1/EV2/EV3
                        if (versionInfo.getHardwareVersionMajor() == 18) {
                            //DESFire EV2
                            publicKeyNxpByte = hexStringToByteArray(PublicKeyNxpDESFire_Ev2);
                            isSupported = true;
                            runOnUiThread(() -> {
                                publicKeyNxp.setText(PublicKeyNxpDESFire_Ev2);
                                tagType.setText("DESFire EV2");
                            });
                        } else if (versionInfo.getHardwareVersionMajor() == 51) {
                            //DESFire EV3
                            publicKeyNxpByte = hexStringToByteArray(PublicKeyNxpDESFire_Ev3);
                            isSupported = true;
                            runOnUiThread(() -> {
                                publicKeyNxp.setText(PublicKeyNxpDESFire_Ev3);
                                tagType.setText("DESFire EV3");
                            });
                        }
                    }
                    if (!isSupported) {
                        writeToUiAppend(readResult, "This tag type is not supported, aborted");
                        runOnUiThread(() -> {
                            tagType.setText("unsupported DESFire tag");
                        });
                        return;
                    }
                    runOnUiThread(() -> {
                        tagId.setText(Utils.bytesToHex(tagIdByte));
                    });
                    // get the signature
                    byte getSignatureCommand = (byte) 0x3c;
                    byte[] getSignatureCommandParameter = new byte[]{(byte) 0x00};
                    byte[] wrappedCommand;
                    try {
                        wrappedCommand = wrapMessage(getSignatureCommand, getSignatureCommandParameter, 0, getSignatureCommandParameter.length);
                    } catch (Exception e) {
                        writeToUiAppend(readResult, "Error when wrapping the command: " + e.getMessage());
                        return;
                    }
                    try {
                        response = isoDep.transceive(wrappedCommand);
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
                            tagSignatureByte = response.clone();
                            runOnUiThread(() -> {
                                tagSignature.setText(Utils.bytesToHex(tagSignatureByte));
                            });

                            // now we are going to verify

                            // get the EC Public Key
                            ECPublicKey ecPubKey = null;
                            try {
                                ecPubKey = generateP256PublicKeyFromUncompressedW(publicKeyNxpByte);
                            } catch (InvalidKeySpecException e) {
                                //throw new RuntimeException(e);
                                writeToUiAppend(readResult, ("Error on getting the key (native Java): " + e.getMessage()));
                            }
                            try {
                                signatureVerified = checkEcdsaSignatureEcPubKey(ecPubKey, tagSignatureByte, tagIdByte);
                            } catch (NoSuchAlgorithmException e) {
                                //throw new RuntimeException(e);
                                writeToUiAppend(readResult, ("Error in checkEcdsaSignatureEcPubKey: " + e.getMessage()));
                            }

                            writeToUiAppend(readResult, "SignatureVerified: " + signatureVerified);
                            runOnUiThread(() -> {
                                if (signatureVerified) {
                                    readResult.setBackgroundColor(getResources().getColor(R.color.light_background_green));
                                } else {
                                    readResult.setBackgroundColor(getResources().getColor(R.color.light_background_red));
                                }
                            });

                            scrollView.postDelayed(new Runnable() {
                                @Override
                                public void run() {
                                    scrollView.fullScroll(ScrollView.FOCUS_DOWN);
                                }
                            },500);

                        }
                    } catch (TagLostException e) {
                        // Log and return
                        runOnUiThread(() -> {
                            readResult.setText("ERROR: Tag lost exception or command not recognized");
                        });
                        return;
                    } catch (IOException e) {
                        writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
                        e.printStackTrace();
                        return;
                    }
                } finally {
                    try {
                        isoDep.close();
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
    }

    public static byte[] wrapMessage(byte command) throws Exception {
        return new byte[]{(byte) 0x90, command, 0x00, 0x00, 0x00};
    }

    public static byte[] wrapMessage(byte command, byte[] parameters, int offset, int length) throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null && length > 0) {
            // actually no length if empty length
            stream.write(length);
            stream.write(parameters, offset, length);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }

    private byte[] getVersion(IsoDep isoDep) {
        // get the tag version to use the matching public key
        byte[] response;
        byte[] fullResponse = new byte[100]; // too much but you never know
        int fullResponseLength = 0;
        final byte getVersionCommand = (byte) 0x60;
        final byte moreDataCommand = (byte) 0xaf;
        try {
            // 1. round
            response = isoDep.transceive(wrapMessage(getVersionCommand));
            if (checkResponseMoreData(response)) {
                System.arraycopy(response, 0, fullResponse, 0, response.length - 2);
                fullResponseLength = response.length - 2;
                // 2. round
                response = isoDep.transceive(wrapMessage(moreDataCommand));
                if (checkResponseMoreData(response)) {
                    System.arraycopy(response, 0, fullResponse, fullResponseLength, response.length - 2);
                    fullResponseLength += (response.length - 2);
                    // 3. round
                    response = isoDep.transceive(wrapMessage(moreDataCommand));
                    System.arraycopy(response, 0, fullResponse, fullResponseLength, response.length - 2);
                    fullResponseLength += (response.length - 2);
                    return Arrays.copyOf(fullResponse, fullResponseLength);
                } else {
                    System.arraycopy(response, 0, fullResponse, fullResponseLength, response.length - 2);
                    fullResponseLength += (response.length - 2);
                    return Arrays.copyOf(fullResponse, fullResponseLength);
                }

            } else {
                return Arrays.copyOf(response, (response.length - 2));
            }
        } catch (IOException e) {
            //throw new RuntimeException(e);
            return null;
        } catch (Exception e) {
            //throw new RuntimeException(e);
            return null;
        }
        //return null;
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x9100) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91AF' at the end means success
     * but there are more data frames available
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponseMoreData(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AF) {
            return true;
        } else {
            return false;
        }
    }

    public String printData(String dataName, byte[] data) {
        int dataLength;
        String dataString = "";
        if (data == null) {
            dataLength = 0;
            dataString = "IS NULL";
        } else {
            dataLength = data.length;
            dataString = Utils.bytesToHex(data);
        }
        StringBuilder sb = new StringBuilder();
        sb
                .append(dataName)
                .append(" length: ")
                .append(dataLength)
                .append(" data: ")
                .append(dataString);
        return sb.toString();
    }

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     *
     * @param w a 64 byte uncompressed EC point starting with <code>04</code>
     * @return an <code>ECPublicKey</code> that the point represents
     */
    public ECPublicKey generateP256PublicKeyFromUncompressedW(byte[] w) throws InvalidKeySpecException {
        if (w[0] != 0x04) {
            throw new InvalidKeySpecException("w is not an uncompressed key");
        }
        return generateP256PublicKeyFromFlatW(Arrays.copyOfRange(w, 1, w.length));
    }

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     *
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
            throws NoSuchAlgorithmException {
        try {
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
            System.out.println("message: " + message);
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