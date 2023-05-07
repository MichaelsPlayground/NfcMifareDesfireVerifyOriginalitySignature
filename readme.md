# NFC Verify the originality signature of NXP's Mifare DESFire Light and EV2/EV3

This app is verifying the ("originality") signature of a Mifare DESFire Light or EV2 / EV3 tag.

Note: As the DESFire EV1 tag 

Kindly note that the code for verification of the signature is taken from the application note  
AN11350, provided by NXP. Unfortunately the curve of the signature changed from SECP128R1 to SECP224R1. 
To verify the signature I'm rebuilding the public key using a helper method provided by Maarten Bodewes on 
StackOverflow.com.

As the tag producer, NXP, decided to use different public keys for different tag types I need to run a 
"get version" command first on the tag and depending on the response I'm using the correct public key.

The **Public Key** for DESFire Light is taken from a public available document: Mifare DESFire Light Features and Hints AN12343.pdf 
(see pages 86-88). The public keys for DESFire EV2 and DESFire EV3 were published in a GitHub repository:
https://github.com/RfidResearchGroup/proxmark3/blob/906e3f4c3262b456c3bb83982e930381f8c96def/client/src/cmdhfmfdes.c.

These are the specifications of the signature (taken from the referenced NXP document):
```plaintext
- Key type: Elliptic Curve
- Curve: SECP224R1
- Signature Scheme: ECDSA with NONE hashing
- Signature encoding: IEE P1363 (28 bytes R value, 28 bytes S value)

Originality Check public key value for MIFARE DESFire Light:
0x04
    0E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C5407557
    1AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D

Byte 1 of the public key, here using the value 0x04, signalizes the IETF protocol SEC1
representation of a point on an elliptic curve, which is a sequence of the fields as seen in
Table 43.

The following 28 bytes represent the x coordinate of the public key.
And the last 28 bytes represent the y coordinate of the public key.

Example:
ECDSA signature = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
                  076CD1BAAF47B8BBA6DCD78BCC64DFD3E80
                  E679D9A663CAE9E4D4C2C77023077CC549CE
                  4A61
UID of the IC =   045A115A346180      
Signature part 1 r = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
                     076CD1BAAF47B8BBA6D
Signature part 2 s = CD78BCC64DFD3E80E679D9A663CAE9E4D4C2
                     C77023077CC549CE4A61

PubKey= 0x040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D
ECDSA = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6DCD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61
Sig r = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6D
Sig s = CD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61                     
                                  
```

As the guys from NXP added some code for using the curve and converting the signature from P1363 to
DER encoding the complete verification is done in pure Java without any additional 3rd party
tools.

```
https://github.com/RfidResearchGroup/proxmark3/blob/906e3f4c3262b456c3bb83982e930381f8c96def/client/src/cmdhfmfdes.c
line 386
    // ref:  MIFARE Desfire Originality Signature Validation
    // See tools/recover_pk.py to recover Pk from UIDs and signatures
#define PUBLIC_DESFIRE_ECDA_KEYLEN 57
    const ecdsa_publickey_t nxp_desfire_public_keys[] = {
        {"NTAG424DNA, DESFire Ev2", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410"},
        {"NTAG413DNA, DESFire Ev1", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD"},
        {"DESFire Ev2",     "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A"},
        {"DESFire Ev3",     "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743"},
        {"NTAG424DNA, NTAG424DNATT, DESFire Light Ev2", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3B"},
        {"DESFire Light",   "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D"},
        {"MIFARE Plus Ev1", "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E"},
        {"MIFARE Plus EvX", "04BB49AE4447E6B1B6D21C098C1538B594A11A4A1DBF3D5E673DEACDEB3CC512D1C08AFA1A2768CE20A200BACD2DC7804CD7523A0131ABF607"},
        {"DESFire Ev2 XL",  "04CD5D45E50B1502F0BA4656FF37669597E7E183251150F9574CC8DA56BF01C7ABE019E29FEA48F9CE22C3EA4029A765E1BC95A89543BAD1BC"},
        {"MIFARE Plus Troika", "040F732E0EA7DF2B38F791BF89425BF7DCDF3EE4D976669E3831F324FF15751BD52AFF1782F72FF2731EEAD5F63ABE7D126E03C856FFB942AF"},
    };
```
dz6

Don't forget to add these 2 permissions to your AndroidManifest.xml:
```plaintext
    <uses-permission android:name="android.permission.NFC" />
    <uses-permission android:name="android.permission.VIBRATE" />
```

The app is runnable on Android SDKs from 21+, developed on Android 13 (SDK 33).

The app icon is generated with help from **Launcher icon generator**
(https://romannurik.github.io/AndroidAssetStudio/icons-launcher.html),
(options trim image and resize to 110%, color #2196F3).
