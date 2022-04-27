import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;


public class Main {
    final static private String KEY_STORE_TYPE = "jks";
    final static private String KEY_STORE_USER_1_ALIAS = "hw_user_1";
    final static private String KEY_STORE_USER_2_ALIAS = "hw_user_2";
    final static private int KEYGEN_KEY_SIZE = 128;
    final static private String PLAIN_FILENAME = "plaintext.txt";
    final static private String ENCRYPTED_FILENAME = "encrypted.txt";
    final static private String DECRYPTED_FILENAME = "decrypted.txt";
    final static private String CONFIG_FILENAME = "config.properties";
    final static private String KEY_STORE_FILENAME = ".keystore";

    static Properties config;
    static KeyStore keyStore;

    public static void main(String[] args) throws Exception {
        String keyStorePassword = args[0];

        init(keyStorePassword);
        encrypt(keyStorePassword);
        decrypt(keyStorePassword);
    }

    /**
     * Init config that controls the cipher algorithms and providers,
     * the config also contains the IV used to sign the file, the encrypted secret key and the encrypted file signature
     * @param keyStorePassword
     * @throws Exception
     */
    private static void init(String keyStorePassword) throws Exception {
        initConfig();
        initKeyStore(keyStorePassword);
    }

    /**
     * Encrypt the file and save the signature
     * @param keyStorePassword
     * @throws Exception
     */
    private static void encrypt(String keyStorePassword) throws Exception {
        encryptFile(new FileInputStream(PLAIN_FILENAME));
        signFile(new FileInputStream(ENCRYPTED_FILENAME), keyStorePassword);
        saveConfig();
    }

    /**
     * Verify the completeness of the encrypted file and decrypt it if valid.
     * @param keyStorePassword
     * @throws Exception
     */
    private static void decrypt(String keyStorePassword) throws Exception {
        if (isCompletedFile(new FileInputStream(ENCRYPTED_FILENAME))) {
            decryptFile(new FileOutputStream(DECRYPTED_FILENAME), keyStorePassword);
        } else {
            handleTamperedFile(new FileOutputStream(DECRYPTED_FILENAME));
        }
    }

    // ENCRYPTION AND DECRYPTION SHARED UTILS FUNCTIONS

    /**
     * Includes the default crypto algorithms and providers,
     * You can override the defaults in the 'config.properties' file
     * @return Default config
     */
    private static Properties getDefaultConfig() {
        Properties defaultConfig = new Properties();

        defaultConfig.setProperty("cipher_algo", "AES/CTR/NoPadding");
        defaultConfig.setProperty("cipher_provider", "SunJCE");
        defaultConfig.setProperty("keygen_algo", "AES");
        defaultConfig.setProperty("secret_cipher_algo", "RSA");
        defaultConfig.setProperty("secret_cipher_provider", "SunJCE");
        defaultConfig.setProperty("signature_algo", "SHA256withRSA");
        defaultConfig.setProperty("signature_provider", "SunRsaSign");

        return defaultConfig;
    }

    private static void initConfig() throws IOException {
        FileInputStream reader = new FileInputStream(CONFIG_FILENAME);

        config = new Properties(getDefaultConfig());
        config.load(reader);

        reader.close();
    }

    /**
     * Initialize the keystore that includes the certificate and private password for both users (Encryption and Decryption),
     * Generated with CommandLine tools (Assignment 1-3)
     * @param keyStorePassword
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    private static void initKeyStore(String keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        keyStore.load(new FileInputStream(KEY_STORE_FILENAME), keyStorePassword.toCharArray() );
    }

    // ENCRYPTION UTILS FUNCTIONS

    /**
     * Generate encrypted file and save the IV and encrypted version of the secret key
     * @param fileInputStream
     * @throws Exception
     */
    private static void encryptFile(FileInputStream fileInputStream) throws Exception {
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        String plainText = new String(bufferedInputStream.readAllBytes());
        bufferedInputStream.close();

        IvParameterSpec iv = generateEncryptIV();
        SecretKey secretKey = getEncryptSecretKey();
        storeIV(iv);
        storeEncryptSecretKey(secretKey);

        Cipher cipher = Cipher.getInstance(config.getProperty("cipher_algo"), config.getProperty("cipher_provider"));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        CipherOutputStream outputStream = new CipherOutputStream(new FileOutputStream(ENCRYPTED_FILENAME), cipher);

        outputStream.write(plainText.getBytes());
        outputStream.close();
    }

    /**
     * Generate signature for encrypted file and save it in config.properties
     * @param fileInputStream
     * @param keyStorePassword
     * @throws Exception
     */
    private static void signFile(FileInputStream fileInputStream, String keyStorePassword) throws Exception {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_STORE_USER_1_ALIAS, keyStorePassword.toCharArray());
        Signature signature = Signature.getInstance(config.getProperty("signature_algo"), config.getProperty("signature_provider"));
        signature.initSign(privateKey);

        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        String plainText = new String(bufferedInputStream.readAllBytes());
        bufferedInputStream.close();

        signature.update(plainText.getBytes());
        byte[] digitalSignature = signature.sign();
        config.setProperty("file_signature", Base64.getEncoder().encodeToString(digitalSignature));
    }

    /**
     * Encrypt and save the secret key used to generate the encrypted file.
     * @param secretKey
     * @throws KeyStoreException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void storeEncryptSecretKey(SecretKey secretKey) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Certificate certificate = keyStore.getCertificate(KEY_STORE_USER_2_ALIAS);
        PublicKey publicKey = certificate.getPublicKey();

        Cipher cipher = Cipher.getInstance(config.getProperty("secret_cipher_algo"), config.getProperty("secret_cipher_provider"));
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());

        config.setProperty("encrypted_key", Base64.getEncoder().encodeToString(encryptedKey));
    }

    /**
     * Save the IV used for generating the encrypted file
     * @param iv
     */
    private static void storeIV(IvParameterSpec iv) {
        config.setProperty("iv", Base64.getEncoder().encodeToString(iv.getIV()));
    }

    /**
     * Saves the updated version of the config back to config.properties file
     * @throws IOException
     */
    private static void saveConfig() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(CONFIG_FILENAME);
        config.store(fileOutputStream, "");
        fileOutputStream.close();
    }

    /**
     * Generate random IV
     * @return
     */
    private static IvParameterSpec generateEncryptIV() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];

        random.nextBytes(bytes);

        return new IvParameterSpec(bytes);
    }

    /**
     * Generate Random Secret Key
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static SecretKey getEncryptSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(config.getProperty("keygen_algo"));
        keyGenerator.init(KEYGEN_KEY_SIZE);
        return keyGenerator.generateKey();
    }


    // DECRYPTION UTILS FUNCTIONS

    /**
     * Verifies the encrypted file signature matches the saved file signature, indicating file was not modified after signing
     * @param fileInputStream
     * @return
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws SignatureException
     */
    private static boolean isCompletedFile(FileInputStream fileInputStream) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        PublicKey publicKey = keyStore.getCertificate(KEY_STORE_USER_1_ALIAS).getPublicKey();
        Signature signature = Signature.getInstance(config.getProperty("signature_algo"), config.getProperty("signature_provider"));
        signature.initVerify(publicKey);

        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        String plainText = new String(bufferedInputStream.readAllBytes());
        bufferedInputStream.close();

        signature.update(plainText.getBytes());

        byte[] signatureFromConfig = Base64.getDecoder().decode(config.getProperty("file_signature"));
        return signature.verify(signatureFromConfig);
    }

    /**
     * Decrypt the file using secret key and IV from the config file
     * @param fileOutputStream
     * @param keyStorePassword
     * @throws Exception
     */
    private static void decryptFile(FileOutputStream fileOutputStream, String keyStorePassword) throws Exception{
        IvParameterSpec iv = getDecryptIV();
        SecretKey secretKey = getDecryptSecretKey(keyStorePassword);

        Cipher cipher = Cipher.getInstance(config.getProperty("cipher_algo"), config.getProperty("cipher_provider"));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        CipherInputStream inputStream = new CipherInputStream(new FileInputStream(ENCRYPTED_FILENAME), cipher);
        String plainText = new String(inputStream.readAllBytes());
        inputStream.close();

        fileOutputStream.write(plainText.getBytes());
        fileOutputStream.close();
    }

    /**
     * Handle the case signature does not match the encrypted file
     * @param fileOutputStream
     * @throws IOException
     */
    private static void handleTamperedFile(FileOutputStream fileOutputStream) throws IOException {
        String errorMsg = "Error: File was tempered, signature does not match the contents";

        System.err.println(errorMsg);

        fileOutputStream.write(errorMsg.getBytes());
        fileOutputStream.close();
    }

    /**
     * Get IV from config
     * @return
     */
    private static IvParameterSpec getDecryptIV() {
        byte[] ivBytes = Base64.getDecoder().decode(config.getProperty("iv"));

        return new IvParameterSpec(ivBytes);
    }

    /**
     * Decrypt the secret key saved in config
     * @param keyStorePassword
     * @return
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static SecretKey getDecryptSecretKey(String keyStorePassword) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_STORE_USER_2_ALIAS, keyStorePassword.toCharArray());
        Cipher cipher = Cipher.getInstance(config.getProperty("secret_cipher_algo"), config.getProperty("secret_cipher_provider"));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedKey = Base64.getDecoder().decode(config.getProperty("encrypted_key"));

        return new SecretKeySpec(cipher.doFinal(encryptedKey), config.getProperty("keygen_algo"));
    }
}