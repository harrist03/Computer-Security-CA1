// SD2B, Harris Teh Kai Ze

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Resources used: https://www.baeldung.com/java-aes-encryption-decryption
//                 https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java
//                 https://www.w3schools.com/java/java_hashmap.asp
// Additional features: Storing a secret key between two parties and option to view a 
//                      secret key using a password shared between two parties.
//                      Password and Secret key validation is created.
//                      Another problem is also created, users might have the same password.
//                      Therefore, a user-id input is created, password hashing and salting to increase security.

public class Main {
    // global variables
    private static final Map<String, String> passwordKeys = new HashMap<>();
    private static final ArrayList<String> userIDs = new ArrayList<>();

    public static void main(String[] args) {
        try {
            int choice = 0;
            boolean valid = true;

            String[] menu = { "\n========= Menu =========",
                    "1. Encrypt a file",
                    "2. Decrypt a file",
                    "3. Store a secret key",
                    "4. View a secret key",
                    "5. Quit",
                    "========================" };
            Scanner sc = new Scanner(System.in);
            do {
                // method to display menu
                displayMenu(menu);
                if (sc.hasNextInt()) {
                    choice = sc.nextInt();
                    sc.nextLine();
                    if (choice == 1) {
                        String ValidFileName = checkFileValid(sc);
                        encryptFile(ValidFileName, sc);
                    } else if (choice == 2) {
                        String ValidFileName = checkFileValid(sc);
                        decryptFile(ValidFileName, sc);
                    } else if (choice == 3) {
                        storeSecretKey(sc);
                    } else if (choice == 4) {
                        viewSecretKey(sc);
                    } else if (choice == 5) {
                        valid = false;
                        System.out.println("Goodbye!");
                    } else {
                        System.out.println("\nInvalid input! Enter numbers 1-3.");
                    }
                } else {
                    System.out.println("Invalid input! Please enter a number.");
                    // clear the invalid input
                    sc.next();
                }
            } while (valid);

            sc.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Task 1: Create a menu system
    public static void displayMenu(String[] menu) {
        for (int i = 0; i < menu.length; i++) {
            System.out.println(menu[i]);
        }
    }

    public static String checkFileValid(Scanner sc) {
        String fileName = "";
        File file;
        boolean isValid = false;

        while (!isValid) {
            System.out.println("Enter file name (include .txt): ");
            fileName = sc.nextLine();
            file = new File(fileName);

            if (fileName.endsWith(".txt")) {
                if (file.exists()) {
                    // File exists and has .txt extension
                    isValid = true;
                } else {
                    System.out.println("File does not exists! Try again!");
                }
            } else {
                System.out.println("Enter a valid file with the correct format (.txt)");
            }
        }

        return fileName;
    }

    // Generate a random AES key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 128 bits or 16 bytes
        return keyGenerator.generateKey();
    }

    // Task 2: Encrypt a file
    public static void encryptFile(String file, Scanner sc) {
        String choice = "", userKeyString = "";
        SecretKey secretKey = null;
        boolean valid = false, UserValidKey = false;
        try {
            // Convert to file content to plain text
            String plaintext = new String(Files.readAllBytes(Paths.get(file)));
            // if plaintext is not empty
            if (plaintext.length() > 0) {
                while (!valid) {
                    System.out.println("Do you have a secret key? (yes/no)");
                    choice = sc.nextLine();
                    // if user doesn't have a secret key
                    if (choice.toLowerCase().equals("no")) {
                        System.out.println("A 16 byte secret key is auto-generated for you!");
                        // generate the secret key
                        secretKey = generateKey();
                        valid = true;
                        // if user already has a secret key
                    } else if (choice.toLowerCase().equals("yes")) {
                        do {
                            System.out.println("Enter your secret key(base 64): ");
                            userKeyString = sc.nextLine();
                            UserValidKey = isValidSecretKey(userKeyString);
                        } while (!UserValidKey);
                        // Decode the Base64 key into bytes and create a SecretKey object
                        byte[] keyBytes = Base64.getDecoder().decode(userKeyString);
                        secretKey = new SecretKeySpec(keyBytes, "AES");
                        valid = true;
                    } else {
                        System.out.println("Invalid input! Try again!");
                    }
                }
                // Encrypt the plaintext
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

                // Save encrypted content to "ciphertext.txt" file
                Path path = Paths.get("ciphertext.txt");
                boolean fileExists = Files.exists(path);

                Files.write(path, Base64.getEncoder().encode(encryptedBytes));

                // convert to a readable format(base 64)
                String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

                System.out.println("\nSecret key(Base 64): " + encodedKey);
                if (fileExists) {
                    System.out.println("ciphertext.txt content is updated!");
                } else {
                    System.out.println("ciphertext.txt created and encrypted content is added!");
                }
            } else {
                System.out.println("File to be encrypted is empty! Encryption aborted.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Task 3: Decrypt a file
    public static void decryptFile(String file, Scanner sc) {
        try {
            String randomKey = "";
            boolean valid = false;

            do {
                System.out.println("Enter your secret key(base 64): ");
                randomKey = sc.nextLine();
                valid = isValidSecretKey(randomKey);
            } while (!valid);

            // Decode the AES key from Base64
            byte[] decodedKey = Base64.getDecoder().decode(randomKey);
            SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");

            // Read the encrypted file
            String encryptedText = new String(Files.readAllBytes(Paths.get(file)));

            if (encryptedText.length() > 0) {
                // Decrypt the content
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

                // Save decrypted content to "plaintext.txt" file
                Path path = Paths.get("plaintext.txt");
                boolean fileExists = Files.exists(path);

                // Write the decrypted content to plaintext.txt
                Files.write(path, decryptedBytes);

                if (fileExists) {
                    System.out.println("plaintext.txt content is updated!");
                } else {
                    System.out.println("plaintext.txt created and encrypted content is added!");
                }
            } else {
                System.out.println("ciphertext.txt is empty! Decryption aborted.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid key format. Please enter a valid base64 encoded key.");
        } catch (Exception e) {
            System.out.println("Decryption failed. Please check the key and try again.");
        }
    }

    // Additional features
    public static void storeSecretKey(Scanner sc) {
        String secretKey = "", password = "", userID = "";
        boolean valid = false;
        try {
            do {
                System.out.println("Enter a unique user ID (no spaces allowed): ");
                userID = sc.nextLine();
                valid = isValidUserID(userID);
            } while (!valid);

            // User ID is valid and unique, add it to the list
            userIDs.add(userID);
            System.out.println("User ID is created!");

            do {
                System.out.println("Enter secret key(base 64) to be stored: ");
                secretKey = sc.nextLine();
                valid = isValidSecretKey(secretKey);
            } while (!valid);

            do {
                System.out.println("Enter a password: ");
                password = sc.nextLine();
                valid = isValidPassword(password);
            } while (!valid);
            // generate salt and hash password
            String salt = generateSalt();
            String hashedPassword = hashPassword(userID, password, salt);
            // store the password and the secret key
            passwordKeys.put(userID + ":" + hashedPassword + ":" + salt, secretKey);

            System.out.println("Secret key is safely stored!");
        } catch (Exception e) {
            System.out.println("Error storing key: " + e.getMessage());
        }
    }

    public static void viewSecretKey(Scanner sc) {
        String password = "", userID = "";
        try {
            // no validation needed to increase security
            System.out.println("Enter your user ID: ");
            userID = sc.nextLine();

            System.out.println("Enter password to view: ");
            password = sc.nextLine();

            // Check if the userID and password exist in the map
            for (Map.Entry<String, String> entry : passwordKeys.entrySet()) {
                String[] keyParts = entry.getKey().split(":");
                String storedUID = keyParts[0]; // stored UID
                String storedHash = keyParts[1]; // stored hash
                String storedSalt = keyParts[2]; // stored salt

                // Ensure the UID matches
                if (storedUID.equals(userID)) {
                    // Rehash the input password with the stored salt and UID
                    String hashedInputPassword = hashPassword(userID, password, storedSalt);

                    // Compare the hashes
                    if (storedHash.equals(hashedInputPassword)) {
                        System.out.println("Your secret key is: " + entry.getValue());
                        return;
                    }
                }
            }

            System.out.println("Invalid userID or password! Aborted!");
        } catch (Exception e) {
            System.out.println("Error retrieving key: " + e.getMessage());
        }
    }

    public static boolean isValidUserID(String userID) {
        if (userID.contains(" ") || userID.length() < 6 || userIDs.contains(userID)) {
            System.out.println("User ID is invalid! It must meet the following requirements:");
            System.out.println("- Must be unique! User ID could already exists!");
            System.out.println("- At least 6 characters long");
            System.out.println("- No spaces are allowed");
            return false;
        }
        return true;
    }

    public static boolean isValidPassword(String password) {
        // one upper, one lower, one digit, one special symbol
        String regex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@#$%^&+=!]).{8,}$";

        if (password.length() < 8 || password.contains(" ") || !password.matches(regex)) {
            System.out.println("Password is invalid! It must meet the following requirements:");
            System.out.println("- At least 8 characters long");
            System.out.println("- Contains at least one uppercase letter");
            System.out.println("- Contains at least one lowercase letter");
            System.out.println("- Contains at least one special symbol (@#$%^&+=!)");
            System.out.println("- Contains at least one number");
            System.out.println("- No spaces are allowed");
            return false;
        }
        return true;
    }

    public static boolean isValidSecretKey(String base64Key) {
        try {
            // Decode the Base64 key
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);

            if (base64Key.contains(" ") || keyBytes.length != 16) {
                System.out.println("Secret key is Invalid! It must meet the following requirements:");
                System.out.println("- Must be valid Base64 format");
                System.out.println("- Must be the following format (16 bytes)");
                System.out.println("- No spaces are allowed");
                return false;
            }
            System.out.println("Secret key is valid!");
            return true;
        } catch (IllegalArgumentException e) {
            System.out.println("Secret key is Invalid! It must meet the following requirements:");
            System.out.println("- Must be valid Base64 format");
            System.out.println("- Must be the following format (16 bytes)");
            System.out.println("- No spaces are allowed");
            return false;
        }
    }

    // Hash the password with the UID and salt (making sure the salt is stored
    // separately)
    public static String hashPassword(String userUID, String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String saltedPassword = userUID + ":" + password + ":" + salt; // Combine UID, password, and salt
        byte[] hashedBytes = md.digest(saltedPassword.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    // Generate a unique salt (random for each user)
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 16 byte salt
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}