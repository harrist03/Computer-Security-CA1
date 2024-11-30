import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Resources used: https://www.baeldung.com/java-aes-encryption-decryption
// Additional features: Storing a secret key between two parties and option to view a 
// secret key using a password shared between two parties. 

public class Main {
    // hashmap to store secret key and password
    private static final Map<String, String> passwordKeys = new HashMap<>();

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
                    sc.next(); // clear the invalid input
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
        keyGenerator.init(128); // 128 bits
        return keyGenerator.generateKey();
    }

    // Task 2: Encrypt a file
    public static void encryptFile(String file, Scanner sc) {
        String choice = "", userKeyString = "";
        SecretKey secretKey = null;
        boolean valid = false;
        try {
            // Convert to file content to plain text
            String plaintext = new String(Files.readAllBytes(Paths.get(file)));
            // if plaintext is not empty
            if (plaintext.length() > 0) {
                while (!valid) {
                    System.out.println("Do you have a secret key? (yes/no)");
                    choice = sc.next();
                    if (choice.toLowerCase().equals("no")) {
                        System.out.println("Secret key is auto-generated for you!");
                        // generate the secret key
                        secretKey = generateKey();
                        valid = true;
                    } else if (choice.toLowerCase().equals("yes")) {
                        // while user key string is not valid
                        while (!isValidSecretKey(userKeyString)) {
                            System.out.println("Enter your secret key(Base64): ");
                            userKeyString = sc.next();
                            if (isValidSecretKey(userKeyString)) {
                                // Decode the Base64 key into bytes and create a SecretKey object
                                byte[] keyBytes = Base64.getDecoder().decode(userKeyString);
                                secretKey = new SecretKeySpec(keyBytes, "AES");
                            } else {
                                System.out.println("Invalid Base64 format! Try again!");
                            }
                        }
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

            while (!isValidSecretKey(randomKey)) {
                System.out.println("Enter a valid secret key(base 64): ");
                randomKey = sc.next();
                if (isValidSecretKey(randomKey)) {
                    System.out.println("Secret key is valid!");
                } else {
                    System.out.println("Invalid Base64 format! Try again!");
                }
            }

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
        String secretKey = "", password = "";
        try {
            System.out.println("Enter secret key(base 64) to be stored: ");
            secretKey = sc.next();
            // function to check if secret key is valid
            if (isValidSecretKey(secretKey)) {
                System.out.println("Secret key is valid!");
            } else {
                System.out.println("Invalid Base64 format! Aborted!");
                return;
            }
            // password doesn't match the regex
            while (!isValidPassword(password)) {
                System.out.println("Enter a password: ");
                password = sc.next();

                if (isValidPassword(password)) {
                    System.out.println("Password is valid!");
                } else {
                    System.out.println("Password is invalid! It must meet the following requirements:");
                    System.out.println("- At least 8 characters long");
                    System.out.println("- Contains at least one uppercase letter");
                    System.out.println("- Contains at least one lowercase letter");
                    System.out.println("- Contains at least one special symbol (@#$%^&+=!)");
                    System.out.println("- Contains at least one number");
                }
            }
            // store the password and the secret key
            passwordKeys.put(password, secretKey);

            System.out.println("Secret key is safely stored!");
        } catch (Exception e) {
            System.out.println("Error storing key: " + e.getMessage());
        }
    }

    public static void viewSecretKey(Scanner sc) {
        String password = "";
        try {
            System.out.println("Enter password to view: ");
            password = sc.next();

            if (passwordKeys.containsKey(password)) {
                System.out.println("Your secret key is: " + passwordKeys.get(password));
            } else {
                System.out.println("Invalid password! Aborted!");
            }
        } catch (Exception e) {
            System.out.println("Error retrieving key: " + e.getMessage());
        }
    }

    public static boolean isValidPassword(String password) {
        // Check if the password is at least 8 characters long
        if (password.length() < 8) {
            return false;
        }
        // one upper, one lower, one digit, one special symbol
        String regex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@#$%^&+=!]).{8,}$";

        return password.matches(regex);
    }

    public static boolean isValidSecretKey(String base64Key) {
        try {
            // Decode the Base64 key
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);

            // Check if the key length is valid for AES
            return keyBytes.length == 16 || keyBytes.length == 24 || keyBytes.length == 32;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}