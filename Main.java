import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Resources used: https://www.baeldung.com/java-aes-encryption-decryption 

public class Main {
    public static void main(String[] args) {
        try {
            int choice = 0;
            boolean valid = true;

            String[] menu = { "\n========= Menu =========",
                    "1. Encrypt a file",
                    "2. Decrypt a file",
                    "3. Quit",
                    "========================" };
            Scanner sc = new Scanner(System.in);
            do {
                displayMenu(menu);
                if (sc.hasNextInt()) {
                    choice = sc.nextInt();
                    sc.nextLine();
                    if (choice == 1) {
                        String ValidFileName = checkFileValid(sc);
                        encryptFile(ValidFileName);
                    } else if (choice == 2) {
                        String ValidFileName = checkFileValid(sc);
                        decryptFile(ValidFileName, sc);
                    } else if (choice == 3) {
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
    public static void encryptFile(String file) {
        try {
            // generate the secret key
            SecretKey secretKey = generateKey();
            String plaintext = new String(Files.readAllBytes(Paths.get(file)));

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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Task 3: Decrypt a file
    public static void decryptFile(String file, Scanner sc) {
        try {
            String randomKey = "";

            System.out.println("Enter a valid secret key: ");
            randomKey = sc.next();

            // Decode the AES key from Base64
            byte[] decodedKey = Base64.getDecoder().decode(randomKey);
            SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");

            // Read the encrypted file
            String encryptedText = new String(Files.readAllBytes(Paths.get(file)));

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
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid key format. Please enter a valid base64 encoded key.");
        } catch (Exception e) {
            System.out.println("Decryption failed. Please check the key and try again.");
        }
    }
}