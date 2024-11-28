import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    public static void main(String[] args) {
        try {
            int choice = 0;
            boolean valid = true;
            String fileName = "";

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
            if (file.exists() && fileName.endsWith(".txt")) {
                isValid = true; // File exists and has .txt extension
            } else {
                System.out.println("Invalid file name! Please enter a valid .txt file name.");
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

            // Save encrypted content to a text file
            Files.write(Paths.get("ciphertext.txt"), Base64.getEncoder().encode(encryptedBytes));

            // convert to a readable format(base 64)
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            System.out.println("\nSecret key(Base 64): " + encodedKey);
            System.out.println("File encrypted and saved to ciphertext.txt");
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

            // Write the decrypted content to plaintext.txt
            Files.write(Paths.get("plaintext.txt"), decryptedBytes);

            System.out.println("Decryption complete!");
            System.out.println("Decrypted content saved to: plaintext.txt");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}