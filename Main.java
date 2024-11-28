import java.io.File;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        int choice = 0;
        boolean valid = true;
        String fileName = "";

        String[] menu = { "========= Menu =========",
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
                } else if (choice == 2) {
                    String ValidFileName = checkFileValid(sc);
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
    
}