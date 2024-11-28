import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        int choice = 0;
        boolean valid = true;

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
                if (choice == 1) {
                    System.out.println("1");
                } else if (choice == 2) {
                    System.out.println("2");
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

        // System.out.println("Enter file name (include .txt)");
        // String fileName = sc.nextLine();

        sc.close();
    }

    // Task 1: Create a menu system
    public static void displayMenu(String[] menu) {
        for (int i = 0; i < menu.length; i++) {
            System.out.println(menu[i]);
        }
    }
}