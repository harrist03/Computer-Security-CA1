public class Main {
    public static void main(String[] args) {
        String[] menu = { "========= Menu =========",
                "1. Encrypt a file",
                "2. Decrypt a file",
                "3. Quit",
                "========================" };
        displayMenu(menu);
    }

    // Task 1: Create a menu system
    public static void displayMenu(String[] menu) {
        for (int i = 0; i < menu.length; i++) {
            System.out.println(menu[i]);
        }
    }
}