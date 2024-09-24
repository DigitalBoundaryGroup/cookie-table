package dbg.cookietable;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.border.TitledBorder;
import java.awt.*;
import javax.swing.border.Border;
import java.awt.event.*;
import java.awt.Dimension;
import java.time.Year;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.DefaultTableCellRenderer;

import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import java.util.concurrent.ConcurrentSkipListSet;

public class CookieTab implements BurpExtension {
    private MontoyaApi api;
    private UserInterface userInterface;
    private static Logging logging;

    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        logging.logToOutput("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n" +
                "⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣿⣿⡿⠿⠷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀\n" +
                "⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣇⠀⠀⢸⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀\n" +
                "⠀⠀⠀⠀⢀⣴⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀\n" +
                "⠀⠀⠀⢠⣿⡟⠁⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀\n" +
                "⠀⠀⢠⣿⣿⣿⣦⣄⣠⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣷⠀⠀⠀\n" +
                "⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⢹⣿⣿⣿⡇⠀⠀\n" +
                "⠀⠀⣿⣿⣿⣿⣿⣿COOKIE TABLE⣿⣿⣿⣿⣶⣶⣿⣿⣿⣿⣿⠀⠀\n" +
                "⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀\n" +
                "⠀⠀⠈⢿⣿⣿⣿⣿⠟⠻⣿⣿⠋⠀⠉⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⢙⣿⠃⠀⠀\n" +
                "⠀⠀⠀⠈⢿⣿⣿⠁⠀⠀⠘⣿⣆⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀\n" +
                "⠀⠀⠀⠀⠀⠙⢿⣦⣤⣤⣶Extension Loaded⣿⠏⠀⠀⠀⠀\n" +
                "⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⢹⣿⣿⡿⠟⠁⠀⠀⠀⠀⠀\n" +
                "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⠿⣿⣿⣿⣷⡤⠾⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀\n" +
                "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
        logging.logToOutput("Copyright (c) " + Year.now() + " Digital Boundary Group");
        api.extension().setName("Cookie Attribute Table");
        userInterface = api.userInterface();
        userInterface.registerSuiteTab("Cookie Attribute Table", new MySuiteTab());
        api.http().registerHttpHandler(new CookieScanner(api));
    }

    // Function to retrieve cookie data from HttpHandler CookieScanner.java
    public static ConcurrentSkipListSet<List<String>> retrievedCookieData;
    public static void retrieveCookieData() {
        retrievedCookieData = CookieScanner.getCookieData();
    }

    // Function to clear cookie data from table
    public static void deleteTree() {
        retrievedCookieData = null;
        CookieScanner.killTree();
    }

    public class MySuiteTab extends JPanel {
        public MySuiteTab() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            setMaximumSize(new Dimension(Short.MAX_VALUE, Short.MAX_VALUE));
            Font myFont = new Font("SansSerif", Font.BOLD, 18);
            TitledBorder blackline = BorderFactory.createTitledBorder(null, "DBG Cookie Table", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, myFont);
            setBorder(new TitledBorder(blackline));

            // Set up cookie table
            DefaultTableModel tableModel = new DefaultTableModel();
            CustomTableCellRenderer renderer = new CustomTableCellRenderer();
            JTable table = new JTable(tableModel);
            table.setDefaultRenderer(Object.class, renderer);

            tableModel.addColumn("Name");
            tableModel.addColumn("Value");
            tableModel.addColumn("URL");
            tableModel.addColumn("Domain");
            tableModel.addColumn("Expiry");
            tableModel.addColumn("Path");
            tableModel.addColumn("Secure");
            tableModel.addColumn("HttpOnly");
            tableModel.addColumn("SameSite");

            // Set up update button with action listener
            JButton updateButton = new JButton("Update Table");
            updateButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    retrieveCookieData();
                    updateTable(tableModel);
                }
            });

            JButton deleteButton = new JButton("Delete Logs");
            deleteButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    deleteTree();
                    updateTable(tableModel);
                }
            });

            // Add the table and button to the JPanel
            add(new JScrollPane(table), BorderLayout.CENTER);

            JPanel bottomPanel = new JPanel(new BorderLayout());
            bottomPanel.setMaximumSize(new Dimension(200, 5));
            bottomPanel.add(updateButton, BorderLayout.WEST);
            bottomPanel.add(deleteButton, BorderLayout.CENTER);

            add(bottomPanel);
        }

        private void updateTable(DefaultTableModel model) {
            model.setRowCount(0);
            for (List<String> l : retrievedCookieData) {
                String name = l.get(0);
                String value = l.get(1);
                String setURL = l.get(2);
                String domain = l.get(3);
                String expiry = l.get(4);
                String path = l.get(5);
                String secure = l.get(6);
                String httponly = l.get(7);
                String samesite = l.get(8);

                // Add a new row to the table with the key and value
                model.addRow(new Object[]{name, value, setURL, domain, expiry, path, secure, httponly, samesite});
            }
        }
    }
    // Class for highlighting "bad" cells red
    public class CustomTableCellRenderer extends DefaultTableCellRenderer {
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // Check if the cell's value meets a certain condition
            if (value != null && (value.toString().equals("(Not set)")) || (value.toString().equals("Lax"))) {
                c.setBackground(new Color(182, 98, 98, 128)); // red, and half transparent
            } else {
                c.setBackground(table.getBackground());
            }

            return c;
        }
    }
}
