package aes;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.util.ArrayList;

public class AESMainGUI extends JFrame {
    private static final Color BG = new Color(245, 245, 250), PANEL = new Color(235, 235, 245),
            CARD = new Color(100, 120, 200);
    private static final Color BDR = new Color(180, 180, 200), ACC = new Color(137, 188, 201),
            GRN = new Color(137, 188, 201), DMN = new Color(58, 153, 78);
    private static final Color YLW = new Color(200, 140, 0), RED = new Color(185, 117, 117),
            TXT = new Color(25, 25, 40), MUT = new Color(100, 100, 120);
    private static final Font MONO = new Font("Consolas", Font.PLAIN, 12), BOLD = new Font("Segoe UI", Font.BOLD, 12);

    private JTextArea txtInput, txtCipher, txtDecrypted;
    private JTextField txtKey;
    private JLabel lblEncTime, lblDecTime, lblTotal, lblStatus, lblCount;
    private JTable tblHistory;
    private DefaultTableModel tableModel;
    private JRadioButton rb128, rb192, rb256;
    private AESCipher cipher = new AESCipher(256);
    private byte[] currentKey;

    private static class Rec {
        String time, plain, ct, dec, keyHex;
        int bits;
        long encNs, decNs;

        Rec(String t, String p, String c, String d, String k, int b, long e, long dc) {
            time = t;
            plain = p;
            ct = c;
            dec = d;
            keyHex = k;
            bits = b;
            encNs = e;
            decNs = dc;
        }
    }

    private final ArrayList<Rec> history = new ArrayList<>();

    public AESMainGUI() {
        setTitle("AES Encryption & Decryption — (128/192/256 bit)");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1100, 780);
        setMinimumSize(new Dimension(900, 640));
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG);
        setLayout(new BorderLayout());
        buildUI();
        generateKey();
    }

    private void buildUI() {
        add(buildHeader(), BorderLayout.NORTH);
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(BG);
        tabs.setForeground(TXT);
        tabs.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        tabs.addTab("Mã hóa / Giải mã", buildMainTab());
        tabs.addTab("Lịch sử", buildHistoryTab());
        tabs.addTab("Hướng dẫn", buildInfoTab());
        add(tabs, BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
    }

    private JPanel buildHeader() {
        JPanel h = new JPanel(new BorderLayout());
        h.setBackground(PANEL);
        h.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BDR));
        h.setPreferredSize(new Dimension(0, 62));
        JLabel t = new JLabel("AES Encryption & Decryption");
        t.setFont(new Font("Segoe UI", Font.BOLD, 18));
        t.setForeground(TXT);

        h.add(t, BorderLayout.WEST);

        return h;
    }

    private JPanel buildMainTab() {
        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBackground(BG);
        root.setBorder(new EmptyBorder(12, 12, 12, 12));
        root.add(buildKeyPanel(), BorderLayout.NORTH);
        JPanel center = new JPanel(new GridLayout(1, 3, 12, 0));
        center.setOpaque(false);
        center.add(buildInputCard());
        center.add(buildBtnColumn());
        center.add(buildOutputCards());
        root.add(center, BorderLayout.CENTER);
        root.add(buildTimeBar(), BorderLayout.SOUTH);
        return root;
    }

    private JPanel buildKeyPanel() {
        JPanel card = createCard();
        card.setLayout(new BorderLayout(10, 0));
        card.setBorder(new CompoundBorder(new MatteBorder(0, 4, 0, 0, ACC), new EmptyBorder(10, 12, 10, 12)));
        card.setPreferredSize(new Dimension(0, 56));
        JLabel lbl = new JLabel("Khoá (Hex):");
        lbl.setFont(BOLD);
        lbl.setForeground(YLW);
        lbl.setPreferredSize(new Dimension(110, 0));
        txtKey = new JTextField();
        txtKey.setFont(MONO);
        txtKey.setBackground(new Color(255, 255, 255));
        txtKey.setForeground(YLW);
        txtKey.setCaretColor(TXT);
        txtKey.setBorder(new CompoundBorder(new LineBorder(BDR, 1, true), new EmptyBorder(4, 8, 4, 8)));
        rb128 = new JRadioButton("Khoá 128 bit");
        rb192 = new JRadioButton("Khoá 192 bit");
        rb256 = new JRadioButton("Khoá 256 bit");
        styleR(rb128);
        styleR(rb192);
        styleR(rb256);
        rb256.setSelected(true);
        ButtonGroup bg = new ButtonGroup();
        bg.add(rb128);
        bg.add(rb192);
        bg.add(rb256);
        rb128.addActionListener(e -> changeSize(128));
        rb192.addActionListener(e -> changeSize(192));
        rb256.addActionListener(e -> changeSize(256));
        JPanel radio = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        radio.setOpaque(false);
        radio.add(rb128);
        radio.add(rb192);
        radio.add(rb256);
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btns.setOpaque(false);
        btns.add(radio);
        btns.add(btn("Sinh khoá", ACC, e -> generateKey()));
        btns.add(btn("Copy", CARD, e -> copy(txtKey.getText(), "Khoá")));
        btns.add(btn("Dùng khoá này", DMN, e -> applyKey()));
        card.add(lbl, BorderLayout.WEST);
        card.add(txtKey, BorderLayout.CENTER);
        card.add(btns, BorderLayout.EAST);
        return card;
    }

    private void styleR(JRadioButton r) {
        r.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        r.setForeground(TXT);
        r.setOpaque(false);
        r.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    private void changeSize(int bits) {
        cipher = new AESCipher(bits);
        generateKey();
        status("Đã chuyển sang khóa " + bits + " bit!", GRN);
    }

    private JPanel buildInputCard() {
        txtInput = new JTextArea();
        txtInput.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        txtInput.setBackground(new Color(255, 255, 255));
        txtInput.setForeground(TXT);
        txtInput.setCaretColor(TXT);
        txtInput.setLineWrap(true);
        txtInput.setWrapStyleWord(true);
        txtInput.setBorder(new EmptyBorder(10, 10, 10, 10));
        txtInput.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                upCount();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                upCount();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                upCount();
            }
        });
        JScrollPane sp = new JScrollPane(txtInput);
        sp.setBorder(null);
        sp.getViewport().setBackground(new Color(255, 255, 255));
        return textCard("Văn bản gốc (≥ 15 ký tự)", sp);
    }

    private JPanel buildBtnColumn() {
        JPanel col = new JPanel();
        col.setOpaque(false);
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setPreferredSize(new Dimension(140, 0));
        col.add(Box.createVerticalGlue());
        lblCount = new JLabel("0 ký tự", SwingConstants.CENTER);
        lblCount.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        lblCount.setForeground(MUT);
        lblCount.setAlignmentX(CENTER_ALIGNMENT);
        col.add(lblCount);
        col.add(Box.createVerticalStrut(16));
        Object[][] btns = {
                { "Mã hóa", ACC, (Runnable) this::runEncrypt },
                { "Giải mã", GRN, (Runnable) this::runDecrypt },
                { "Mã & Giải", new Color(137, 188, 201), (Runnable) this::runBoth },
                { "Xóa", RED, (Runnable) this::clearAll },
                { "Lưu file", CARD, (Runnable) this::saveResult }
        };
        for (Object[] b : btns) {
            JButton jb = bigBtn((String) b[0], (Color) b[1], (Runnable) b[2]);
            jb.setAlignmentX(CENTER_ALIGNMENT);
            col.add(jb);
            col.add(Box.createVerticalStrut(10));
        }
        col.add(Box.createVerticalGlue());
        return col;
    }

    private JPanel buildOutputCards() {
        JPanel p = new JPanel(new GridLayout(2, 1, 0, 10));
        p.setOpaque(false);
        txtCipher = outArea(new Color(251, 191, 36));
        txtDecrypted = outArea(GRN);
        p.add(textCard("Bản Mã (Base64)", sc(txtCipher)));
        p.add(textCard("Bản Rõ giải mã", sc(txtDecrypted)));
        return p;
    }

    private JPanel buildTimeBar() {
        JPanel bar = createCard();
        bar.setLayout(new FlowLayout(FlowLayout.CENTER, 36, 10));
        bar.setPreferredSize(new Dimension(0, 55));
        bar.setBorder(new CompoundBorder(new MatteBorder(1, 0, 0, 0, BDR), new EmptyBorder(5, 20, 5, 20)));
        bar.add(lb("Thống kê:", MUT));
        bar.add(vs());
        lblEncTime = tl("Mã hóa: —");
        lblDecTime = tl("Giải mã: —");
        lblTotal = tl("Tổng: —");
        lblTotal.setForeground(YLW);
        bar.add(lblEncTime);
        bar.add(vs());
        bar.add(lblDecTime);
        bar.add(vs());
        bar.add(lblTotal);
        return bar;
    }

    private JPanel buildHistoryTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBackground(BG);
        p.setBorder(new EmptyBorder(12, 12, 12, 12));
        String[] cols = { "#", "Thời điểm", "Key (bit)", "Văn bản gốc", "Ciphertext",
                "Mã hóa (ms)", "Giải mã (ms)" };
        tableModel = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        tblHistory = new JTable(tableModel);
        tblHistory.setBackground(PANEL);
        tblHistory.setForeground(TXT);
        tblHistory.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        tblHistory.setRowHeight(28);
        tblHistory.setGridColor(BDR);
        tblHistory.setSelectionBackground(ACC);
        tblHistory.getTableHeader().setBackground(CARD);
        tblHistory.getTableHeader().setForeground(TXT);
        tblHistory.getTableHeader().setFont(BOLD);
        JScrollPane sp = new JScrollPane(tblHistory);
        sp.setBorder(new LineBorder(BDR));
        sp.getViewport().setBackground(PANEL);
        JPanel bb = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        bb.setOpaque(false);
        bb.add(btn("Xóa lịch sử", RED, e -> {
            history.clear();
            tableModel.setRowCount(0);
        }));
        bb.add(btn("Xuất CSV", GRN, e -> exportCSV()));
        p.add(sp, BorderLayout.CENTER);
        p.add(bb, BorderLayout.SOUTH);
        return p;
    }

    private JScrollPane buildInfoTab() {
        JTextArea t = new JTextArea(
                "MÃ HOÁ AES\n\nCách dùng:\n1. Chọn kích thước khoá: 128/192/256 bit\n2. Nhấn [Sinh Khoá] để tạo khoá ngẫu nhiên\n3. Nhập văn bản >= 15 ký tự\n4. Nhấn [Mã & Giải] để thực hiện\n\nĐộ dài khoá\n  128 bit = 32 ký tự Hex (10 vòng)\n  192 bit = 48 ký tự Hex (12 vòng)\n  256 bit = 64 ký tự Hex (14 vòng)\n");
        t.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        t.setBackground(PANEL);
        t.setForeground(TXT);
        t.setEditable(false);
        t.setLineWrap(true);
        t.setWrapStyleWord(true);
        t.setBorder(new EmptyBorder(16, 20, 16, 20));
        return new JScrollPane(t);
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(PANEL);
        bar.setBorder(new CompoundBorder(new MatteBorder(1, 0, 0, 0, BDR), new EmptyBorder(4, 14, 4, 14)));
        lblStatus = new JLabel("Sẵn sàng  |  AES/CBC/PKCS7 — Tự cài đặt");
        lblStatus.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        lblStatus.setForeground(MUT);
        JLabel v = new JLabel("Java " + System.getProperty("java.version") + "  ");
        v.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        v.setForeground(MUT);
        bar.add(lblStatus, BorderLayout.WEST);
        bar.add(v, BorderLayout.EAST);
        return bar;
    }

    // === LOGIC ===
    private void generateKey() {
        currentKey = cipher.generateKey();
        txtKey.setText(cipher.toHex(currentKey));
        int b = cipher.getKeyBits();
        status("Đã sinh Khóa AES-" + b + " mới! (" + b / 4 + " ký tự Hex)", GRN);
    }

    private void applyKey() {
        try {
            byte[] k = cipher.fromHex(txtKey.getText());
            int ex = cipher.getKeyBits() / 8;
            if (k.length != ex)
                throw new Exception("Khóa " + cipher.getKeyBits() + " bit cần " + (ex * 2)
                        + " ký tự Hex!\nHiện tại: " + k.length * 8 + " bit");
            currentKey = k;
            status("Đã áp dụng khóa tùy chỉnh " + cipher.getKeyBits()
                    + " bit!", GRN);
            JOptionPane.showMessageDialog(this, "Khóa hợp lệ!", "OK", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            err(ex.getMessage());
        }
    }

    private void runEncrypt() {
        if (!val())
            return;
        try {
            long s = System.nanoTime();
            byte[] ct = cipher.encryptCBC(cipher.toBytes(txtInput.getText().trim()), currentKey);
            long ns = System.nanoTime() - s;
            txtCipher.setText(cipher.base64Encode(ct));
            upTime(ns, -1);
            status("Mã hóa thành công  |  " + ns + " ns  (" + fmt(ns) + " ms)", ACC);
        } catch (Exception ex) {
            err("Lỗi mã hóa: " + ex.getMessage());
        }
    }

    private void runDecrypt() {
        if (txtCipher.getText().trim().isEmpty()) {
            err("Chưa có bản mã!");
            return;
        }
        try {
            byte[] ct = cipher.base64Decode(txtCipher.getText().trim());
            long s = System.nanoTime();
            byte[] pt = cipher.decryptCBC(ct, currentKey);
            long ns = System.nanoTime() - s;
            txtDecrypted.setText(cipher.toString(pt));
            upTime(-1, ns);
            status("Giải mã thành công  |  " + ns + " ns  (" + fmt(ns) + " ms)", GRN);
        } catch (Exception ex) {
            err("Lỗi giải mã: " + ex.getMessage() + "\nKiểm tra lại khóa!");
        }
    }

    private void runBoth() {
        if (!val())
            return;
        try {
            String plain = txtInput.getText().trim();
            long s1 = System.nanoTime();
            byte[] ct = cipher.encryptCBC(cipher.toBytes(plain), currentKey);
            long encNs = System.nanoTime() - s1;
            String b64 = cipher.base64Encode(ct);
            long s2 = System.nanoTime();
            byte[] pt = cipher.decryptCBC(ct, currentKey);
            long decNs = System.nanoTime() - s2;
            txtCipher.setText(b64);
            txtDecrypted.setText(cipher.toString(pt));
            upTime(encNs, decNs);
            String ts = new java.util.Date().toString();
            Rec r = new Rec(ts, plain, b64, cipher.toString(pt), cipher.toHex(currentKey), cipher.getKeyBits(), encNs,
                    decNs);
            history.add(r);
            String pv = b64.length() > 30 ? b64.substring(0, 30) + "..." : b64;
            tableModel.addRow(new Object[] { tableModel.getRowCount() + 1, ts, cipher.getKeyBits() + " bit", plain, pv,
                    fmt(encNs), fmt(decNs) });
            status("Hoàn tất  |  Tổng: " + fmt(encNs + decNs) + " ms", GRN);
        } catch (Exception ex) {
            err("Lỗi: " + ex.getMessage());
        }
    }

    private void clearAll() {
        txtInput.setText("");
        txtCipher.setText("");
        txtDecrypted.setText("");
        lblEncTime.setText("Mã hóa: —");
        lblDecTime.setText("Giải mã: —");
        lblTotal.setText("Tổng: —");
        status("Đã xóa tất cả", MUT);
    }

    private void saveResult() {
        if (txtCipher.getText().isEmpty()) {
            err("Chưa có kết quả!");
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("ket_qua_AES.txt"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile(), true))) {
                pw.println("=== AES-" + cipher.getKeyBits() + "/CBC/PKCS7 === " + new java.util.Date());
                pw.println("Khóa: " + txtKey.getText());
                pw.println("Bản rõ: " + txtInput.getText());
                pw.println("Bản mã: " + txtCipher.getText());
                pw.println("Giải mã: " + txtDecrypted.getText());
                pw.println(lblEncTime.getText());
                pw.println(lblDecTime.getText());
                pw.println(lblTotal.getText());
                pw.println();
                status("Đã lưu: " + fc.getSelectedFile().getName(), GRN);
            } catch (IOException ex) {
                err("Lỗi: " + ex.getMessage());
            }
        }
    }

    private void exportCSV() {
        if (history.isEmpty()) {
            err("Chưa có lịch sử!");
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("lich_su_AES.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                pw.println("STT,Thời điểm,Key bit,Văn bản gốc,Ciphertext,Mã hóa ms,Giải mã ms");
                for (int i = 0; i < history.size(); i++) {
                    Rec r = history.get(i);
                    pw.printf("%d,\"%s\",%d,\"%s\",\"%s\",%s,%s%n", i + 1, r.time, r.bits,
                            r.plain.replace("\"", "\"\""), r.ct.substring(0, Math.min(30, r.ct.length())) + "...",
                            fmt(r.encNs), fmt(r.decNs));
                }
                status("Xuất CSV: " + fc.getSelectedFile().getName(), GRN);
            } catch (IOException ex) {
                err("Lỗi: " + ex.getMessage());
            }
        }
    }

    // helpers
    private boolean val() {
        String s = txtInput.getText().trim();
        if (s.isEmpty()) {
            err("Chưa nhập văn bản!");
            return false;
        }
        if (s.length() < 15) {
            err("Văn bản phải ≥ 15 ký tự!\nHiện tại: " + s.length());
            return false;
        }
        if (currentKey == null) {
            err("Chưa có khóa!");
            return false;
        }
        return true;
    }

    private void upTime(long e, long d) {
        if (e >= 0)
            lblEncTime.setText(String.format("Mã hóa: %,d ns  (%.4f ms)", e, e / 1e6));
        if (d >= 0)
            lblDecTime.setText(String.format("Giải mã: %,d ns  (%.4f ms)", d, d / 1e6));
        if (e >= 0 && d >= 0)
            lblTotal.setText(String.format("Tổng: %.4f ms", (e + d) / 1e6));
    }

    private void upCount() {
        int n = txtInput.getText().length();
        lblCount.setText(n + " ký tự");
        lblCount.setForeground(n >= 15 ? GRN : RED);
    }

    private void status(String m, Color c) {
        lblStatus.setText(m);
        lblStatus.setForeground(c);
    }

    private void err(String m) {
        JOptionPane.showMessageDialog(this, m, "Lỗi", JOptionPane.ERROR_MESSAGE);
        status(m.split("\n")[0], RED);
    }

    private void copy(String t, String l) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(t), null);
        status("Đã copy " + l, GRN);
    }

    private String fmt(long ns) {
        return String.format("%.4f", ns / 1e6);
    }

    private JPanel createCard() {
        JPanel p = new JPanel();
        p.setBackground(PANEL);
        p.setBorder(new LineBorder(BDR, 1, true));
        return p;
    }

    private JLabel lb(String t, Color c) {
        JLabel l = new JLabel(t);
        l.setFont(BOLD);
        l.setForeground(c);
        return l;
    }

    private JButton btn(String t, Color bg, java.awt.event.ActionListener al) {
        JButton b = new JButton(t);
        b.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        b.setBackground(bg);
        b.setForeground(Color.WHITE);
        b.setFocusPainted(false);
        b.setBorderPainted(false);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setBorder(new EmptyBorder(5, 12, 5, 12));
        b.addActionListener(al);
        return b;
    }

    private JButton bigBtn(String t, Color bg, Runnable r) {
        JButton b = btn(t, bg, e -> r.run());
        b.setFont(BOLD);
        b.setMaximumSize(new Dimension(130, 38));
        b.setPreferredSize(new Dimension(130, 38));
        return b;
    }

    private JPanel textCard(String ti, Component co) {
        JPanel c = createCard();
        c.setLayout(new BorderLayout());
        JLabel l = new JLabel("  " + ti);
        l.setFont(BOLD);
        l.setForeground(MUT);
        l.setPreferredSize(new Dimension(0, 32));
        l.setBorder(new MatteBorder(0, 0, 1, 0, BDR));
        c.add(l, BorderLayout.NORTH);
        c.add(co, BorderLayout.CENTER);
        return c;
    }

    private JTextArea outArea(Color fg) {
        JTextArea a = new JTextArea();
        a.setFont(MONO);
        a.setBackground(new Color(255, 255, 255));
        a.setForeground(fg);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setBorder(new EmptyBorder(8, 10, 8, 10));
        return a;
    }

    private JScrollPane sc(JTextArea a) {
        JScrollPane sp = new JScrollPane(a);
        sp.setBorder(null);
        sp.getViewport().setBackground(new Color(255, 255, 255));
        return sp;
    }

    private JLabel tl(String t) {
        JLabel l = new JLabel(t);
        l.setFont(MONO);
        l.setForeground(TXT);
        return l;
    }

    private JSeparator vs() {
        JSeparator s = new JSeparator(JSeparator.VERTICAL);
        s.setPreferredSize(new Dimension(1, 20));
        s.setForeground(BDR);
        return s;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new AESMainGUI().setVisible(true));
    }
}
