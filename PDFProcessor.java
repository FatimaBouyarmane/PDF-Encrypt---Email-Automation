import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.text.PDFTextStripper;

import javax.activation.DataHandler;
import javax.mail.util.ByteArrayDataSource;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.util.Properties;
import java.util.regex.*;
import javax.mail.*;
import javax.mail.internet.*;

public class PDFProcessor {

    // CIN formats: X1111 or XX111
    private static final String CIN_REGEX = "([A-Z][0-9]{6})|([A-Z]{2}[0-9]{5})";

    // ---------------- Extract CIN ----------------
    public static String extractCINFromPDF(File file) throws Exception {
        PDDocument document = PDDocument.load(file);
        PDFTextStripper stripper = new PDFTextStripper();
        String text = stripper.getText(document);
        document.close();

        Pattern pattern = Pattern.compile(CIN_REGEX);
        Matcher matcher = pattern.matcher(text);

        String foundCIN = null;
        int count = 0;

        while (matcher.find()) {
            foundCIN = matcher.group();
            count++;
        }

        if (count == 0) {
            throw new Exception("No CIN found in " + file.getName());
        } else if (count > 1) {
            throw new Exception("Multiple CINs found in " + file.getName());
        }

        return foundCIN;
    }

    // ---------------- Password-Protect PDF ----------------
    public static byte[] passwordProtectPDF(File file, String password) throws Exception {
        // Load the original PDF
        PDDocument document = PDDocument.load(file);
        
        // Set up access permissions
        AccessPermission accessPermission = new AccessPermission();
        accessPermission.setCanPrint(true);
        accessPermission.setCanModify(false);
        accessPermission.setCanExtractContent(false);
        accessPermission.setCanModifyAnnotations(false);
        
        // Create protection policy with password
        StandardProtectionPolicy protectionPolicy = new StandardProtectionPolicy(
            password,        // Owner password (for full access)
            password,        // User password (for opening the document)
            accessPermission // Permissions
        );
        
        // Set encryption key length (128-bit AES)
        protectionPolicy.setEncryptionKeyLength(128);
        
        // Apply protection to the document
        document.protect(protectionPolicy);
        
        // Save to byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        document.save(baos);
        document.close();
        
        return baos.toByteArray();
    }

    // ---------------- Store in SQLite ----------------
    public static void storeInDatabase(String filename, String cin, byte[] protectedPDF) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:files.db");
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, cin TEXT, protected_pdf BLOB, password TEXT)");

        PreparedStatement pstmt = conn.prepareStatement("INSERT INTO files(filename, cin, protected_pdf, password) VALUES (?, ?, ?, ?)");
        pstmt.setString(1, filename);
        pstmt.setString(2, cin);
        pstmt.setBytes(3, protectedPDF);
        pstmt.setString(4, cin); // Password is the CIN
        pstmt.executeUpdate();

        conn.close();
    }

    // ---------------- Send Email - FIXED VERSION ----------------
    public static void sendEmail(String toEmail, String subject, String body, String filename, byte[] attachmentData) throws Exception {
        final String fromEmail = "xyz@gmail.com"; 
        final String password = "app_password"; // Your App Password

        // Enhanced Gmail SMTP configuration
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");
        
        // Additional SSL/TLS properties for better compatibility
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");
        props.put("mail.smtp.writetimeout", "10000");

        // Create session with authentication
        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(fromEmail, password);
            }
        });

        session.setDebug(false); 

        try {
            // Build the message
            Message msg = new MimeMessage(session);
            msg.setFrom(new InternetAddress(fromEmail));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail, false));
            msg.setSubject(subject);

            // Body + attachment
            Multipart multipart = new MimeMultipart();

            // Text body
            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(body);
            multipart.addBodyPart(textPart);

            // Attachment
            if (attachmentData != null && filename != null) {
                MimeBodyPart attachmentPart = new MimeBodyPart();
                attachmentPart.setFileName(filename);
                attachmentPart.setDataHandler(new DataHandler(new ByteArrayDataSource(attachmentData, "application/pdf")));
                multipart.addBodyPart(attachmentPart);
            }

            msg.setContent(multipart);

            // Send with retry mechanism
            int maxRetries = 3;
            for (int i = 0; i < maxRetries; i++) {
                try {
                    Transport.send(msg);
                    System.out.println("Email sent successfully to " + toEmail);
                    return;
                } catch (MessagingException e) {
                    if (i == maxRetries - 1) {
                        throw e;
                    }
                    Thread.sleep(2000); // Wait 2 seconds before retry
                }
            }
        } catch (Exception e) {
            throw e;
        }
    }

    // ---------------- Alternative Gmail SMTP method with port 465 ----------------
    public static void sendEmailSecure(String toEmail, String subject, String body, String filename, byte[] attachmentData) throws Exception {
        final String fromEmail = "xyz@gmail.com"; 
        final String password = "app_password";

        // Gmail SMTP with SSL (port 465)
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", "true");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");

        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(fromEmail, password);
            }
        });

        Message msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(fromEmail));
        msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail, false));
        msg.setSubject(subject);

        Multipart multipart = new MimeMultipart();

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body);
        multipart.addBodyPart(textPart);

        if (attachmentData != null && filename != null) {
            MimeBodyPart attachmentPart = new MimeBodyPart();
            attachmentPart.setFileName(filename);
            attachmentPart.setDataHandler(new DataHandler(new ByteArrayDataSource(attachmentData, "application/pdf")));
            multipart.addBodyPart(attachmentPart);
        }

        msg.setContent(multipart);
        Transport.send(msg);
        System.out.println("Email sent successfully to " + toEmail + " via SSL");
    }

    // ---------------- Process Folder ----------------
    public static void processFolder(String folderPath, String receiverEmail) throws Exception {
        Files.list(Paths.get(folderPath)).forEach(path -> {
            try {
                File file = path.toFile();
                if (!file.getName().toLowerCase().endsWith(".pdf")) return;

                String cin = extractCINFromPDF(file);

                // Create password-protected PDF using CIN as password
                byte[] protectedPDF = passwordProtectPDF(file, cin);

                // Store in database
                storeInDatabase(file.getName(), cin, protectedPDF);
                
                // Prepare email content
                String emailSubject = "Protected PDF: " + file.getName();
                String emailBody = "Dear recipient,\n\n" +
                                 "Please find attached the password-protected PDF file: " + file.getName() + "\n\n" +
                                 "Password to open the file: " + cin + "\n\n" +
                                 "Simply open the PDF with any PDF reader and enter the password when prompted.\n\n" +
                                 "Best regards";
                
                try {
                    sendEmailSecure(receiverEmail,
                            emailSubject,
                            emailBody,
                            file.getName(),
                            protectedPDF);
                } catch (Exception e) {
                    sendEmail(receiverEmail,
                            emailSubject,
                            emailBody,
                            file.getName(),
                            protectedPDF);
                }

                System.out.println("Processed and sent " + file.getName() + " with password: " + cin);

            } catch (Exception e) {
                System.out.println("Skipping " + path.getFileName() + ": " + e.getMessage());
            }
        });
    }

    public static void main(String[] args) throws Exception {
        processFolder("input_pdfs", "ssss@gmail.com");
    }
}