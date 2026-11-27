import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class GramOneServer {
    private static final int MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
    private static final String DEMO_USERNAME = "demo";
    private static final String DEMO_PASSWORD = "gramone123";
    private static final int PASSWORD_ITERATIONS = 310_000;
    private static final int PASSWORD_HASH_BYTES = 32;
    private static final int PASSWORD_SALT_BYTES = 16;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("[a-zA-Z0-9._-]{3,32}");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private static final CopyOnWriteArrayList<Complaint> complaints = new CopyOnWriteArrayList<>();
    private static final CopyOnWriteArrayList<Feedback> feedbackEntries = new CopyOnWriteArrayList<>();

    public static void main(String[] args) throws IOException {
        try {
            initializeAccountDatabase();
        } catch (SQLException error) {
            System.err.println("Unable to initialize the PostgreSQL account database: " + error.getMessage());
            System.err.println("Check GRAMONE_DB_URL, GRAMONE_DB_USER, and GRAMONE_DB_PASSWORD.");
            System.err.println("Starting the website; registration and non-demo accounts need PostgreSQL.");
        }
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", GramOneServer::handleIndex);
        server.createContext("/login", GramOneServer::handleAccountAccess);
        server.createContext("/register", GramOneServer::handleAccountAccess);
        server.createContext("/api/complaints", GramOneServer::handleComplaints);
        server.createContext("/api/attachments", GramOneServer::handleAttachment);
        server.createContext("/api/feedback", GramOneServer::handleFeedback);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("GramOne is running at http://localhost:" + port);
    }

    private static void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method Not Allowed");
            return;
        }
        String path = exchange.getRequestURI().getPath();
        boolean authenticated = hasSession(exchange);
        String html;
        switch (path) {
            case "/login" -> {
                if (authenticated) {
                    redirect(exchange, "/");
                    return;
                }
                html = loginPage(safeNext(param(exchange.getRequestURI().getRawQuery(), "next")));
            }
            case "/file", "/track", "/feedback" -> {
                if (!authenticated) {
                    redirect(exchange, "/login?next=" + path);
                    return;
                }
                html = switch (path) {
                    case "/file" -> filePage();
                    case "/track" -> trackPage();
                    default -> feedbackPage();
                };
            }
            case "/" -> html = homePage(authenticated);
            case "/logout" -> {
                logout(exchange);
                redirect(exchange, "/login");
                return;
            }
            default -> {
                send(exchange, 404, "text/plain", "Not Found");
                return;
            }
        }
        send(exchange, 200, "text/html; charset=UTF-8", html);
    }

    private static void handleAccountAccess(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        boolean registering = "/register".equals(path);
        if (!registering && !"/login".equals(path)) {
            send(exchange, 404, "text/plain", "Not Found");
            return;
        }
        if ("GET".equals(exchange.getRequestMethod())) {
            if (hasSession(exchange)) {
                redirect(exchange, "/");
                return;
            }
            String next = safeNext(param(exchange.getRequestURI().getRawQuery(), "next"));
            send(exchange, 200, "text/html; charset=UTF-8", registering ? registerPage(next) : loginPage(next));
            return;
        }
        if (!"POST".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method Not Allowed");
            return;
        }
        String body;
        try {
            body = new String(readLimited(exchange.getRequestBody(), 4096), StandardCharsets.UTF_8);
        } catch (PayloadTooLargeException error) {
            send(exchange, 413, "text/plain; charset=UTF-8", "Login request is too large");
            return;
        }
        String identifier = param(body, "identifier");
        String password = param(body, "password");
        String next = safeNext(param(body, "next"));
        if (registering) {
            String fullName = param(body, "fullName");
            String username = param(body, "username");
            String email = param(body, "email");
            String passwordConfirm = param(body, "passwordConfirm");
            String validationError = validateRegistration(fullName, username, email, password, passwordConfirm);
            if (validationError != null) {
                send(exchange, 400, "text/html; charset=UTF-8", registerPage(next, validationError));
                return;
            }
            try {
                createAccount(fullName.trim(), username.trim(), email.trim(), password);
                authenticate(exchange, username.trim());
                redirect(exchange, next);
            } catch (SQLException error) {
                if ("23505".equals(error.getSQLState())) {
                    send(exchange, 409, "text/html; charset=UTF-8",
                            registerPage(next, "That username or email is already registered."));
                } else {
                    System.err.println("Account registration failed: " + error.getMessage());
                    send(exchange, 503, "text/html; charset=UTF-8",
                            registerPage(next, "Account service is temporarily unavailable. Please try again."));
                }
            } catch (GeneralSecurityException error) {
                System.err.println("Password hashing failed: " + error.getMessage());
                send(exchange, 500, "text/html; charset=UTF-8",
                        registerPage(next, "Unable to securely create the account. Please try again."));
            }
            return;
        }
        if (identifier == null || identifier.isBlank() || password == null || password.isEmpty()) {
            send(exchange, 400, "text/html; charset=UTF-8", loginPage(next, "Enter your username or email and password."));
            return;
        }
        if (DEMO_USERNAME.equalsIgnoreCase(identifier.trim()) && DEMO_PASSWORD.equals(password)) {
            authenticate(exchange, DEMO_USERNAME);
            redirect(exchange, next);
            return;
        }
        try {
            Account account = findAccount(identifier.trim());
            if (account != null && verifyPassword(password, account.passwordSalt, account.passwordHash)) {
                authenticate(exchange, account.username);
                redirect(exchange, next);
                return;
            }
        } catch (SQLException error) {
            System.err.println("Account sign-in failed: " + error.getMessage());
            send(exchange, 503, "text/html; charset=UTF-8",
                    loginPage(next, "Account service is temporarily unavailable. Please try again."));
            return;
        } catch (GeneralSecurityException error) {
            System.err.println("Password verification failed: " + error.getMessage());
            send(exchange, 500, "text/html; charset=UTF-8", loginPage(next, "Unable to verify your sign-in."));
            return;
        }
        send(exchange, 401, "text/html; charset=UTF-8", loginPage(next, "Invalid username/email or password."));
    }

    private static void handleFeedback(HttpExchange exchange) throws IOException {
        if (!requireSession(exchange)) return;
        if (!"POST".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method Not Allowed");
            return;
        }
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String complaintId = json(body, "complaintId");
        String rating = json(body, "rating");
        String message = json(body, "message");
        if (complaintId == null || complaintId.isBlank() || rating == null || message == null || message.isBlank()) {
            send(exchange, 400, "application/json", "{\"error\":\"Please complete all required fields\"}");
            return;
        }
        feedbackEntries.add(new Feedback(complaintId.trim(), rating, message.trim()));
        send(exchange, 201, "application/json", "{\"success\":true}");
    }

    private static void handleComplaints(HttpExchange exchange) throws IOException {
        if (!requireSession(exchange)) return;
        String method = exchange.getRequestMethod();
        if ("GET".equals(method)) {
            String query = exchange.getRequestURI().getRawQuery();
            String status = param(query, "status");
            String category = param(query, "category");
            String search = param(query, "search");
            List<Complaint> result = new ArrayList<>();
            for (Complaint complaint : complaints) {
                if (status != null && !status.isBlank() && !"All".equalsIgnoreCase(status)
                        && !complaint.status.equalsIgnoreCase(status)) continue;
                if (category != null && !category.isBlank() && !"All".equalsIgnoreCase(category)
                        && !complaint.category.equalsIgnoreCase(category)) continue;
                if (search != null && !search.isBlank()) {
                    String haystack = (complaint.title + " " + complaint.id + " " + complaint.ward).toLowerCase();
                    if (!haystack.contains(search.toLowerCase())) continue;
                }
                result.add(complaint);
            }
            send(exchange, 200, "application/json; charset=UTF-8", complaintsJson(result));
            return;
        }

        if ("POST".equals(method)) {
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("multipart/form-data;")) {
                send(exchange, 400, "application/json", "{\"error\":\"Complaint form must use multipart form data\"}");
                return;
            }
            String boundary = multipartBoundary(contentType);
            if (boundary == null) {
                send(exchange, 400, "application/json", "{\"error\":\"Invalid upload form boundary\"}");
                return;
            }
            String lengthHeader = exchange.getRequestHeaders().getFirst("Content-Length");
            if (lengthHeader != null && Long.parseLong(lengthHeader) > MAX_UPLOAD_BYTES + 65536L) {
                send(exchange, 413, "application/json", "{\"error\":\"Upload must be smaller than 10 MB\"}");
                return;
            }
            byte[] requestBody;
            try {
                requestBody = readLimited(exchange.getRequestBody(), MAX_UPLOAD_BYTES + 65536);
            } catch (PayloadTooLargeException error) {
                send(exchange, 413, "application/json", "{\"error\":\"Upload must be smaller than 10 MB\"}");
                return;
            }
            MultipartForm form;
            try {
                form = parseMultipart(requestBody, boundary);
            } catch (IllegalArgumentException error) {
                send(exchange, 400, "application/json", "{\"error\":\"Invalid complaint form data\"}");
                return;
            }
            String title = form.fields.get("title");
            String category = form.fields.get("category");
            String ward = form.fields.get("ward");
            String name = form.fields.get("name");
            if (title == null || title.isBlank() || category == null || ward == null || name == null) {
                send(exchange, 400, "application/json", "{\"error\":\"Please complete all required fields\"}");
                return;
            }
            StoredFile attachment = form.file;
            if (attachment != null && attachment.data.length > MAX_UPLOAD_BYTES) {
                send(exchange, 413, "application/json", "{\"error\":\"Attachment must be smaller than 10 MB\"}");
                return;
            }
            if (attachment != null && !allowedAttachment(attachment.filename)) {
                send(exchange, 400, "application/json", "{\"error\":\"Attach a JPG, PNG, GIF, WEBP, PDF, or TXT file\"}");
                return;
            }
            String id = "GP-" + LocalDate.now().getYear() + "-" + String.format("%04d", 1000 + complaints.size() + (int)(Math.random() * 700));
            String date = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE);
            Complaint complaint = new Complaint(id, title.trim(), category, ward, name.trim(), "Raised", date, attachment);
            complaints.add(0, complaint);
            send(exchange, 201, "application/json", "{\"success\":true,\"id\":\"" + id + "\"}");
            return;
        }
        send(exchange, 405, "text/plain", "Method Not Allowed");
    }

    private static void handleAttachment(HttpExchange exchange) throws IOException {
        if (!requireSession(exchange)) return;
        if (!"GET".equals(exchange.getRequestMethod())) {
            send(exchange, 405, "text/plain", "Method Not Allowed");
            return;
        }
        String path = exchange.getRequestURI().getPath();
        String prefix = "/api/attachments/";
        String suffix = "/file";
        if (!path.startsWith(prefix) || !path.endsWith(suffix)) {
            send(exchange, 404, "text/plain", "Not Found");
            return;
        }
        String id = path.substring(prefix.length(), path.length() - suffix.length());
        Complaint complaint = complaints.stream().filter(item -> item.id.equals(id)).findFirst().orElse(null);
        if (complaint == null || complaint.attachment == null) {
            send(exchange, 404, "text/plain; charset=UTF-8", "Attachment not found");
            return;
        }
        exchange.getResponseHeaders().set("Content-Type", complaint.attachment.contentType);
        exchange.getResponseHeaders().set("Content-Disposition",
                "attachment; filename=\"" + safeHeaderFilename(complaint.attachment.filename) + "\"");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, complaint.attachment.data.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(complaint.attachment.data);
        }
    }

    private static String multipartBoundary(String contentType) {
        for (String part : contentType.split(";")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase(Locale.ROOT).startsWith("boundary=")) {
                String boundary = trimmed.substring("boundary=".length()).trim();
                if (boundary.length() >= 2 && boundary.startsWith("\"") && boundary.endsWith("\"")) {
                    boundary = boundary.substring(1, boundary.length() - 1);
                }
                return boundary.isBlank() || boundary.length() > 200 ? null : boundary;
            }
        }
        return null;
    }

    private static byte[] readLimited(InputStream input, int limit) throws IOException {
        byte[] buffer = new byte[8192];
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (output.size() + read > limit) throw new PayloadTooLargeException();
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static MultipartForm parseMultipart(byte[] body, String boundary) {
        String raw = new String(body, StandardCharsets.ISO_8859_1);
        String delimiter = "--" + boundary;
        String partSeparator = "\r\n" + delimiter;
        Map<String, String> fields = new HashMap<>();
        StoredFile file = null;
        int cursor = raw.indexOf(delimiter);
        if (cursor < 0) throw new IllegalArgumentException("Missing multipart delimiter");
        while (cursor >= 0) {
            cursor += delimiter.length();
            if (raw.startsWith("--", cursor)) break;
            if (!raw.startsWith("\r\n", cursor)) throw new IllegalArgumentException("Malformed multipart delimiter");
            int headerStart = cursor + 2;
            int contentStart = raw.indexOf("\r\n\r\n", headerStart);
            if (contentStart < 0) throw new IllegalArgumentException("Missing multipart headers");
            String headers = raw.substring(headerStart, contentStart);
            contentStart += 4;
            int contentEnd = raw.indexOf(partSeparator, contentStart);
            if (contentEnd < 0) throw new IllegalArgumentException("Missing multipart terminator");

            String disposition = headerValue(headers, "Content-Disposition");
            String fieldName = dispositionParameter(disposition, "name");
            String filename = dispositionParameter(disposition, "filename");
            if (fieldName != null && filename != null && !filename.isBlank()) {
                String cleanFilename = safeHeaderFilename(filename);
                int startByte = contentStart;
                int endByte = contentEnd;
                byte[] fileBytes = java.util.Arrays.copyOfRange(body, startByte, endByte);
                file = new StoredFile(cleanFilename, attachmentContentType(cleanFilename), fileBytes);
            } else if (fieldName != null) {
                fields.put(fieldName, new String(body, contentStart, contentEnd - contentStart, StandardCharsets.UTF_8));
            }
            cursor = contentEnd + 2;
        }
        return new MultipartForm(fields, file);
    }

    private static String headerValue(String headers, String name) {
        for (String line : headers.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return "";
    }

    private static String dispositionParameter(String disposition, String key) {
        String marker = key + "=";
        int start = disposition.toLowerCase(Locale.ROOT).indexOf(marker.toLowerCase(Locale.ROOT));
        if (start < 0) return null;
        start += marker.length();
        if (start < disposition.length() && disposition.charAt(start) == '"') {
            int end = disposition.indexOf('"', start + 1);
            return end < 0 ? null : disposition.substring(start + 1, end);
        }
        int end = disposition.indexOf(';', start);
        return (end < 0 ? disposition.substring(start) : disposition.substring(start, end)).trim();
    }

    private static boolean allowedAttachment(String filename) {
        String lower = filename.toLowerCase(Locale.ROOT);
        return lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png")
                || lower.endsWith(".gif") || lower.endsWith(".webp") || lower.endsWith(".pdf")
                || lower.endsWith(".txt");
    }

    private static String attachmentContentType(String filename) {
        String lower = filename.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".gif")) return "image/gif";
        if (lower.endsWith(".webp")) return "image/webp";
        if (lower.endsWith(".pdf")) return "application/pdf";
        return "text/plain; charset=UTF-8";
    }

    private static String safeHeaderFilename(String filename) {
        String cleaned = filename.replace("\\", "/");
        cleaned = cleaned.substring(cleaned.lastIndexOf('/') + 1).replaceAll("[\\r\\n\\\"]", "_");
        return cleaned.isBlank() ? "attachment" : cleaned;
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String param(String query, String key) {
        if (query == null) return null;
        for (String part : query.split("&")) {
            String[] pair = part.split("=", 2);
            if (pair.length == 2 && pair[0].equalsIgnoreCase(key)) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String json(String body, String key) {
        String marker = "\"" + key + "\"";
        int index = body.indexOf(marker);
        if (index < 0) return null;
        int colon = body.indexOf(':', index + marker.length());
        if (colon < 0) return null;
        int quote = body.indexOf('"', colon);
        if (quote < 0) return null;
        int end = quote + 1;
        StringBuilder value = new StringBuilder();
        while (end < body.length()) {
            char c = body.charAt(end++);
            if (c == '\\' && end < body.length()) {
                char escaped = body.charAt(end++);
                value.append(escaped == 'n' ? '\n' : escaped);
            } else if (c == '"') {
                break;
            } else {
                value.append(c);
            }
        }
        return value.toString();
    }

    private static String complaintsJson(List<Complaint> data) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < data.size(); i++) {
            Complaint c = data.get(i);
            if (i > 0) sb.append(',');
            sb.append('{')
              .append("\"id\":\"").append(esc(c.id)).append("\",")
              .append("\"title\":\"").append(esc(c.title)).append("\",")
              .append("\"category\":\"").append(esc(c.category)).append("\",")
              .append("\"ward\":\"").append(esc(c.ward)).append("\",")
              .append("\"name\":\"").append(esc(c.name)).append("\",")
              .append("\"status\":\"").append(esc(c.status)).append("\",")
              .append("\"date\":\"").append(esc(c.date)).append("\",")
              .append("\"attachmentName\":").append(c.attachment == null ? "null" : "\"" + jsonEscape(c.attachment.filename) + "\"").append(',')
              .append("\"attachmentUrl\":").append(c.attachment == null ? "null" : "\"/api/attachments/" + esc(c.id) + "/file\"").append('}');
        }
        return sb.append(']').toString();
    }

    private static String esc(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private record Complaint(String id, String title, String category, String ward, String name, String status, String date, StoredFile attachment) {}
    private record Feedback(String complaintId, String rating, String message) {}
    private record Account(String fullName, String username, String email, byte[] passwordSalt, byte[] passwordHash) {}
    private record Session(String username, long expiresAt) {}
    private record StoredFile(String filename, String contentType, byte[] data) {}
    private record MultipartForm(Map<String, String> fields, StoredFile file) {}
    private static class PayloadTooLargeException extends IOException {}

    private static boolean hasSession(HttpExchange exchange) {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader == null) return false;
        for (String cookie : cookieHeader.split(";")) {
            String[] parts = cookie.trim().split("=", 2);
            if (parts.length == 2 && parts[0].equals("GRAMONE_SESSION")) {
                Session session = sessions.get(parts[1]);
                if (session == null) return false;
                if (session.expiresAt > System.currentTimeMillis()) return true;
                sessions.remove(parts[1]);
                return false;
            }
        }
        return false;
    }

    private static boolean requireSession(HttpExchange exchange) throws IOException {
        if (hasSession(exchange)) return true;
        send(exchange, 401, "application/json; charset=UTF-8", "{\"error\":\"Please sign in to continue\"}");
        return false;
    }

    private static void setSessionCookie(HttpExchange exchange, String token) {
        exchange.getResponseHeaders().add("Set-Cookie",
                "GRAMONE_SESSION=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800");
    }

    private static void authenticate(HttpExchange exchange, String username) {
        String token = UUID.randomUUID().toString();
        sessions.put(token, new Session(username, System.currentTimeMillis() + 8 * 60 * 60 * 1000L));
        setSessionCookie(exchange, token);
    }

    private static void initializeAccountDatabase() throws SQLException {
        String url = environment("GRAMONE_DB_URL", "jdbc:postgresql://localhost:5432/gramone");
        String user = environment("GRAMONE_DB_USER", "gramone");
        String password = System.getenv("GRAMONE_DB_PASSWORD");
        if (password == null || password.isBlank()) {
            throw new SQLException("GRAMONE_DB_PASSWORD is not set.");
        }
        try (Connection connection = DriverManager.getConnection(url, user, password);
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS gramone_accounts (
                        id BIGSERIAL PRIMARY KEY,
                        full_name VARCHAR(100) NOT NULL,
                        username VARCHAR(32) NOT NULL UNIQUE,
                        email VARCHAR(254) NOT NULL UNIQUE,
                        password_salt BYTEA NOT NULL,
                        password_hash BYTEA NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """);
        }
    }

    private static String environment(String key, String defaultValue) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static String validateRegistration(String fullName, String username, String email,
                                               String password, String passwordConfirm) {
        if (fullName == null || fullName.trim().length() < 2 || fullName.trim().length() > 100) {
            return "Enter your name (2 to 100 characters).";
        }
        if (username == null || !USERNAME_PATTERN.matcher(username.trim()).matches()) {
            return "Username must be 3 to 32 characters and use letters, numbers, dots, underscores, or hyphens.";
        }
        if (email == null || email.length() > 254 || !EMAIL_PATTERN.matcher(email.trim()).matches()) {
            return "Enter a valid email address.";
        }
        if (password == null || password.length() < 10 || password.length() > 128) {
            return "Password must be between 10 and 128 characters.";
        }
        if (!password.equals(passwordConfirm)) {
            return "The passwords do not match.";
        }
        return null;
    }

    private static void createAccount(String fullName, String username, String email, String password)
            throws SQLException, GeneralSecurityException {
        byte[] salt = new byte[PASSWORD_SALT_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        byte[] passwordHash = passwordHash(password, salt);
        String sql = """
                INSERT INTO gramone_accounts (full_name, username, email, password_salt, password_hash)
                VALUES (?, ?, ?, ?, ?)
                """;
        try (Connection connection = accountConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, fullName.trim());
            statement.setString(2, username.trim().toLowerCase(Locale.ROOT));
            statement.setString(3, email.trim().toLowerCase(Locale.ROOT));
            statement.setBytes(4, salt);
            statement.setBytes(5, passwordHash);
            statement.executeUpdate();
        } finally {
            Arrays.fill(passwordHash, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    private static Account findAccount(String identifier) throws SQLException {
        String sql = """
                SELECT full_name, username, email, password_salt, password_hash
                FROM gramone_accounts
                WHERE username = ? OR email = ?
                """;
        String normalized = identifier.toLowerCase(Locale.ROOT);
        try (Connection connection = accountConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalized);
            statement.setString(2, normalized);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) return null;
                return new Account(result.getString("full_name"), result.getString("username"),
                        result.getString("email"), result.getBytes("password_salt"),
                        result.getBytes("password_hash"));
            }
        }
    }

    private static Connection accountConnection() throws SQLException {
        return DriverManager.getConnection(
                environment("GRAMONE_DB_URL", "jdbc:postgresql://localhost:5432/gramone"),
                environment("GRAMONE_DB_USER", "gramone"),
                System.getenv("GRAMONE_DB_PASSWORD"));
    }

    private static boolean verifyPassword(String password, byte[] salt, byte[] expectedHash)
            throws GeneralSecurityException {
        byte[] actualHash = passwordHash(password, salt);
        try {
            return MessageDigest.isEqual(actualHash, expectedHash);
        } finally {
            Arrays.fill(actualHash, (byte) 0);
        }
    }

    private static byte[] passwordHash(String password, byte[] salt) throws GeneralSecurityException {
        char[] passwordChars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, PASSWORD_ITERATIONS, PASSWORD_HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            Arrays.fill(passwordChars, '\0');
        }
    }

    private static void logout(HttpExchange exchange) {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader != null) {
            for (String cookie : cookieHeader.split(";")) {
                String[] parts = cookie.trim().split("=", 2);
                if (parts.length == 2 && parts[0].equals("GRAMONE_SESSION")) {
                    sessions.remove(parts[1]);
                }
            }
        }
        exchange.getResponseHeaders().add("Set-Cookie",
                "GRAMONE_SESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(303, -1);
        exchange.close();
    }

    private static String safeNext(String next) {
        if ("/file".equals(next) || "/track".equals(next) || "/feedback".equals(next)) return next;
        return "/";
    }

    private static String htmlEscape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String homePage(boolean authenticated) {
        String content = """
<header class="page-heading"><span class="eyebrow">GRAM PANCHAYAT PORTAL</span><h1>Services</h1><p>Select a service to continue.</p></header>
<section class="service-grid">
  <a class="service-card" href="/file"><span class="service-number">01</span><h2>File complaint</h2><p>Submit an issue to your Gram Panchayat.</p><span class="card-arrow">Open service <b>→</b></span></a>
  <a class="service-card" href="/track"><span class="service-number">02</span><h2>Track complaint</h2><p>Check the latest status of a submitted complaint.</p><span class="card-arrow">Open service <b>→</b></span></a>
  <a class="service-card" href="/feedback"><span class="service-number">03</span><h2>Complaint feedback</h2><p>Share feedback about a complaint or its resolution.</p><span class="card-arrow">Open service <b>→</b></span></a>
</section>
""";
        return pageHtml("Services", content, "", authenticated);
    }

    private static String loginPage(String next) {
        return loginPage(next, "");
    }

    private static String loginPage(String next, String error) {
        String content = """
<header class="page-heading"><span class="eyebrow">ACCOUNT ACCESS</span><h1>Sign in</h1><p>Sign in to use GramOne services.</p></header>
<form class="form-card login-card" method="post" action="/login">
  <input type="hidden" name="next" value="__NEXT__">
  <div class="field"><label for="identifier">Username or email</label><input id="identifier" name="identifier" required autocomplete="username" placeholder="Enter your username or email"></div>
  <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password" placeholder="Enter your password"></div>
  <p class="login-error" role="alert">__ERROR__</p>
  <div class="form-actions"><button class="btn btn-primary" type="submit">Sign in</button></div>
  <aside class="demo-hint"><strong>Temporary demo account</strong><span>Username: <code>demo</code></span><span>Password: <code>gramone123</code></span></aside>
  <p class="account-prompt">New to GramOne? <a href="/register?next=__NEXT__">Create an account</a></p>
</form>
""".replace("__NEXT__", htmlEscape(next)).replace("__ERROR__", htmlEscape(error));
        return pageHtml("Sign in", content, "", false);
    }

    private static String registerPage(String next) {
        return registerPage(next, "");
    }

    private static String registerPage(String next, String error) {
        String content = """
<header class="page-heading"><span class="eyebrow">ACCOUNT ACCESS</span><h1>Create account</h1><p>Register to use GramOne services.</p></header>
<form class="form-card login-card" method="post" action="/register">
  <input type="hidden" name="next" value="__NEXT__">
  <div class="field"><label for="fullName">Full name</label><input id="fullName" name="fullName" required maxlength="100" autocomplete="name" placeholder="Your full name"></div>
  <div class="field"><label for="username">Username</label><input id="username" name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9._-]{3,32}" autocomplete="username" placeholder="Choose a username"></div>
  <div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" required maxlength="254" autocomplete="email" placeholder="you@example.com"></div>
  <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="At least 10 characters"></div>
  <div class="field"><label for="passwordConfirm">Confirm password</label><input id="passwordConfirm" name="passwordConfirm" type="password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="Enter the password again"></div>
  <p class="login-error" role="alert">__ERROR__</p>
  <div class="form-actions"><button class="btn btn-primary" type="submit">Create account</button></div>
  <p class="account-prompt">Already registered? <a href="/login?next=__NEXT__">Sign in</a></p>
</form>
""".replace("__NEXT__", htmlEscape(next)).replace("__ERROR__", htmlEscape(error));
        return pageHtml("Create account", content, "", false);
    }

    private static String filePage() {
        String content = """
<header class="page-heading"><span class="eyebrow">SERVICE 01</span><h1>File complaint</h1><p>Enter the issue details and submit your complaint.</p></header>
<form class="form-card" id="complaintForm">
  <div class="field"><label for="title">Complaint title</label><input id="title" name="title" required maxlength="140" placeholder="Brief description of the issue"></div>
  <div class="form-grid">
    <div class="field"><label for="category">Category</label><select id="category" name="category" required><option value="">Select category</option><option>Roads</option><option>Water</option><option>Sanitation</option><option>Lighting</option><option>Health</option><option>Other</option></select></div>
    <div class="field"><label for="ward">Ward</label><select id="ward" name="ward" required><option value="">Select ward</option><option>Ward 1</option><option>Ward 2</option><option>Ward 3</option><option>Ward 4</option><option>Ward 5</option><option>Ward 6</option></select></div>
  </div>
  <div class="field"><label for="name">Your name</label><input id="name" name="name" required maxlength="100" placeholder="Full name"></div>
  <div class="field"><label for="details">Additional details</label><textarea id="details" name="details" maxlength="1000" placeholder="Location or other relevant details"></textarea></div>
  <div class="field"><label for="attachment">Attach a file <span class="optional">(optional)</span></label><input id="attachment" name="attachment" type="file" accept=".jpg,.jpeg,.png,.gif,.webp,.pdf,.txt,image/jpeg,image/png,image/gif,image/webp,application/pdf,text/plain"><small class="field-hint">JPG, PNG, GIF, WEBP, PDF, or TXT · Up to 10 MB</small></div>
  <div class="form-actions"><button class="btn btn-primary" type="submit">Submit complaint</button></div>
  <p class="form-message" id="formMessage" role="status"></p>
</form>
""";
        String script = """
document.getElementById('complaintForm').addEventListener('submit',async e=>{
  e.preventDefault();const message=document.getElementById('formMessage');message.textContent='Submitting...';
  const file=document.getElementById('attachment').files[0];
  if(file&&file.size>10*1024*1024){message.textContent='Attachment must be smaller than 10 MB';return}
  try{
    const response=await fetch('/api/complaints',{method:'POST',body:new FormData(e.target)});
    const result=await response.json();if(!response.ok)throw new Error(result.error||'Unable to submit complaint');
    message.textContent='Complaint submitted. Reference ID: '+result.id;e.target.reset();
  }catch(error){message.textContent=error.message}
});
""";
        return pageHtml("File complaint", content, script, true);
    }

    private static String trackPage() {
        String content = """
<header class="page-heading"><span class="eyebrow">SERVICE 02</span><h1>Track complaint</h1><p>Enter the reference ID you received when filing your complaint.</p></header>
<form class="form-card compact" id="trackForm">
  <div class="field"><label for="complaintId">Complaint reference ID</label><div class="input-action"><input id="complaintId" required placeholder="e.g. GP-2026-1042"><button class="btn btn-primary" type="submit">Track</button></div></div>
  <section class="result-card" id="trackResult" aria-live="polite">Complaint status will appear here.</section>
</form>
""";
        String script = """
document.getElementById('trackForm').addEventListener('submit',async e=>{
  e.preventDefault();const id=document.getElementById('complaintId').value.trim();const box=document.getElementById('trackResult');box.textContent='Searching...';
  try{
    const response=await fetch('/api/complaints');if(!response.ok)throw new Error('Unable to load complaints');
    const data=await response.json();const complaint=data.find(item=>item.id.toLowerCase()===id.toLowerCase());
    if(!complaint){box.textContent='No complaint found with that reference ID.';return}
    const attachment=complaint.attachmentUrl?'<p><a class="attachment-link" href="'+escapeHtml(complaint.attachmentUrl)+'">Download attachment: '+escapeHtml(complaint.attachmentName)+'</a></p>':'';
    box.innerHTML='<span class="status">'+escapeHtml(complaint.status)+'</span><h2>'+escapeHtml(complaint.title)+'</h2><p>'+escapeHtml(complaint.id)+' · '+escapeHtml(complaint.category)+' · '+escapeHtml(complaint.ward)+'</p><small>Filed '+escapeHtml(complaint.date)+'</small>'+attachment;
  }catch(error){box.textContent=error.message}
});
function escapeHtml(value){const node=document.createElement('span');node.textContent=value;return node.innerHTML}
""";
        return pageHtml("Track complaint", content, script, true);
    }

    private static String feedbackPage() {
        String content = """
<header class="page-heading"><span class="eyebrow">SERVICE 03</span><h1>Complaint feedback</h1><p>Send feedback about a complaint or its resolution.</p></header>
<form class="form-card" id="feedbackForm">
  <div class="field"><label for="feedbackComplaintId">Complaint reference ID</label><input id="feedbackComplaintId" name="complaintId" required placeholder="e.g. GP-2026-1042"></div>
  <div class="field"><label for="rating">Your rating</label><select id="rating" name="rating" required><option value="">Select a rating</option><option value="5">5 - Excellent</option><option value="4">4 - Good</option><option value="3">3 - Fair</option><option value="2">2 - Poor</option><option value="1">1 - Very poor</option></select></div>
  <div class="field"><label for="message">Feedback</label><textarea id="message" name="message" required maxlength="1000" placeholder="Share your feedback"></textarea></div>
  <div class="form-actions"><button class="btn btn-primary" type="submit">Send feedback</button></div>
  <p class="form-message" id="feedbackMessage" role="status"></p>
</form>
""";
        String script = """
document.getElementById('feedbackForm').addEventListener('submit',async e=>{
  e.preventDefault();const message=document.getElementById('feedbackMessage');message.textContent='Sending...';
  const payload=Object.fromEntries(new FormData(e.target).entries());
  try{
    const response=await fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const result=await response.json();if(!response.ok)throw new Error(result.error||'Unable to send feedback');
    message.textContent='Feedback submitted.';e.target.reset();
  }catch(error){message.textContent=error.message}
});
""";
        return pageHtml("Complaint feedback", content, script, true);
    }

    private static String pageHtml(String title, String content, String script, boolean authenticated) {
        String currentPage = activePage(content);
        String navLinks;
        if (authenticated) {
            navLinks = navLink("Services", "/", currentPage)
                    + navLink("File complaint", "/file", currentPage)
                    + navLink("Track complaint", "/track", currentPage)
                    + navLink("Complaint feedback", "/feedback", currentPage)
                    + "<a href=\"/logout\">Sign out</a>";
        } else {
            navLinks = navLink("Services", "/", currentPage)
                    + navLink("Sign in", "/login", currentPage)
                    + navLink("Create account", "/register", currentPage);
        }
        return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GramOne | __TITLE__</title>
  <style>
    :root{color-scheme:dark;--bg:#101311;--surface:#181d1a;--surface-raised:#1d2420;--line:#2c3530;--text:#e9efeb;--muted:#98a49d;--green:#78c69a;--green-dark:#57a77b;--green-soft:#22372b}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;min-height:100vh}
    nav{height:76px;border-bottom:1px solid var(--line);background:#131714}.nav-inner{max-width:1080px;height:100%;margin:auto;padding:0 24px;display:flex;align-items:center;justify-content:space-between;gap:24px}
    .brand{display:flex;align-items:center;gap:11px;text-decoration:none;color:var(--text);font-weight:800;font-size:19px;letter-spacing:-.4px}.brand-mark{width:34px;height:34px;border:1px solid #38684a;border-radius:10px;background:var(--green-soft);display:grid;place-items:center;color:var(--green);font-size:16px}
    .nav-links{display:flex;gap:7px;align-items:center}.nav-links a{padding:10px 12px;color:var(--muted);text-decoration:none;font-size:13px;font-weight:700;border-radius:8px}.nav-links a:hover,.nav-links a.active{background:#222a25;color:var(--text)}
    main{max-width:1080px;margin:auto;padding:58px 24px 84px}.page-heading{margin-bottom:28px}.eyebrow{font-size:10px;letter-spacing:1.5px;color:var(--green);font-weight:800}.page-heading h1{font-size:clamp(32px,5vw,45px);letter-spacing:-1.6px;margin:10px 0 8px}.page-heading p{color:var(--muted);margin:0;font-size:14px;line-height:1.6}
    .service-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.service-card,.form-card{background:var(--surface);border:1px solid var(--line);border-radius:12px}.service-card{min-height:220px;padding:22px;text-decoration:none;color:var(--text);display:flex;flex-direction:column;transition:border-color .15s,transform .15s}.service-card:hover{border-color:#50765d;transform:translateY(-2px)}.service-number{font-size:11px;color:var(--green);font-weight:800;letter-spacing:1px}.service-card h2{font-size:19px;margin:24px 0 8px}.service-card p{color:var(--muted);font-size:13px;line-height:1.6;margin:0}.card-arrow{margin-top:auto;padding-top:18px;color:var(--green);font-size:12px;font-weight:800}.card-arrow b{margin-left:5px}
    .form-card{max-width:660px;padding:24px}.form-card.compact{max-width:700px}.field{margin-bottom:18px}.field label{display:block;color:#cad3cd;font-size:12px;font-weight:700;margin-bottom:8px}.field input,.field select,.field textarea{width:100%;background:#111613;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:12px 13px;font:inherit;font-size:13px;outline:none}.field input::placeholder,.field textarea::placeholder{color:#66736b}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--green-dark)}.field input[type=file]{padding:9px}.field input[type=file]::file-selector-button{margin-right:12px;background:#25342b;border:0;border-radius:6px;color:var(--text);padding:8px 11px;cursor:pointer}.optional,.field-hint{color:var(--muted);font-size:11px;font-weight:400}.field-hint{display:block;margin-top:8px}.field textarea{height:112px;resize:vertical}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.form-actions{display:flex;justify-content:flex-end}.btn{border:1px solid transparent;border-radius:8px;padding:11px 17px;font-size:13px;font-weight:800;cursor:pointer}.btn-primary{background:var(--green);color:#102017}.btn-primary:hover{background:#91d6ad}.input-action{display:flex;gap:9px}.input-action input{flex:1;min-width:0}
    .login-card{max-width:430px}.login-error{min-height:18px;color:#ff9d9d;font-size:12px}.demo-hint{display:grid;gap:6px;border:1px solid var(--line);border-radius:8px;margin-top:20px;padding:13px;color:var(--muted);font-size:12px}.demo-hint strong{color:var(--text);margin-bottom:2px}.demo-hint code{color:var(--green);font-family:Consolas,monospace}.account-prompt{margin:18px 0 0;color:var(--muted);font-size:12px}.account-prompt a{color:var(--green);font-weight:700}
    .result-card{background:#131815;border:1px solid var(--line);border-radius:9px;padding:18px;color:var(--muted);font-size:13px;line-height:1.6}.result-card h2{font-size:17px;color:var(--text);margin:12px 0 5px}.result-card p{margin:0 0 4px}.result-card small{color:var(--muted)}.attachment-link{display:inline-block;margin-top:12px;color:var(--green);font-weight:700}.status{display:inline-block;color:var(--green);background:var(--green-soft);border-radius:20px;padding:4px 9px;font-size:11px;font-weight:800}.form-message{min-height:18px;margin:14px 0 0;color:var(--green);font-size:13px}
    footer{border-top:1px solid var(--line);color:var(--muted);font-size:11px}.footer-inner{max-width:1080px;margin:auto;padding:20px 24px}
    @media(max-width:720px){nav{height:auto;min-height:70px}.nav-inner{padding:14px 18px;align-items:flex-start;flex-direction:column;gap:10px}.nav-links{width:100%;overflow:auto}.nav-links a{white-space:nowrap;padding:9px 10px;font-size:12px}main{padding:38px 18px 60px}.service-grid{grid-template-columns:1fr}.service-card{min-height:175px}.form-card{padding:18px}.form-grid{grid-template-columns:1fr;gap:0}.input-action{flex-direction:column}}
  </style>
</head>
<body>
  <nav><div class="nav-inner">
    <a class="brand" href="/"><span class="brand-mark">G</span><span>GramOne</span></a>
    <div class="nav-links">__NAV_LINKS__</div>
  </div></nav>
  <main>__CONTENT__</main>
  <footer><div class="footer-inner">GramOne · Gram Panchayat services</div></footer>
  <script>__SCRIPT__</script>
</body>
</html>
"""
        .replace("__TITLE__", title)
        .replace("__NAV_LINKS__", navLinks)
        .replace("__CONTENT__", content)
        .replace("__SCRIPT__", script);
    }

    private static String navLink(String label, String path, String currentPage) {
        return "<a" + (path.equals(currentPage) ? " class=\"active\"" : "")
                + " href=\"" + path + "\">" + label + "</a>";
    }

    private static String activePage(String content) {
        if (content.contains("ACCOUNT ACCESS")) return content.contains("Create account") ? "/register" : "/login";
        if (content.contains("SERVICE 01")) return "/file";
        if (content.contains("SERVICE 02")) return "/track";
        if (content.contains("SERVICE 03")) return "/feedback";
        return "/";
    }
}
