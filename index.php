<?php
session_start();

// Security Headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Database configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "akaripic";

// Create connection with error handling
try {
    $conn = new mysqli($servername, $username, $password, $dbname);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    // Set charset to prevent SQL injection
    $conn->set_charset("utf8mb4");
    
} catch (Exception $e) {
    error_log($e->getMessage());
    die("System maintenance in progress. Please try again later.");
}

// Create necessary tables if they don't exist
$createTables = [
    "CREATE TABLE IF NOT EXISTS signup (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        confirm_password VARCHAR(255) NOT NULL,
        date_created DATETIME DEFAULT CURRENT_TIMESTAMP
    )",
    
    "CREATE TABLE IF NOT EXISTS login (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        login_time DATETIME DEFAULT CURRENT_TIMESTAMP
    )",
    
    "CREATE TABLE IF NOT EXISTS trending_categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        category_name VARCHAR(100) NOT NULL,
        search_count INT DEFAULT 1,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        UNIQUE KEY unique_category (category_name)
    )",
    
    "CREATE TABLE IF NOT EXISTS search_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        keyword VARCHAR(100) NOT NULL,
        search_count INT DEFAULT 1,
        last_searched DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_keyword (keyword)
    )",
    
    "CREATE TABLE IF NOT EXISTS user_usage_time (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        session_start DATETIME NOT NULL,
        session_end DATETIME NULL,
        total_seconds INT DEFAULT 0,
        date DATE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE CASCADE,
        INDEX idx_user_date (user_id, date)
    )",
    
    "CREATE TABLE IF NOT EXISTS user_search_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        keyword VARCHAR(100) NOT NULL,
        search_count INT DEFAULT 1,
        last_searched DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE CASCADE,
        INDEX idx_user_keyword (user_id, keyword)
    )",
    
    "CREATE TABLE IF NOT EXISTS user_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        logout_time DATETIME NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE CASCADE,
        INDEX idx_user_login (user_id, login_time)
    )",
    
    "CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(100) NOT NULL,
        otp_code VARCHAR(10) NOT NULL,
        expires_at DATETIME NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email_token (email, token),
        INDEX idx_expires (expires_at)
    )"
];

foreach ($createTables as $sql) {
    if (!$conn->query($sql)) {
        error_log("Error creating table: " . $conn->error);
    }
}

// Security: Check if user is logged in
$isLoggedIn = isset($_SESSION['user_id']) && isset($_SESSION['last_activity']) && 
              (time() - $_SESSION['last_activity'] < 1800);

if ($isLoggedIn) {
    $_SESSION['last_activity'] = time();
}

$username = $isLoggedIn ? $_SESSION['username'] : '';

// Remove username column from signup table if it exists
$checkColumn = $conn->query("SHOW COLUMNS FROM signup LIKE 'username'");
if ($checkColumn->num_rows > 0) {
    $alterSQL = "ALTER TABLE signup DROP COLUMN username";
    if (!$conn->query($alterSQL)) {
        error_log("Error removing username column: " . $conn->error);
    }
}

// Enhanced security functions
function sanitize_input($data, $conn) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $conn->real_escape_string($data);
}

function validate_email($email) {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    return preg_match('/@gmail\.com$/', $email);
}

function check_brute_force($email, $conn) {
    $valid_time = time() - (30 * 60); // last 30 minutes

    $stmt = $conn->prepare("
        SELECT COUNT(*) AS attempts 
        FROM login 
        WHERE email = ? 
        AND attempt_time > FROM_UNIXTIME(?) 
        AND status = 'failed'
    ");
    $stmt->bind_param("si", $email, $valid_time);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();

    return $result['attempts'] >= 10;
}

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Generate OTP code
function generateOTP($length = 6) {
    $characters = '0123456789';
    $otp = '';
    for ($i = 0; $i < $length; $i++) {
        $otp .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $otp;
}

function sendOTP($email, $otp) {
    error_log("OTP for $email: $otp");
    sleep(1);
    return true;
}

function createPasswordResetToken($email, $conn) {
    $cleanup = $conn->prepare("DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = TRUE");
    $cleanup->execute();
    
    $token = bin2hex(random_bytes(32));
    $otp = generateOTP();
    $expires = date('Y-m-d H:i:s', time() + 1800);
    
    $stmt = $conn->prepare("INSERT INTO password_reset_tokens (email, token, otp_code, expires_at) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $email, $token, $otp, $expires);
    
    if ($stmt->execute()) {
        if (sendOTP($email, $otp)) {
            return [
                'success' => true,
                'token' => $token,
                'otp' => $otp
            ];
        }
    }
    
    return ['success' => false];
}

function verifyOTP($email, $otp, $token, $conn) {
    $stmt = $conn->prepare("SELECT id, expires_at FROM password_reset_tokens WHERE email = ? AND otp_code = ? AND token = ? AND used = FALSE AND expires_at > NOW()");
    $stmt->bind_param("sss", $email, $otp, $token);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $update = $conn->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE id = ?");
        $update->bind_param("i", $row['id']);
        $update->execute();
        return true;
    }
    
    return false;
}

function changePassword($user_id, $current_password, $new_password, $conn) {
    $stmt = $conn->prepare("SELECT password FROM signup WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        if (password_verify($current_password, $user['password'])) {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $update_stmt = $conn->prepare("UPDATE signup SET password = ?, confirm_password = ? WHERE id = ?");
            $update_stmt->bind_param("ssi", $hashed_password, $hashed_password, $user_id);
            
            if ($update_stmt->execute()) {
                return ['success' => true, 'message' => 'Password changed successfully!'];
            } else {
                return ['success' => false, 'message' => 'Error updating password.'];
            }
        } else {
            return ['success' => false, 'message' => 'Current password is incorrect.'];
        }
    }
    
    return ['success' => false, 'message' => 'User not found.'];
}

// Get available Nekos.best endpoints
function getAvailableCategories() {
    return [
        'neko', 'husbando', 'kitsune', 'waifu', 
        'shinobu', 'megumin', 'uniform', 'maid',
        'marin', 'selfies', 'wave', 'wink',
        'tea', 'bonk', 'punch', 'poke',
        'bully', 'pat', 'kiss', 'kick',
        'happy', 'hold', 'hug', 'cuddle',
        'cry', 'smug', 'blush', 'sleep',
        'highfive', 'handhold', 'bite', 'glomp',
        'slap', 'kill', 'kick', 'happy',
        'wave', 'tease', 'feed', 'smug',
        'run', 'facepalm', 'confused', 'bow'
    ];
}

// User tracking functions
function trackUserLogin($user_id, $conn) {
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    $stmt = $conn->prepare("INSERT INTO user_sessions (user_id, login_time, ip_address, user_agent) VALUES (?, NOW(), ?, ?)");
    $stmt->bind_param("iss", $user_id, $ip_address, $user_agent);
    $stmt->execute();
    
    return $conn->insert_id;
}

function trackUserLogout($session_id, $conn) {
    $stmt = $conn->prepare("UPDATE user_sessions SET logout_time = NOW() WHERE id = ?");
    $stmt->bind_param("i", $session_id);
    return $stmt->execute();
}

function updateUserUsageTime($user_id, $seconds, $conn) {
    $today = date('Y-m-d');
    
    $check_stmt = $conn->prepare("SELECT id, total_seconds FROM user_usage_time WHERE user_id = ? AND date = ?");
    $check_stmt->bind_param("is", $user_id, $today);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $new_seconds = $row['total_seconds'] + $seconds;
        $update_stmt = $conn->prepare("UPDATE user_usage_time SET total_seconds = ? WHERE id = ?");
        $update_stmt->bind_param("ii", $new_seconds, $row['id']);
        $update_stmt->execute();
    } else {
        $insert_stmt = $conn->prepare("INSERT INTO user_usage_time (user_id, session_start, total_seconds, date) VALUES (?, NOW(), ?, ?)");
        $insert_stmt->bind_param("iis", $user_id, $seconds, $today);
        $insert_stmt->execute();
    }
}

function updateUserSearchHistory($user_id, $keyword, $conn) {
    $keyword = $conn->real_escape_string(strtolower(trim($keyword)));
    
    $check_stmt = $conn->prepare("SELECT id, search_count FROM user_search_history WHERE user_id = ? AND keyword = ?");
    $check_stmt->bind_param("is", $user_id, $keyword);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $new_count = $row['search_count'] + 1;
        $update_stmt = $conn->prepare("UPDATE user_search_history SET search_count = ?, last_searched = NOW() WHERE user_id = ? AND keyword = ?");
        $update_stmt->bind_param("iis", $new_count, $user_id, $keyword);
        $update_stmt->execute();
    } else {
        $insert_stmt = $conn->prepare("INSERT INTO user_search_history (user_id, keyword, search_count, last_searched) VALUES (?, ?, 1, NOW())");
        $insert_stmt->bind_param("is", $user_id, $keyword);
        $insert_stmt->execute();
    }
}

function getUserUsageStats($user_id, $conn) {
    $stats = [
        'today' => 0,
        'week' => 0,
        'month' => 0,
        'total' => 0,
        'avg_daily' => 0
    ];
    
    // Today's usage
    $today = date('Y-m-d');
    $stmt = $conn->prepare("SELECT SUM(total_seconds) as total FROM user_usage_time WHERE user_id = ? AND date = ?");
    $stmt->bind_param("is", $user_id, $today);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['today'] = $row['total'] ?? 0;
    }
    
    // This week's usage
    $week_start = date('Y-m-d', strtotime('monday this week'));
    $stmt = $conn->prepare("SELECT SUM(total_seconds) as total FROM user_usage_time WHERE user_id = ? AND date >= ?");
    $stmt->bind_param("is", $user_id, $week_start);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['week'] = $row['total'] ?? 0;
    }
    
    // This month's usage
    $month_start = date('Y-m-01');
    $stmt = $conn->prepare("SELECT SUM(total_seconds) as total FROM user_usage_time WHERE user_id = ? AND date >= ?");
    $stmt->bind_param("is", $user_id, $month_start);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['month'] = $row['total'] ?? 0;
    }
    
    // Total usage
    $stmt = $conn->prepare("SELECT SUM(total_seconds) as total FROM user_usage_time WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['total'] = $row['total'] ?? 0;
    }
    
    // Average daily usage (last 30 days)
    $month_start = date('Y-m-d', strtotime('-30 days'));
    $stmt = $conn->prepare("SELECT AVG(total_seconds) as avg_seconds FROM user_usage_time WHERE user_id = ? AND date >= ?");
    $stmt->bind_param("is", $user_id, $month_start);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['avg_daily'] = $row['avg_seconds'] ?? 0;
    }
    
    return $stats;
}

function getUserSearchHistory($user_id, $conn, $limit = 5) {
    $stmt = $conn->prepare("SELECT keyword, search_count, last_searched FROM user_search_history WHERE user_id = ? ORDER BY last_searched DESC LIMIT ?");
    $stmt->bind_param("ii", $user_id, $limit);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $search_history = [];
    while ($row = $result->fetch_assoc()) {
        $search_history[] = $row;
    }
    
    return $search_history;
}

function getUserSearchStats($user_id, $conn) {
    $stats = [
        'total_searches' => 0,
        'unique_categories' => 0,
        'most_searched' => ''
    ];
    
    // Total searches
    $stmt = $conn->prepare("SELECT SUM(search_count) as total FROM user_search_history WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['total_searches'] = $row['total'] ?? 0;
    }
    
    // Unique categories
    $stmt = $conn->prepare("SELECT COUNT(DISTINCT keyword) as unique_count FROM user_search_history WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['unique_categories'] = $row['unique_count'] ?? 0;
    }
    
    // Most searched
    $stmt = $conn->prepare("SELECT keyword, search_count FROM user_search_history WHERE user_id = ? ORDER BY search_count DESC, last_searched DESC LIMIT 1");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stats['most_searched'] = $row['keyword'] . ' (' . $row['search_count'] . ')';
    } else {
        $stats['most_searched'] = 'No searches yet';
    }
    
    return $stats;
}

// Handle AJAX requests
if (isset($_POST['update_usage']) && $isLoggedIn) {
    header('Content-Type: application/json');
    
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo json_encode(['error' => 'Security validation failed']);
        exit;
    }
    
    $user_id = $_SESSION['user_id'];
    $seconds = isset($_POST['seconds']) ? intval($_POST['seconds']) : 60;
    
    updateUserUsageTime($user_id, $seconds, $conn);
    $stats = getUserUsageStats($user_id, $conn);
    
    echo json_encode([
        'success' => true,
        'stats' => $stats
    ]);
    exit;
}

if (isset($_POST['keyword']) && $isLoggedIn) {
    header('Content-Type: application/json');
    
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo json_encode(['error' => 'Security validation failed']);
        exit;
    }
    
    $keyword = sanitize_input($_POST['keyword'], $conn);
    $user_id = $_SESSION['user_id'];
    
    if (strlen($keyword) < 2 || strlen($keyword) > 50 || !preg_match('/^[a-zA-Z0-9\s\-_]+$/', $keyword)) {
        echo json_encode(['error' => 'Invalid search keyword']);
        exit;
    }
    
    updateUserSearchHistory($user_id, $keyword, $conn);
    $search_history = getUserSearchHistory($user_id, $conn, 5);
    $search_stats = getUserSearchStats($user_id, $conn);
    
    // Update shared search history
    $check_stmt = $conn->prepare("SELECT id, search_count FROM search_history WHERE keyword = ?");
    $check_stmt->bind_param("s", $keyword);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $new_count = $row['search_count'] + 1;
        $update_stmt = $conn->prepare("UPDATE search_history SET search_count = ?, last_searched = NOW() WHERE keyword = ?");
        $update_stmt->bind_param("is", $new_count, $keyword);
        $update_stmt->execute();
        
        $update_trending = $conn->prepare("UPDATE trending_categories SET search_count = search_count + 1, last_updated = NOW() WHERE category_name = ?");
        $update_trending->bind_param("s", $keyword);
        $update_trending->execute();
    } else {
        $insert_stmt = $conn->prepare("INSERT INTO search_history (keyword, search_count, last_searched) VALUES (?, 1, NOW())");
        $insert_stmt->bind_param("s", $keyword);
        $insert_stmt->execute();
        
        $available_categories = getAvailableCategories();
        if (in_array($keyword, $available_categories)) {
            $insert_trending = $conn->prepare("INSERT IGNORE INTO trending_categories (category_name, search_count) VALUES (?, 1)");
            $insert_trending->bind_param("s", $keyword);
            $insert_trending->execute();
        }
    }
    
    echo json_encode([
        'success' => true, 
        'message' => "Search history updated for: " . $keyword,
        'search_history' => $search_history,
        'search_stats' => $search_stats
    ]);
    exit;
}

if (isset($_POST['change_password']) && $isLoggedIn) {
    header('Content-Type: application/json');
    
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo json_encode(['error' => 'Security validation failed']);
        exit;
    }
    
    $user_id = $_SESSION['user_id'];
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required!']);
        exit;
    }
    
    if ($new_password !== $confirm_password) {
        echo json_encode(['success' => false, 'message' => 'New passwords do not match!']);
        exit;
    }
    
    if (strlen($new_password) < 8) {
        echo json_encode(['success' => false, 'message' => 'New password must be at least 8 characters long!']);
        exit;
    }
    
    $result = changePassword($user_id, $current_password, $new_password, $conn);
    echo json_encode($result);
    exit;
}

if (isset($_POST['get_search_stats']) && $isLoggedIn) {
    header('Content-Type: application/json');
    
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo json_encode(['error' => 'Security validation failed']);
        exit;
    }
    
    $user_id = $_SESSION['user_id'];
    $search_stats = getUserSearchStats($user_id, $conn);
    $search_history = getUserSearchHistory($user_id, $conn, 5);
    
    echo json_encode([
        'success' => true,
        'search_stats' => $search_stats,
        'search_history' => $search_history
    ]);
    exit;
}

// Handle form submissions
$error_message = "";
$success_message = "";
$show_signup_form = false;
$reset_step = 'request';

// Password reset handling
if (isset($_POST['reset_password'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error_message = "Security validation failed. Please try again.";
    } else {
        $email = sanitize_input($_POST['email'], $conn);
        
        if (!preg_match('/@gmail\.com$/', $email)) {
            $error_message = "Only Gmail accounts are allowed! Please use an @gmail.com address.";
        } else {
            $check_stmt = $conn->prepare("SELECT id FROM signup WHERE email = ?");
            $check_stmt->bind_param("s", $email);
            $check_stmt->execute();
            $check_result = $check_stmt->get_result();
            
            if ($check_result->num_rows > 0) {
                $result = createPasswordResetToken($email, $conn);
                
                if ($result['success']) {
                    $_SESSION['reset_token'] = $result['token'];
                    $_SESSION['reset_email'] = $email;
                    $reset_step = 'verify';
                    $success_message = "OTP sent to your email! Check your inbox. (Demo OTP: " . $result['otp'] . ")";
                } else {
                    $error_message = "Failed to send OTP. Please try again.";
                }
            } else {
                $error_message = "Email not found in our system.";
            }
        }
    }
}

// OTP verification
if (isset($_POST['verify_otp'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error_message = "Security validation failed. Please try again.";
    } else {
        $otp = sanitize_input($_POST['otp'], $conn);
        $email = $_SESSION['reset_email'] ?? '';
        $token = $_SESSION['reset_token'] ?? '';
        
        if (empty($email) || empty($token)) {
            $error_message = "Reset session expired. Please start over.";
            $reset_step = 'request';
        } else {
            if (verifyOTP($email, $otp, $token, $conn)) {
                $reset_step = 'reset';
                $success_message = "OTP verified successfully! You can now set your new password.";
            } else {
                $error_message = "Invalid or expired OTP. Please try again.";
            }
        }
    }
}

// Password reset completion
if (isset($_POST['new_password_submit'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error_message = "Security validation failed. Please try again.";
    } else {
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];
        $email = $_SESSION['reset_email'] ?? '';
        
        if (empty($email)) {
            $error_message = "Reset session expired. Please start over.";
            $reset_step = 'request';
        } elseif ($new_password !== $confirm_password) {
            $error_message = "Passwords do not match!";
            $reset_step = 'reset';
        } elseif (strlen($new_password) < 8) {
            $error_message = "Password must be at least 8 characters long!";
            $reset_step = 'reset';
        } else {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $update_stmt = $conn->prepare("UPDATE signup SET password = ?, confirm_password = ? WHERE email = ?");
            $update_stmt->bind_param("sss", $hashed_password, $hashed_password, $email);
            
            if ($update_stmt->execute()) {
                $success_message = "Password reset successfully! You can now log in with your new password.";
                unset($_SESSION['reset_token']);
                unset($_SESSION['reset_email']);
                $reset_step = 'complete';
            } else {
                $error_message = "Error resetting password. Please try again.";
                $reset_step = 'reset';
            }
        }
    }
}

// Login handling
if (isset($_POST['login'])) {

    // CSRF Protection
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error_message = "Security validation failed. Please try again.";
        goto endLogin;
    }

    // Get Email & Password
    $email = sanitize_input($_POST['email'], $conn);
    $password = $_POST['password'];

    // Brute force prevention
    if (check_brute_force($email, $conn)) {
        $error_message = "Too many failed attempts. Please try again in 30 minutes.";
        goto endLogin;
    }

    // Check if account is locked
    $lock_check = $conn->prepare("
        SELECT failed_attempts, is_locked, unlock_time 
        FROM login 
        WHERE email = ?
        ORDER BY attempt_time DESC
        LIMIT 1
    ");
    $lock_check->bind_param("s", $email);
    $lock_check->execute();
    $lock_result = $lock_check->get_result();

    $previous_failed_attempts = 0;
    $account_locked = false;
    $unlock_time = null;

    if ($lock_result->num_rows > 0) {
        $lock_data = $lock_result->fetch_assoc();
        $previous_failed_attempts = $lock_data['failed_attempts'];
        $account_locked = $lock_data['is_locked'];
        $unlock_time = $lock_data['unlock_time'];

        if ($account_locked == 1 && time() < strtotime($unlock_time)) {
            $error_message = "Account is temporarily locked. Try again after " . $unlock_time;
            goto endLogin;
        }
    }

    /* ============================
           CHECK USER EXISTS
    ============================ */

    $stmt = $conn->prepare("
        SELECT id, email, password, date_created 
        FROM signup 
        WHERE email = ?
    ");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    // EMAIL FOUND?
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();

    // =======================================
    //        SUCCESSFUL LOGIN
    // =======================================
    if (password_verify($password, $user['password'])) {

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['username'] = explode('@', $user['email'])[0];
            $_SESSION['user_created'] = $user['date_created'];
            $_SESSION['last_activity'] = time();

            // Track user session
            $session_id = trackUserLogin($user['id'], $conn);
            $_SESSION['session_id'] = $session_id;

            // Insert success log
            $insert_success = $conn->prepare("
                INSERT INTO login (email, attempt_time, status, failed_attempts, is_locked, unlock_time, ip_address, user_agent)
                VALUES (?, NOW(), 'success', 0, 0, NULL, ?, ?)
            ");
            $insert_success->bind_param(
                "sss",
                $email,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT']
            );
            $insert_success->execute();

            $success_message = "Login successful!";
            goto endLogin;
        }

        // ======= FAILED LOGIN (wrong password) =======
        $new_attempts = $previous_failed_attempts + 1;
        $is_locked = 0;
        $new_unlock_time = NULL;
        $error_message = "Invalid email or password!";

        // lock after 5 attempts
        if ($new_attempts >= 5) {
            $is_locked = 1;
            $new_unlock_time = date('Y-m-d H:i:s', time() + 1800);
            $error_message = "Too many failed attempts. Account locked for 30 minutes.";
        }

        // Insert failed log
        $insert_fail = $conn->prepare("
            INSERT INTO login (email, attempt_time, status, failed_attempts, is_locked, unlock_time, ip_address, user_agent)
            VALUES (?, NOW(), 'failed', ?, ?, ?, ?, ?)
        ");
        $insert_fail->bind_param(
            "siisss",
            $email,
            $new_attempts,
            $is_locked,
            $new_unlock_time,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT']
        );
        $insert_fail->execute();

    } 
    else {
        // ======= EMAIL NOT FOUND =======
        $error_message = "Invalid email or password!";
    }

endLogin:
}

// Signup handling
if (isset($_POST['signup'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error_message = "Security validation failed. Please try again.";
    } else {
        $show_signup_form = true;
        $email = sanitize_input($_POST['email'], $conn);
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        
        if (empty($email) || empty($password) || empty($confirm_password)) {
            $error_message = "All fields are required!";
        } elseif ($password !== $confirm_password) {
            $error_message = "Passwords do not match!";
        } elseif (strlen($password) < 8) {
            $error_message = "Password must be at least 8 characters long!";
        } elseif (!validate_email($email)) {
            $error_message = "Invalid email format! Only Gmail accounts are allowed.";
        } else {
            $check_stmt = $conn->prepare("SELECT id FROM signup WHERE email = ?");
            $check_stmt->bind_param("s", $email);
            $check_stmt->execute();
            $check_result = $check_stmt->get_result();
            
            if ($check_result->num_rows > 0) {
                $error_message = "Email already registered!";
            } else {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                
                $insert_stmt = $conn->prepare("INSERT INTO signup (email, password, confirm_password, date_created) VALUES (?, ?, ?, NOW())");
                $insert_stmt->bind_param("sss", $email, $hashed_password, $hashed_password);
                
                if ($insert_stmt->execute()) {
                    $success_message = "Account created successfully! You can now log in.";
                    $show_signup_form = false;
                    $_POST = array();
                } else {
                    $error_message = "Error creating account. Please try again.";
                }
            }
        }
    }
}

// Update search history
function updateSearchHistory($keyword, $conn) {
    $keyword = $conn->real_escape_string(strtolower(trim($keyword)));
    
    $check_stmt = $conn->prepare("SELECT id, search_count FROM search_history WHERE keyword = ?");
    $check_stmt->bind_param("s", $keyword);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $new_count = $row['search_count'] + 1;
        $update_stmt = $conn->prepare("UPDATE search_history SET search_count = ?, last_searched = NOW() WHERE keyword = ?");
        $update_stmt->bind_param("is", $new_count, $keyword);
        $update_stmt->execute();
        
        $update_trending = $conn->prepare("UPDATE trending_categories SET search_count = search_count + 1, last_updated = NOW() WHERE category_name = ?");
        $update_trending->bind_param("s", $keyword);
        $update_trending->execute();
    } else {
        $insert_stmt = $conn->prepare("INSERT INTO search_history (keyword, search_count, last_searched) VALUES (?, 1, NOW())");
        $insert_stmt->bind_param("s", $keyword);
        $insert_stmt->execute();
        
        $available_categories = getAvailableCategories();
        if (in_array($keyword, $available_categories)) {
            $insert_trending = $conn->prepare("INSERT IGNORE INTO trending_categories (category_name, search_count) VALUES (?, 1)");
            $insert_trending->bind_param("s", $keyword);
            $insert_trending->execute();
        }
    }
    
    return true;
}

// Get trending categories
function getTrendingCategories($conn, $limit = 6) {
    $trending_stmt = $conn->prepare("SELECT category_name, search_count FROM trending_categories WHERE is_active = TRUE ORDER BY search_count DESC, last_updated DESC LIMIT ?");
    $trending_stmt->bind_param("i", $limit);
    $trending_stmt->execute();
    $trending_result = $trending_stmt->get_result();
    
    $trending_categories = [];
    $available_categories = getAvailableCategories();
    
    while ($row = $trending_result->fetch_assoc()) {
        if (in_array($row['category_name'], $available_categories)) {
            $trending_categories[] = $row;
        }
    }
    
    if (empty($trending_categories)) {
        $trending_categories = getPopularSearches($conn, $limit);
        
        foreach ($trending_categories as $category) {
            $insert_stmt = $conn->prepare("INSERT IGNORE INTO trending_categories (category_name, search_count) VALUES (?, ?)");
            $insert_stmt->bind_param("si", $category['keyword'], $category['search_count']);
            $insert_stmt->execute();
        }
    }
    
    return $trending_categories;
}

function updateTrendingCategories($conn) {
    $popular_searches = getPopularSearches($conn, 12);
    $available_categories = getAvailableCategories();
    
    $clear_stmt = $conn->prepare("UPDATE trending_categories SET is_active = FALSE");
    $clear_stmt->execute();
    
    $count = 0;
    foreach ($popular_searches as $search) {
        if ($count >= 12) break;
        
        $keyword = $search['keyword'];
        
        if (in_array($keyword, $available_categories)) {
            $check_stmt = $conn->prepare("SELECT id FROM trending_categories WHERE category_name = ?");
            $check_stmt->bind_param("s", $keyword);
            $check_stmt->execute();
            $check_result = $check_stmt->get_result();
            
            if ($check_result->num_rows > 0) {
                $update_stmt = $conn->prepare("UPDATE trending_categories SET search_count = ?, last_updated = NOW(), is_active = TRUE WHERE category_name = ?");
                $update_stmt->bind_param("is", $search['search_count'], $keyword);
                $update_stmt->execute();
            } else {
                $insert_stmt = $conn->prepare("INSERT INTO trending_categories (category_name, search_count, is_active) VALUES (?, ?, TRUE)");
                $insert_stmt->bind_param("si", $keyword, $search['search_count']);
                $insert_stmt->execute();
            }
            $count++;
        }
    }
    
    return true;
}

function getPopularSearches($conn, $limit = 6) {
    $stmt = $conn->prepare("SELECT keyword, search_count FROM search_history ORDER BY search_count DESC, last_searched DESC LIMIT ?");
    $stmt->bind_param("i", $limit);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $popular_searches = [];
    while ($row = $result->fetch_assoc()) {
        $popular_searches[] = $row;
    }
    
    return $popular_searches;
}

// Initialize data with sample searches if empty
function initializeData($conn) {
    $check_stmt = $conn->prepare("SELECT COUNT(*) as count FROM search_history");
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    $row = $result->fetch_assoc();
    
    if ($row['count'] == 0) {
        $sample_searches = [
            'neko' => 25, 'kitsune' => 18, 'happy' => 22, 
            'dance' => 15, 'blush' => 12, 'wink' => 10,
            'punch' => 8, 'hug' => 14, 'pat' => 9,
            'waifu' => 20, 'husbando' => 16, 'cry' => 7
        ];
        
        foreach ($sample_searches as $keyword => $count) {
            $insert_stmt = $conn->prepare("INSERT INTO search_history (keyword, search_count, last_searched) VALUES (?, ?, NOW())");
            $insert_stmt->bind_param("si", $keyword, $count);
            $insert_stmt->execute();
        }
    }
    
    $check_trending = $conn->prepare("SELECT COUNT(*) as count FROM trending_categories WHERE is_active = TRUE");
    $check_trending->execute();
    $trending_result = $check_trending->get_result();
    $trending_row = $trending_result->fetch_assoc();
    
    if ($trending_row['count'] == 0) {
        updateTrendingCategories($conn);
    }
}

// Initialize data
initializeData($conn);

// Get trending categories for display
$trending_categories = getTrendingCategories($conn, 6);

// Handle trending categories refresh
if (isset($_GET['refresh_trending']) && $isLoggedIn) {
    updateTrendingCategories($conn);
    $trending_categories = getTrendingCategories($conn, 6);
    $success_message = "Trending categories updated with fresh data!";
}

// Logout handling
if (isset($_GET['logout'])) {
    if (isset($_SESSION['session_id'])) {
        trackUserLogout($_SESSION['session_id'], $conn);
    }
    
    session_destroy();
    session_start();
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    header("Location: index.php");
    exit();
}

// Get user statistics for display
if ($isLoggedIn) {
    $user_id = $_SESSION['user_id'];
    $usage_stats = getUserUsageStats($user_id, $conn);
    $user_search_history = getUserSearchHistory($user_id, $conn, 5);
    $search_stats = getUserSearchStats($user_id, $conn);
    
    function formatTime($seconds) {
        if ($seconds < 60) {
            return $seconds . " sec";
        } elseif ($seconds < 3600) {
            return floor($seconds / 60) . " min";
        } else {
            $hours = floor($seconds / 3600);
            $minutes = floor(($seconds % 3600) / 60);
            return $hours . "h " . $minutes . "m";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AnimeGIF - Discover Amazing Anime Content</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4338ca;
            --secondary: #ec4899;
            --dark: #1e293b;
            --darker: #0f172a;
            --light: #f8fafc;
            --gray: #64748b;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --radius: 16px;
            --radius-lg: 20px;
            --shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            color: var(--light);
            min-height: 100vh;
            line-height: 1.6;
            overflow-x: hidden;
            position: relative;
        }
        
        /* Animated Background Elements */
        .floating-shapes {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }
        
        .shape {
            position: absolute;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.1) 0%, transparent 70%);
            animation: float 6s ease-in-out infinite;
        }
        
        .shape:nth-child(1) {
            width: 300px;
            height: 300px;
            top: 10%;
            left: 5%;
            animation-delay: 0s;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%);
        }
        
        .shape:nth-child(2) {
            width: 200px;
            height: 200px;
            top: 60%;
            right: 10%;
            animation-delay: 2s;
            background: radial-gradient(circle, rgba(236, 72, 153, 0.1) 0%, transparent 70%);
        }
        
        .shape:nth-child(3) {
            width: 150px;
            height: 150px;
            bottom: 20%;
            left: 15%;
            animation-delay: 4s;
            background: radial-gradient(circle, rgba(245, 158, 11, 0.1) 0%, transparent 70%);
        }
        
        .shape:nth-child(4) {
            width: 250px;
            height: 250px;
            top: 30%;
            right: 20%;
            animation-delay: 1s;
            background: radial-gradient(circle, rgba(16, 185, 129, 0.1) 0%, transparent 70%);
        }
        
        .sparkle {
            position: absolute;
            width: 8px;
            height: 8px;
            background: rgba(255, 255, 255, 0.8);
            border-radius: 50%;
            animation: sparkle 3s ease-in-out infinite;
        }
        
        .sparkle:nth-child(5) {
            top: 15%;
            right: 25%;
            animation-delay: 0.5s;
        }
        
        .sparkle:nth-child(6) {
            bottom: 25%;
            left: 20%;
            animation-delay: 1.5s;
        }
        
        .sparkle:nth-child(7) {
            top: 45%;
            left: 30%;
            animation-delay: 2.5s;
        }
        
        .sparkle:nth-child(8) {
            bottom: 15%;
            right: 30%;
            animation-delay: 3.5s;
        }
        
        @keyframes float {
            0%, 100% {
                transform: translateY(0) rotate(0deg);
                opacity: 0.7;
            }
            50% {
                transform: translateY(-20px) rotate(180deg);
                opacity: 1;
            }
        }
        
        @keyframes sparkle {
            0%, 100% {
                transform: scale(0) rotate(0deg);
                opacity: 0;
            }
            50% {
                transform: scale(1) rotate(180deg);
                opacity: 1;
            }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        /* Creative Header with Centered Navigation */
        .creative-header {
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
            padding: 15px 0;
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: relative;
        }
        
        .logo-section {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo {
            font-size: 2.8rem;
            font-weight: 900;
            background: linear-gradient(135deg, var(--primary), var(--secondary), #f59e0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 4px 20px rgba(99, 102, 241, 0.3);
            letter-spacing: -1px;
        }
        
        .logo i {
            font-size: 2.6rem;
            margin-right: 8px;
        }
        
        /* Centered Navigation */
        .centered-nav {
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            display: flex;
            gap: 8px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 50px;
            padding: 8px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }
        
        .nav-item {
            padding: 12px 24px;
            border-radius: 50px;
            cursor: pointer;
            transition: var(--transition);
            font-weight: 600;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--gray);
            border: none;
            background: transparent;
        }
        
        .nav-item:hover {
            color: var(--light);
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-2px);
        }
        
        .nav-item.active {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            box-shadow: 0 8px 20px rgba(99, 102, 241, 0.3);
        }
        
        .nav-item i {
            font-size: 1.1rem;
        }
        
        /* Auth Buttons */
        .auth-buttons {
            display: flex;
            gap: 12px;
        }
        
        .auth-btn {
            padding: 12px 24px;
            border-radius: 50px;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            border: none;
            font-size: 0.95rem;
        }
        
        .login-btn {
            background: transparent;
            border: 2px solid var(--primary);
            color: var(--primary);
        }
        
        .signup-btn {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            color: white;
        }
        
        .auth-btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        /* User Profile */
        .user-profile {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 16px;
            border-radius: 50px;
            cursor: pointer;
            transition: var(--transition);
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
        }
        
        .user-profile:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-2px);
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.1rem;
            color: white;
        }
        
        .user-name {
            font-weight: 600;
            color: var(--light);
        }
        
        /* User Dropdown */
        .user-dropdown {
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 10px;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: var(--radius);
            min-width: 180px;
            box-shadow: var(--shadow);
            opacity: 0;
            visibility: hidden;
            transform: translateY(-10px);
            transition: var(--transition);
            z-index: 1001;
        }
        
        .user-profile.active .user-dropdown {
            opacity: 1;
            visibility: visible;
            transform: translateY(0);
        }
        
        .dropdown-item {
            padding: 12px 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--light);
            text-decoration: none;
            transition: var(--transition);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .dropdown-item:last-child {
            border-bottom: none;
        }
        
        .dropdown-item:hover {
            background: rgba(255, 255, 255, 0.05);
            color: var(--primary);
        }
        
        .dropdown-item i {
            width: 20px;
            text-align: center;
        }
        
        /* Main Content Sections */
        .main-content {
            min-height: calc(100vh - 120px);
            padding: 40px 0;
        }
        
        .content-section {
            display: none;
            animation: fadeInUp 0.6s ease-out;
        }
        
        .content-section.active {
            display: block;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Dashboard Section */
        .dashboard-hero {
            text-align: center;
            margin-bottom: 50px;
            padding: 60px 20px;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(236, 72, 153, 0.1));
            border-radius: var(--radius-lg);
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
            overflow: hidden;
        }
        
        .dashboard-hero::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at 30% 20%, rgba(99, 102, 241, 0.2) 0%, transparent 50%),
                        radial-gradient(circle at 80% 80%, rgba(236, 72, 153, 0.2) 0%, transparent 50%);
            z-index: 1;
        }
        
        .dashboard-hero > * {
            position: relative;
            z-index: 2;
        }
        
        .dashboard-title {
            font-size: 4rem;
            font-weight: 900;
            margin-bottom: 20px;
            background: linear-gradient(135deg, var(--primary), var(--secondary), #f59e0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1.1;
        }
        
        .dashboard-subtitle {
            font-size: 1.4rem;
            color: #cbd5e1;
            margin-bottom: 30px;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .quick-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: var(--radius);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
            text-align: center;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
            box-shadow: var(--shadow);
        }
        
        .stat-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
        }
        
        .stat-icon i {
            font-size: 1.5rem;
            color: white;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: var(--gray);
            font-size: 0.9rem;
            font-weight: 600;
        }
        
        /* Try It Now Button */
        .try-now-section {
            text-align: center;
            margin: 40px 0;
        }
        
        .try-now-btn {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            padding: 16px 32px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            border-radius: 50px;
            font-weight: 700;
            font-size: 1.1rem;
            cursor: pointer;
            transition: var(--transition);
            box-shadow: var(--shadow);
        }
        
        .try-now-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.3);
        }
        
        /* Search Section */
        .search-section {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .search-container {
            background: rgba(255, 255, 255, 0.05);
            border-radius: var(--radius-lg);
            padding: 40px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 30px;
        }
        
        .search-box {
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .search-input {
            flex: 1;
            padding: 18px 25px;
            background: rgba(255, 255, 255, 0.08);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: var(--radius);
            color: white;
            font-size: 1.1rem;
            outline: none;
            transition: var(--transition);
        }
        
        .search-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }
        
        .search-input::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }
        
        .search-btn {
            padding: 18px 30px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
            border-radius: var(--radius);
        }
        
        .search-btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .search-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .action-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .action-btn {
            padding: 15px 25px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #cbd5e1;
            border-radius: var(--radius);
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 600;
        }
        
        .action-btn:hover {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary);
            transform: translateY(-2px);
        }
        
        .search-history-section {
            margin: 30px 0;
        }
        
        .section-title {
            font-size: 2rem;
            margin-bottom: 25px;
            color: var(--primary);
            text-align: center;
            font-weight: 700;
        }
        
        .search-history-scroll {
            display: flex;
            overflow-x: auto;
            gap: 15px;
            padding: 10px 5px;
            scrollbar-width: thin;
        }
        
        .search-history-item {
            background: rgba(255, 255, 255, 0.08);
            border-radius: var(--radius);
            padding: 15px 20px;
            text-align: center;
            transition: var(--transition);
            cursor: pointer;
            border: 1px solid rgba(255, 255, 255, 0.1);
            min-width: 150px;
            flex-shrink: 0;
        }
        
        .search-history-item:hover {
            background: rgba(99, 102, 241, 0.2);
            transform: translateY(-3px);
            border-color: var(--primary);
        }
        
        .search-history-keyword {
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 8px;
            color: var(--light);
        }
        
        .search-history-count {
            color: var(--secondary);
            font-size: 0.9rem;
            margin-bottom: 5px;
        }
        
        .trending-section {
            margin: 50px 0;
        }
        
        .trending-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }
        
        .refresh-trending {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #cbd5e1;
            padding: 10px 18px;
            border-radius: var(--radius);
            cursor: pointer;
            font-size: 0.9rem;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .refresh-trending:hover {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary);
        }
        
        .category-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            justify-content: center;
            margin-bottom: 30px;
        }
        
        .category-tag {
            padding: 12px 24px;
            background: rgba(255, 255, 255, 0.08);
            border-radius: 50px;
            font-size: 0.95rem;
            cursor: pointer;
            transition: var(--transition);
            position: relative;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .category-tag:hover {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            transform: translateY(-3px);
            box-shadow: var(--shadow);
        }
        
        .search-count {
            position: absolute;
            top: -8px;
            right: -8px;
            background: var(--secondary);
            color: white;
            border-radius: 50%;
            width: 22px;
            height: 22px;
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
        }
        
        /* GIF Grid Styles */
        .gif-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 25px;
            margin-bottom: 50px;
        }
        
        .gif-grid.dashboard-grid {
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
        }
        
        .gif-grid.search-grid {
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
        }
        
        .gif-grid.search-grid.list-view {
            grid-template-columns: 1fr;
        }
        
        .gif-grid.search-grid.list-view .gif-card {
            display: flex;
            flex-direction: row;
            height: 200px;
        }
        
        .gif-grid.search-grid.list-view .gif-img {
            width: 200px;
            height: 100%;
            object-fit: cover;
        }
        
        .gif-grid.search-grid.list-view .gif-title {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .gif-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: var(--radius);
            overflow: hidden;
            transition: var(--transition);
            box-shadow: var(--shadow);
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
        }
        
        .gif-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            border-color: var(--primary);
        }
        
        .gif-card:hover .gif-overlay {
            opacity: 1;
        }
        
        .gif-img {
            width: 100%;
            height: 220px;
            object-fit: cover;
            display: block;
        }
        
        .gif-title {
            padding: 18px;
            font-size: 1rem;
            text-align: center;
            background: rgba(0, 0, 0, 0.3);
            font-weight: 600;
        }
        
        .gif-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: var(--transition);
        }
        
        .gif-actions {
            display: flex;
            gap: 10px;
        }
        
        .gif-action-btn {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            border: none;
            background: var(--primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: var(--transition);
            font-size: 1.1rem;
        }
        
        .gif-action-btn:hover {
            transform: scale(1.1);
            background: var(--secondary);
        }
        
        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 15px;
            margin: 30px 0;
        }
        
        .pagination-btn {
            padding: 12px 24px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #cbd5e1;
            border-radius: var(--radius);
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 600;
        }
        
        .pagination-btn:hover:not(:disabled) {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary);
            transform: translateY(-2px);
        }
        
        .pagination-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        
        .pagination-info {
            color: var(--gray);
            font-weight: 600;
        }
        
        /* Account Section */
        .account-section {
            max-width: 1000px;
            margin: 0 auto;
        }
        
        .account-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .account-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: var(--radius);
            padding: 30px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
        }
        
        .account-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
            box-shadow: var(--shadow);
        }
        
        .account-card h3 {
            color: var(--primary);
            margin-bottom: 20px;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .account-card h3 i {
            font-size: 1.3rem;
        }
        
        .stats-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .stats-table th, .stats-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .stats-table th {
            background-color: rgba(255, 255, 255, 0.05);
            color: var(--light);
            font-weight: 600;
            font-size: 0.9rem;
        }
        
        .stats-table tr:last-child td {
            border-bottom: none;
        }
        
        .time-value {
            color: var(--primary);
            font-weight: 600;
        }
        
        /* Change Password Button and Form */
        .change-password-btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 14px 24px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            border-radius: var(--radius);
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            margin-bottom: 20px;
        }
        
        .change-password-btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .change-password-form {
            background: rgba(255, 255, 255, 0.05);
            border-radius: var(--radius);
            padding: 40px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            display: none;
        }
        
        .change-password-form.active {
            display: block;
            animation: fadeInUp 0.5s ease-out;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-label {
            display: block;
            color: var(--primary);
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 1rem;
        }
        
        .form-input {
            width: 100%;
            padding: 16px 18px;
            border-radius: var(--radius);
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.08);
            color: white;
            font-size: 1rem;
            outline: none;
            transition: var(--transition);
        }
        
        .form-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }
        
        .form-submit {
            width: 100%;
            padding: 16px;
            border-radius: var(--radius);
            border: none;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: var(--transition);
        }
        
        .form-submit:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .password-strength {
            margin-top: 5px;
            height: 5px;
            border-radius: 5px;
            background: var(--gray);
            overflow: hidden;
        }
        
        .password-strength-fill {
            height: 100%;
            transition: var(--transition);
            width: 0%;
        }
        
        .password-strength.weak .password-strength-fill {
            background: var(--error);
            width: 33%;
        }
        
        .password-strength.medium .password-strength-fill {
            background: var(--warning);
            width: 66%;
        }
        
        .password-strength.strong .password-strength-fill {
            background: var(--success);
            width: 100%;
        }
        
        .password-strength-text {
            font-size: 0.8rem;
            margin-top: 5px;
            text-align: right;
            color: var(--gray);
        }
        
        .password-visibility-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--gray);
            cursor: pointer;
        }
        
        /* Loading and Messages */
        .loading {
            text-align: center;
            padding: 50px;
            font-size: 1.3rem;
            color: #94a3b8;
            grid-column: 1 / -1;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 40px;
            height: 40px;
            border: 4px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 1s ease-in-out infinite;
            margin-bottom: 15px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .no-results {
            text-align: center;
            padding: 50px;
            font-size: 1.3rem;
            color: #94a3b8;
            grid-column: 1 / -1;
        }
        
        .api-error {
            text-align: center;
            padding: 25px;
            font-size: 1.1rem;
            color: var(--error);
            background: rgba(239, 68, 68, 0.1);
            border-radius: var(--radius);
            margin: 20px 0;
            grid-column: 1 / -1;
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        .message {
            padding: 15px;
            border-radius: var(--radius);
            margin-bottom: 25px;
            text-align: center;
            font-weight: 600;
        }
        
        .error-message {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
        }
        
        .success-message {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: var(--success);
        }
        
        /* Auth Modal */
        .auth-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(5px);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 2000;
        }
        
        .auth-container {
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            padding: 30px;
            border-radius: var(--radius-lg);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 420px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
        }
        
        .close-modal {
            position: absolute;
            top: 15px;
            right: 15px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: #94a3b8;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: var(--transition);
            z-index: 10;
        }
        
        .close-modal:hover {
            background: rgba(239, 68, 68, 0.2);
            color: var(--error);
        }
        
        .auth-header {
            text-align: center;
            margin-bottom: 25px;
        }
        
        .auth-title {
            font-size: 2rem;
            margin-bottom: 10px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
        }
        
        .auth-subtitle {
            color: #94a3b8;
            font-size: 1rem;
        }
        
        .auth-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .auth-switch {
            text-align: center;
            margin-top: 20px;
            color: #94a3b8;
        }
        
        .auth-switch a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
        }
        
        .auth-switch a:hover {
            color: var(--secondary);
            text-decoration: underline;
        }
        
        .hidden {
            display: none !important;
        }
        
        /* Footer */
        footer {
            text-align: center;
            padding: 30px;
            margin-top: 60px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: #94a3b8;
        }
        
        /* Responsive Design */
        @media (max-width: 1024px) {
            .centered-nav {
                position: static;
                transform: none;
                margin: 20px 0;
                order: 3;
                width: 100%;
                justify-content: center;
            }
            
            .header-content {
                flex-wrap: wrap;
            }
            
            .logo-section {
                order: 1;
            }
            
            .auth-buttons {
                order: 2;
            }
            
            .dashboard-title {
                font-size: 3rem;
            }
        }
        
        @media (max-width: 768px) {
            .dashboard-title {
                font-size: 2.5rem;
            }
            
            .dashboard-subtitle {
                font-size: 1.2rem;
            }
            
            .search-box {
                flex-direction: column;
            }
            
            .gif-grid {
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            }
            
            .account-stats {
                grid-template-columns: 1fr;
            }
            
            .nav-item {
                padding: 10px 16px;
                font-size: 0.9rem;
            }
            
            .logo {
                font-size: 2.2rem;
            }
            
            .auth-container {
                padding: 25px 20px;
                margin: 15px;
            }
        }
        
        @media (max-width: 480px) {
            .dashboard-title {
                font-size: 2rem;
            }
            
            .dashboard-hero {
                padding: 40px 20px;
            }
            
            .search-container {
                padding: 25px;
            }
            
            .gif-grid {
                grid-template-columns: 1fr;
            }
            
            .nav-item {
                padding: 8px 12px;
                font-size: 0.85rem;
            }
            
            .nav-item span {
                display: none;
            }
            
            .logo {
                font-size: 1.8rem;
            }
            
            .auth-container {
                padding: 20px 15px;
                margin: 10px;
            }
            
            .user-name {
                display: none;
            }
        }
    </style>
</head>
<body>
    <!-- Animated Background -->
    <div class="floating-shapes">
        <div class="shape"></div>
        <div class="shape"></div>
        <div class="shape"></div>
        <div class="shape"></div>
        <div class="sparkle"></div>
        <div class="sparkle"></div>
        <div class="sparkle"></div>
        <div class="sparkle"></div>
    </div>

    <!-- Auth Modal -->
    <?php if (!$isLoggedIn): ?>
    <div class="auth-modal" id="auth-modal">
        <div class="auth-container">
            <button class="close-modal" id="close-modal">
                <i class="fas fa-times"></i>
            </button>
            
            <div class="auth-header">
                <h2 class="auth-title" id="auth-title">
                    <?php 
                    if ($reset_step === 'request') echo 'Welcome to AnimeGIF';
                    elseif ($reset_step === 'verify') echo 'Verify OTP';
                    elseif ($reset_step === 'reset') echo 'Reset Password';
                    else echo ($show_signup_form ? 'Join AnimeGIF' : 'Welcome to AnimeGIF'); 
                    ?>
                </h2>
                <p class="auth-subtitle" id="auth-subtitle">
                    <?php 
                    if ($reset_step === 'request') echo ($show_signup_form ? 'Create your account to get started' : 'Please log in to access our collection');
                    elseif ($reset_step === 'verify') echo 'Enter the OTP sent to your email';
                    elseif ($reset_step === 'reset') echo 'Create a new password for your account';
                    else echo ($show_signup_form ? 'Create your account to get started' : 'Please log in to access our collection'); 
                    ?>
                </p>
            </div>
            
            <?php if ($error_message): ?>
                <div class="message error-message"><?php echo $error_message; ?></div>
            <?php endif; ?>
            
            <?php if ($success_message): ?>
                <div class="message success-message"><?php echo $success_message; ?></div>
            <?php endif; ?>
            
            <!-- LOGIN FORM -->
            <form class="auth-form <?php echo ($show_signup_form || $reset_step !== 'request') ? 'hidden' : ''; ?>" id="login-form" method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
                <div class="form-group">
                    <label class="form-label" for="login-email">Email</label>
                    <input type="email" class="form-input" id="login-email" name="email" placeholder="Enter your Gmail address" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label" for="login-password">Password</label>
                    <input type="password" class="form-input" id="login-password" name="password" placeholder="Enter your password" required>
                </div>
                
                <button type="submit" class="form-submit" name="login">Log In</button>
                
                <div class="auth-switch">
                    Don't have an account? <a id="switch-to-signup">Sign Up</a>
                </div>
            </form>
            
            <!-- SIGNUP FORM -->
            <form class="auth-form <?php echo ($show_signup_form && $reset_step === 'request') ? '' : 'hidden'; ?>" id="signup-form" method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
                <div class="form-group">
                    <label class="form-label" for="signup-email">Gmail Address</label>
                    <input type="email" class="form-input" id="signup-email" name="email" placeholder="Enter your Gmail address" value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" pattern="[a-zA-Z0-9._%+-]+@gmail\.com$" title="Please enter a valid Gmail address ending with @gmail.com" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label" for="signup-password">Password (min 8 characters)</label>
                    <input type="password" class="form-input" id="signup-password" name="password" placeholder="Create a password (min 8 characters)" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label" for="signup-confirm">Confirm Password</label>
                    <input type="password" class="form-input" id="signup-confirm" name="confirm_password" placeholder="Confirm your password" required>
                </div>
                
                <button type="submit" class="form-submit" name="signup">Create Account</button>
                
                <div class="auth-switch">
                    Already have an account? <a id="switch-to-login">Log In</a>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>

    <!-- Creative Header -->
    <header class="creative-header">
        <div class="container">
            <div class="header-content">
                <div class="logo-section">
                    <div class="logo">
                        <i class="fas fa-play-circle"></i>
                        ANIMEGIF
                    </div>
                </div>
                
                <!-- Centered Navigation -->
                <nav class="centered-nav">
                    <button class="nav-item active" data-section="dashboard">
                        <i class="fas fa-home"></i>
                        <span>Dashboard</span>
                    </button>
                    <button class="nav-item" data-section="search">
                        <i class="fas fa-search"></i>
                        <span>Search GIF</span>
                    </button>
                    <button class="nav-item" data-section="account">
                        <i class="fas fa-user"></i>
                        <span>Account</span>
                    </button>
                </nav>
                
                <!-- Right Side - Auth/User -->
                <div class="auth-section">
                    <?php if (!$isLoggedIn): ?>
                    <div class="auth-buttons">
                        <button class="auth-btn login-btn" id="header-login">Log In</button>
                        <button class="auth-btn signup-btn" id="header-signup">Sign Up</button>
                    </div>
                    <?php else: ?>
                    <div class="user-profile" id="user-profile">
                        <div class="user-avatar"><?php echo strtoupper(substr($username, 0, 1)); ?></div>
                        <span class="user-name"><?php echo htmlspecialchars($username); ?></span>
                        <div class="user-dropdown">
                            <a href="?logout=true" class="dropdown-item">
                                <i class="fas fa-sign-out-alt"></i>
                                <span>Log Out</span>
                            </a>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="main-content">
        <div class="container">
            <!-- Dashboard Section -->
            <section id="dashboard-section" class="content-section active">
                <div class="dashboard-hero">
                    <h1 class="dashboard-title">Discover Amazing Anime Content</h1>
                    <p class="dashboard-subtitle">Explore thousands of high-quality anime GIFs and images from your favorite series</p>
                    
                    <?php if ($isLoggedIn): ?>
                    <div class="quick-stats">
                        <div class="stat-card">
                            <div class="stat-icon">
                                <i class="fas fa-clock"></i>
                            </div>
                            <div class="stat-value"><?php echo formatTime($usage_stats['total']); ?></div>
                            <div class="stat-label">Total Usage Time</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-icon">
                                <i class="fas fa-search"></i>
                            </div>
                            <div class="stat-value" id="total-searches-value"><?php echo $search_stats['total_searches']; ?></div>
                            <div class="stat-label">Total Searches</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-icon">
                                <i class="fas fa-fire"></i>
                            </div>
                            <div class="stat-value" id="unique-categories-value"><?php echo $search_stats['unique_categories']; ?></div>
                            <div class="stat-label">Unique Categories</div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Trending Section -->
                <div class="trending-section">
                    <div class="trending-header">
                        <h2 class="section-title">Trending Categories</h2>
                        <?php if ($isLoggedIn): ?>
                        <button class="refresh-trending" id="refresh-trending">
                            <i class="fas fa-sync-alt"></i> Refresh Trends
                        </button>
                        <?php endif; ?>
                    </div>
                    
                    <div class="category-tags">
                        <?php if (count($trending_categories) > 0): ?>
                            <?php foreach ($trending_categories as $category): ?>
                                <div class="category-tag" data-category="<?php echo htmlspecialchars($category['category_name']); ?>">
                                    <?php echo htmlspecialchars(ucfirst($category['category_name'])); ?>
                                    <span class="search-count"><?php echo $category['search_count']; ?></span>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="category-tag" data-category="neko">Neko</div>
                            <div class="category-tag" data-category="kitsune">Kitsune</div>
                            <div class="category-tag" data-category="happy">Happy</div>
                            <div class="category-tag" data-category="dance">Dance</div>
                            <div class="category-tag" data-category="blush">Blush</div>
                            <div class="category-tag" data-category="wink">Wink</div>
                        <?php endif; ?>
                    </div>
                    
                    <h2 class="section-title">Featured Content</h2>
                    <div class="gif-grid dashboard-grid" id="dashboard-gif-grid">
                        <div class="loading">
                            <div class="loading-spinner"></div>
                            <?php echo $isLoggedIn ? 'Loading featured content...' : 'Please log in to access anime content...'; ?>
                        </div>
                    </div>
                    
                    <!-- Try It Now Button -->
                    <div class="try-now-section">
                        <button class="try-now-btn" id="try-now-btn">
                            <i class="fas fa-play-circle"></i>
                            Try It Now
                        </button>
                    </div>
                </div>
            </section>

            <!-- Search Section -->
            <section id="search-section" class="content-section">
                <div class="search-section">
                    <div class="search-container">
                        <h2 class="section-title">Search Anime Content</h2>
                        
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="<?php echo $isLoggedIn ? 'Search for anime GIFs...' : 'Please log in to search...'; ?>" id="search-input" <?php echo !$isLoggedIn ? 'disabled' : ''; ?>>
                            <button class="search-btn" id="search-btn" <?php echo !$isLoggedIn ? 'disabled' : ''; ?>>
                                <i class="fas fa-search"></i> Search
                            </button>
                        </div>
                        
                        <?php if ($isLoggedIn): ?>
                        <div class="action-buttons">
                            <button class="action-btn" id="random-btn">
                                <i class="fas fa-random"></i> Random
                            </button>
                            <button class="action-btn" id="view-toggle">
                                <i class="fas fa-th"></i> Grid View
                            </button>
                        </div>
                        <?php endif; ?>
                    </div>
                    
                    <?php if ($isLoggedIn && count($user_search_history) > 0): ?>
                    <div class="search-history-section">
                        <h3 class="section-title">Your Recent Searches</h3>
                        <div class="search-history-scroll" id="search-history-scroll">
                            <?php foreach ($user_search_history as $search): ?>
                            <div class="search-history-item" data-keyword="<?php echo htmlspecialchars($search['keyword']); ?>">
                                <div class="search-history-keyword"><?php echo htmlspecialchars(ucfirst($search['keyword'])); ?></div>
                                <div class="search-history-count"><?php echo $search['search_count']; ?> search<?php echo $search['search_count'] > 1 ? 'es' : ''; ?></div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <div class="gif-grid search-grid" id="search-gif-grid">
                        <div class="loading">
                            <div class="loading-spinner"></div>
                            <?php echo $isLoggedIn ? 'Ready to search...' : 'Please log in to search...'; ?>
                        </div>
                    </div>
                    
                    <!-- Pagination -->
                    <div class="pagination" id="pagination" style="display: none;">
                        <button class="pagination-btn" id="prev-btn" disabled>
                            <i class="fas fa-chevron-left"></i> Previous
                        </button>
                        <div class="pagination-info" id="page-info">Page 1 of 1</div>
                        <button class="pagination-btn" id="next-btn" disabled>
                            Next <i class="fas fa-chevron-right"></i>
                        </button>
                    </div>
                </div>
            </section>

            <!-- Account Section -->
            <section id="account-section" class="content-section">
                <div class="account-section">
                    <h2 class="section-title">Account Statistics</h2>
                    
                    <?php if ($isLoggedIn): ?>
                    <div class="account-stats">
                        <div class="account-card">
                            <h3><i class="fas fa-chart-line"></i> Usage Statistics</h3>
                            <table class="stats-table">
                                <tbody>
                                    <tr>
                                        <td>Today</td>
                                        <td class="time-value"><?php echo formatTime($usage_stats['today']); ?></td>
                                    </tr>
                                    <tr>
                                        <td>This Week</td>
                                        <td class="time-value"><?php echo formatTime($usage_stats['week']); ?></td>
                                    </tr>
                                    <tr>
                                        <td>This Month</td>
                                        <td class="time-value"><?php echo formatTime($usage_stats['month']); ?></td>
                                    </tr>
                                    <tr>
                                        <td>All Time</td>
                                        <td class="time-value"><?php echo formatTime($usage_stats['total']); ?></td>
                                    </tr>
                                    <tr>
                                        <td>Daily Average</td>
                                        <td class="time-value"><?php echo formatTime($usage_stats['avg_daily']); ?></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        
                        <div class="account-card">
                            <h3><i class="fas fa-search"></i> Search Activity</h3>
                            <table class="stats-table">
                                <tbody>
                                    <tr>
                                        <td>Total Searches</td>
                                        <td class="time-value" id="account-total-searches"><?php echo $search_stats['total_searches']; ?></td>
                                    </tr>
                                    <tr>
                                        <td>Unique Categories</td>
                                        <td class="time-value" id="account-unique-categories"><?php echo $search_stats['unique_categories']; ?></td>
                                    </tr>
                                    <tr>
                                        <td>Most Searched</td>
                                        <td class="time-value" id="account-most-searched">
                                            <?php echo $search_stats['most_searched']; ?>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Account Created</td>
                                        <td class="time-value"><?php echo date('M j, Y', strtotime($_SESSION['user_created'] ?? 'now')); ?></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div class="account-card">
                        <h3><i class="fas fa-key"></i> Account Security</h3>
                        <button class="change-password-btn" id="change-password-btn">
                            <i class="fas fa-lock"></i> Change Password
                        </button>
                        
                        <form class="change-password-form" id="change-password-form">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            
                            <div class="form-group">
                                <label class="form-label" for="current-password">Current Password</label>
                                <input type="password" class="form-input" id="current-password" name="current_password" placeholder="Enter current password" required>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label" for="new-password">New Password (min 8 characters)</label>
                                <input type="password" class="form-input" id="new-password" name="new_password" placeholder="Enter new password" required>
                                <div class="password-strength" id="change-password-strength">
                                    <div class="password-strength-fill"></div>
                                </div>
                                <div class="password-strength-text" id="change-password-text">Password strength</div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label" for="confirm-password">Confirm New Password</label>
                                <input type="password" class="form-input" id="confirm-password" name="confirm_password" placeholder="Confirm new password" required>
                            </div>
                            
                            <button type="submit" class="form-submit" id="change-password-submit">Update Password</button>
                        </form>
                    </div>
                    <?php else: ?>
                    <div class="account-card">
                        <div style="text-align: center; padding: 60px 20px;">
                            <i class="fas fa-user-lock" style="font-size: 4rem; color: var(--primary); margin-bottom: 20px; opacity: 0.7;"></i>
                            <h3 style="color: var(--primary); margin-bottom: 15px; font-size: 1.8rem;">Account Features Locked</h3>
                            <p style="color: #cbd5e1; margin-bottom: 30px; font-size: 1.1rem; max-width: 500px; margin-left: auto; margin-right: auto;">
                                Log in to view your detailed statistics, track your usage time, and manage your account settings.
                            </p>
                            <div style="display: flex; gap: 15px; justify-content: center; flex-wrap: wrap;">
                                <button class="auth-btn login-btn" id="account-login-btn">Log In</button>
                                <button class="auth-btn signup-btn" id="account-signup-btn">Create Account</button>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </section>
        </div>
    </main>

    <footer>
        <div class="container">
            <p>AnimeGIF &copy; 2023 - Your ultimate destination for anime content</p>
        </div>
    </footer>

    <script>
        // Configuration
        const API_BASE_URL = 'https://nekos.best/api/v2';
        const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
        const isLoggedIn = <?php echo $isLoggedIn ? 'true' : 'false'; ?>;
        
        // Valid categories
        const validCategories = [
            'neko', 'husbando', 'kitsune', 'waifu', 
            'shinobu', 'megumin', 'uniform', 'maid',
            'marin', 'selfies', 'wave', 'wink',
            'tea', 'bonk', 'punch', 'poke',
            'bully', 'pat', 'kiss', 'kick',
            'happy', 'hold', 'hug', 'cuddle',
            'cry', 'smug', 'blush', 'sleep',
            'highfive', 'handhold', 'bite', 'glomp',
            'slap', 'kill', 'kick', 'happy',
            'wave', 'tease', 'feed', 'smug',
            'run', 'facepalm', 'confused', 'bow'
        ];
        
        // State
        let currentCategory = 'neko';
        let currentMediaType = 'gif';
        let isGridView = true;
        let usageUpdateInterval = null;
        let secondsCounter = 0;
        
        // Pagination state
        let currentPage = 1;
        let totalPages = 1;
        let currentResults = [];
        const RESULTS_PER_PAGE = 4;
        
        // DOM Elements
        const navItems = document.querySelectorAll('.nav-item');
        const contentSections = document.querySelectorAll('.content-section');
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');
        const randomBtn = document.getElementById('random-btn');
        const viewToggle = document.getElementById('view-toggle');
        const categoryTags = document.querySelectorAll('.category-tag');
        const refreshTrendingBtn = document.getElementById('refresh-trending');
        const changePasswordBtn = document.getElementById('change-password-btn');
        const changePasswordForm = document.getElementById('change-password-form');
        const authModal = document.getElementById('auth-modal');
        const headerLoginBtn = document.getElementById('header-login');
        const headerSignupBtn = document.getElementById('header-signup');
        const accountLoginBtn = document.getElementById('account-login-btn');
        const accountSignupBtn = document.getElementById('account-signup-btn');
        const closeModal = document.getElementById('close-modal');
        const switchToSignup = document.getElementById('switch-to-signup');
        const switchToLogin = document.getElementById('switch-to-login');
        const userProfile = document.getElementById('user-profile');
        const tryNowBtn = document.getElementById('try-now-btn');
        
        // Pagination elements
        const pagination = document.getElementById('pagination');
        const prevBtn = document.getElementById('prev-btn');
        const nextBtn = document.getElementById('next-btn');
        const pageInfo = document.getElementById('page-info');
        
        // Stats elements
        const totalSearchesValue = document.getElementById('total-searches-value');
        const uniqueCategoriesValue = document.getElementById('unique-categories-value');
        const accountTotalSearches = document.getElementById('account-total-searches');
        const accountUniqueCategories = document.getElementById('account-unique-categories');
        const accountMostSearched = document.getElementById('account-most-searched');
        const searchHistoryScroll = document.getElementById('search-history-scroll');
        
        // Initialize the application
        function init() {
            setupEventListeners();
            setupNavigation();
            
            if (isLoggedIn) {
                startUsageTracking();
                loadDashboardContent();
            }
        }
        
        // Setup navigation
        function setupNavigation() {
            navItems.forEach(item => {
                item.addEventListener('click', () => {
                    const targetSection = item.getAttribute('data-section');
                    
                    // Update active nav item
                    navItems.forEach(nav => nav.classList.remove('active'));
                    item.classList.add('active');
                    
                    // Show target section
                    contentSections.forEach(section => {
                        section.classList.remove('active');
                        if (section.id === `${targetSection}-section`) {
                            section.classList.add('active');
                        }
                    });
                    
                    // Load section-specific content
                    if (targetSection === 'dashboard' && isLoggedIn) {
                        loadDashboardContent();
                    }
                });
            });
        }
        
        // Setup event listeners
        function setupEventListeners() {
            // Search functionality
            if (searchBtn) {
                searchBtn.addEventListener('click', handleSearch);
            }
            
            if (searchInput) {
                searchInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        handleSearch();
                    }
                });
            }
            
            // Random button
            if (randomBtn) {
                randomBtn.addEventListener('click', fetchRandomGifs);
            }
            
            // View toggle
            if (viewToggle) {
                viewToggle.addEventListener('click', toggleViewMode);
            }
            
            // Category tags
            categoryTags.forEach(tag => {
                tag.addEventListener('click', () => {
                    if (!isLoggedIn) {
                        showAuthModal();
                        return;
                    }
                    
                    const category = tag.getAttribute('data-category');
                    currentCategory = category;
                    updateSearchHistory(category);
                    
                    if (document.getElementById('search-section').classList.contains('active')) {
                        fetchAnimeGifs(category, 'search-gif-grid');
                    } else {
                        fetchAnimeGifs(category, 'dashboard-gif-grid');
                    }
                    
                    if (searchInput) searchInput.value = '';
                });
            });
            
            // Search history items
            if (searchHistoryScroll) {
                searchHistoryScroll.addEventListener('click', (e) => {
                    const historyItem = e.target.closest('.search-history-item');
                    if (historyItem && isLoggedIn) {
                        const keyword = historyItem.getAttribute('data-keyword');
                        currentCategory = keyword;
                        
                        if (searchInput) {
                            searchInput.value = keyword;
                        }
                        
                        fetchAnimeGifs(keyword, 'search-gif-grid');
                        updateSearchHistory(keyword);
                    }
                });
            }
            
            // Refresh trending
            if (refreshTrendingBtn) {
                refreshTrendingBtn.addEventListener('click', refreshTrending);
            }
            
            // Change password button
            if (changePasswordBtn) {
                changePasswordBtn.addEventListener('click', () => {
                    changePasswordForm.classList.toggle('active');
                });
            }
            
            // Change password form
            if (changePasswordForm) {
                changePasswordForm.addEventListener('submit', handleChangePassword);
            }
            
            // Auth modal
            if (headerLoginBtn) headerLoginBtn.addEventListener('click', showAuthModal);
            if (headerSignupBtn) headerSignupBtn.addEventListener('click', showAuthModal);
            if (accountLoginBtn) accountLoginBtn.addEventListener('click', showAuthModal);
            if (accountSignupBtn) accountSignupBtn.addEventListener('click', showAuthModal);
            if (closeModal) closeModal.addEventListener('click', hideAuthModal);
            if (switchToSignup) switchToSignup.addEventListener('click', showSignupForm);
            if (switchToLogin) switchToLogin.addEventListener('click', showLoginForm);
            
            // User profile dropdown
            if (userProfile) {
                userProfile.addEventListener('click', (e) => {
                    e.stopPropagation();
                    userProfile.classList.toggle('active');
                });
                
                // Close dropdown when clicking outside
                document.addEventListener('click', () => {
                    if (userProfile.classList.contains('active')) {
                        userProfile.classList.remove('active');
                    }
                });
            }
            
            // Try Now button
            if (tryNowBtn) {
                tryNowBtn.addEventListener('click', () => {
                    // Switch to search section
                    document.querySelector('[data-section="search"]').click();
                    
                    // Focus on search input
                    if (searchInput) {
                        searchInput.focus();
                    }
                });
            }
            
            // Pagination buttons
            if (prevBtn) {
                prevBtn.addEventListener('click', () => {
                    if (currentPage > 1) {
                        currentPage--;
                        displayCurrentPage();
                    }
                });
            }
            
            if (nextBtn) {
                nextBtn.addEventListener('click', () => {
                    if (currentPage < totalPages) {
                        currentPage++;
                        displayCurrentPage();
                    }
                });
            }
            
            // Close modal when clicking outside
            if (authModal) {
                authModal.addEventListener('click', (e) => {
                    if (e.target === authModal) {
                        hideAuthModal();
                    }
                });
            }
        }
        
        // Auth modal functions
        function showAuthModal() {
            if (authModal) authModal.classList.remove('hidden');
        }
        
        function hideAuthModal() {
            if (authModal) authModal.classList.add('hidden');
        }
        
        function showLoginForm() {
            document.getElementById('login-form').classList.remove('hidden');
            document.getElementById('signup-form').classList.add('hidden');
            document.getElementById('auth-title').textContent = 'Welcome Back';
            document.getElementById('auth-subtitle').textContent = 'Log in to your account';
        }
        
        function showSignupForm() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('signup-form').classList.remove('hidden');
            document.getElementById('auth-title').textContent = 'Join AnimeGIF';
            document.getElementById('auth-subtitle').textContent = 'Create your account to get started';
        }
        
        // Search functionality
        function handleSearch() {
            if (!isLoggedIn) {
                showAuthModal();
                return;
            }
            
            const searchTerm = searchInput.value.trim().toLowerCase();
            
            if (searchTerm === '') {
                fetchAnimeGifs(currentCategory, 'search-gif-grid');
                return;
            }
            
            if (!validCategories.includes(searchTerm)) {
                showApiError(`"${searchTerm}" is not a valid category. Try: ${validCategories.slice(0, 6).join(', ')}`, 'search-gif-grid');
                return;
            }
            
            currentCategory = searchTerm;
            updateSearchHistory(searchTerm);
            fetchAnimeGifs(searchTerm, 'search-gif-grid');
        }
        
        // Fetch random GIFs
        function fetchRandomGifs() {
            const randomCategory = validCategories[Math.floor(Math.random() * validCategories.length)];
            currentCategory = randomCategory;
            updateSearchHistory(randomCategory);
            
            if (searchInput) {
                searchInput.value = '';
            }
            
            fetchAnimeGifs(randomCategory, 'search-gif-grid');
        }
        
        // Toggle view mode (only for search section)
        function toggleViewMode() {
            // Only apply to search section
            if (!document.getElementById('search-section').classList.contains('active')) {
                return;
            }
            
            isGridView = !isGridView;
            const searchGrid = document.getElementById('search-gif-grid');
            
            if (searchGrid) {
                if (isGridView) {
                    searchGrid.classList.remove('list-view');
                    viewToggle.innerHTML = '<i class="fas fa-th"></i> Grid View';
                } else {
                    searchGrid.classList.add('list-view');
                    viewToggle.innerHTML = '<i class="fas fa-list"></i> List View';
                }
            }
        }
        
        // Load dashboard content
        function loadDashboardContent() {
            fetchAnimeGifs('neko', 'dashboard-gif-grid');
        }
        
        // Fetch anime content from API
        async function fetchAnimeGifs(category, gridId) {
            const grid = document.getElementById(gridId);
            if (!grid) return;
            
            grid.innerHTML = `
                <div class="loading">
                    <div class="loading-spinner"></div>
                    Loading ${category} content...
                </div>
            `;
            
            // Reset pagination for search section
            if (gridId === 'search-gif-grid') {
                currentPage = 1;
                pagination.style.display = 'none';
            }
            
            try {
                let apiUrl = `${API_BASE_URL}/${category}?amount=20`;
                
                const response = await fetch(apiUrl);
                
                if (!response.ok) {
                    throw new Error(`API request failed with status ${response.status}`);
                }
                
                const data = await response.json();
                
                if (data.results && data.results.length > 0) {
                    if (gridId === 'search-gif-grid') {
                        // For search section, implement pagination
                        currentResults = data.results;
                        totalPages = Math.ceil(currentResults.length / RESULTS_PER_PAGE);
                        displayCurrentPage();
                        
                        // Show pagination if there are multiple pages
                        if (totalPages > 1) {
                            pagination.style.display = 'flex';
                            updatePaginationButtons();
                        }
                    } else {
                        // For dashboard, show all results (limited to 8)
                        const limitedResults = data.results.slice(0, 8);
                        displayGifs(limitedResults, gridId);
                    }
                } else {
                    showApiError(`No results found for "${category}"`, gridId);
                }
            } catch (error) {
                console.error('Error fetching anime content:', error);
                showApiError(`Failed to load content for "${category}"`, gridId);
            }
        }
        
        // Display current page of results
        function displayCurrentPage() {
            const startIndex = (currentPage - 1) * RESULTS_PER_PAGE;
            const endIndex = startIndex + RESULTS_PER_PAGE;
            const pageResults = currentResults.slice(startIndex, endIndex);
            
            displayGifs(pageResults, 'search-gif-grid');
            updatePaginationInfo();
            updatePaginationButtons();
        }
        
        // Update pagination information
        function updatePaginationInfo() {
            if (pageInfo) {
                pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
            }
        }
        
        // Update pagination buttons
        function updatePaginationButtons() {
            if (prevBtn) {
                prevBtn.disabled = currentPage <= 1;
            }
            if (nextBtn) {
                nextBtn.disabled = currentPage >= totalPages;
            }
        }
        
        // Display GIFs in grid
        function displayGifs(gifs, gridId) {
            const grid = document.getElementById(gridId);
            grid.innerHTML = '';
            
            gifs.forEach(gif => {
                const gifCard = document.createElement('div');
                gifCard.className = 'gif-card';
                
                const imageUrl = gif.url || (gif.images && gif.images[0] && gif.images[0].url);
                const animeName = gif.anime_name || 'Anime Content';
                
                gifCard.innerHTML = `
                    <img src="${imageUrl}" alt="${animeName}" class="gif-img" loading="lazy">
                    <div class="gif-title">${animeName}</div>
                    <div class="gif-overlay">
                        <div class="gif-actions">
                            <button class="gif-action-btn view-gif" title="View Fullscreen">
                                <i class="fas fa-expand"></i>
                            </button>
                            <button class="gif-action-btn share-gif" title="Share">
                                <i class="fas fa-share"></i>
                            </button>
                        </div>
                    </div>
                `;
                
                // Add event listeners
                const viewBtn = gifCard.querySelector('.view-gif');
                const shareBtn = gifCard.querySelector('.share-gif');
                
                viewBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openFullscreen(imageUrl, animeName);
                });
                
                shareBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    shareContent(imageUrl);
                });
                
                // Click on card to open fullscreen
                gifCard.addEventListener('click', () => {
                    openFullscreen(imageUrl, animeName);
                });
                
                grid.appendChild(gifCard);
            });
        }
        
        // Show API error
        function showApiError(message, gridId) {
            const grid = document.getElementById(gridId);
            grid.innerHTML = `
                <div class="api-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>${message}</h3>
                    <p>Try these categories instead: ${validCategories.slice(0, 8).join(', ')}</p>
                </div>
            `;
        }
        
        // Update search history
        function updateSearchHistory(keyword) {
            const formData = new FormData();
            formData.append('keyword', keyword);
            formData.append('csrf_token', csrfToken);
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('Search history updated:', data.message);
                    // Update the UI with new data
                    updateSearchHistoryUI(data.search_history);
                    updateSearchStatsUI(data.search_stats);
                }
            })
            .catch(error => {
                console.error('Error updating search history:', error);
            });
        }
        
        // Update search history UI
        function updateSearchHistoryUI(searchHistory) {
            if (!searchHistoryScroll) return;
            
            searchHistoryScroll.innerHTML = '';
            
            searchHistory.forEach(search => {
                const historyItem = document.createElement('div');
                historyItem.className = 'search-history-item';
                historyItem.setAttribute('data-keyword', search.keyword);
                historyItem.innerHTML = `
                    <div class="search-history-keyword">${ucfirst(search.keyword)}</div>
                    <div class="search-history-count">${search.search_count} search${search.search_count > 1 ? 'es' : ''}</div>
                `;
                searchHistoryScroll.appendChild(historyItem);
            });
        }
        
        // Update search stats UI
        function updateSearchStatsUI(searchStats) {
            if (totalSearchesValue) {
                totalSearchesValue.textContent = searchStats.total_searches;
            }
            if (uniqueCategoriesValue) {
                uniqueCategoriesValue.textContent = searchStats.unique_categories;
            }
            if (accountTotalSearches) {
                accountTotalSearches.textContent = searchStats.total_searches;
            }
            if (accountUniqueCategories) {
                accountUniqueCategories.textContent = searchStats.unique_categories;
            }
            if (accountMostSearched) {
                accountMostSearched.textContent = searchStats.most_searched;
            }
        }
        
        // Utility function to capitalize first letter
        function ucfirst(str) {
            return str.charAt(0).toUpperCase() + str.slice(1);
        }
        
        // Refresh trending categories
        function refreshTrending() {
            if (refreshTrendingBtn) {
                const originalHTML = refreshTrendingBtn.innerHTML;
                refreshTrendingBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
                refreshTrendingBtn.disabled = true;
                
                window.location.href = '?refresh_trending=true';
            }
        }
        
        // Handle change password
        function handleChangePassword(event) {
            event.preventDefault();
            
            const formData = new FormData(changePasswordForm);
            formData.append('change_password', '1');
            formData.append('csrf_token', csrfToken);
            
            const submitBtn = document.getElementById('change-password-submit');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage(data.message, 'success');
                    changePasswordForm.reset();
                    changePasswordForm.classList.remove('active');
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error changing password:', error);
                showMessage('An error occurred. Please try again.', 'error');
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Update Password';
            });
        }
        
        // Show message
        function showMessage(message, type) {
            // Create toast message
            const toast = document.createElement('div');
            toast.className = `message ${type}-message`;
            toast.textContent = message;
            toast.style.position = 'fixed';
            toast.style.top = '20px';
            toast.style.right = '20px';
            toast.style.zIndex = '3000';
            toast.style.maxWidth = '300px';
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.remove();
            }, 5000);
        }
        
        // Open fullscreen view
        function openFullscreen(url, title) {
            // In a real implementation, you would create a fullscreen modal
            // For now, we'll just open the image in a new tab
            window.open(url, '_blank');
        }
        
        // Share content
        function shareContent(url) {
            if (navigator.share) {
                navigator.share({
                    title: 'Check out this anime content!',
                    url: url
                });
            } else {
                navigator.clipboard.writeText(url).then(() => {
                    showMessage('URL copied to clipboard!', 'success');
                });
            }
        }
        
        // Usage tracking
        function startUsageTracking() {
            usageUpdateInterval = setInterval(() => {
                if (!document.hidden) {
                    secondsCounter++;
                    
                    if (secondsCounter % 30 === 0) {
                        updateUsageTime(30);
                    }
                }
            }, 1000);
        }
        
        function updateUsageTime(seconds) {
            const formData = new FormData();
            formData.append('update_usage', '1');
            formData.append('seconds', seconds);
            formData.append('csrf_token', csrfToken);
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('Usage time updated');
                }
            })
            .catch(error => {
                console.error('Error updating usage time:', error);
            });
        }
        
        // Handle page visibility change
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                if (usageUpdateInterval) {
                    clearInterval(usageUpdateInterval);
                    usageUpdateInterval = null;
                }
            } else {
                if (!usageUpdateInterval && isLoggedIn) {
                    startUsageTracking();
                }
            }
        });
        
        // Initialize the app
        init();
    </script>
</body>
</html>