<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

require 'config.php';

$response = ['success' => false, 'message' => 'Invalid action'];

if($_SERVER['REQUEST_METHOD'] == 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if($input['action'] == 'register') {
        $username = $input['username'];
        $email = $input['email'];
        $password = $input['password'];
        
        // Validate password strength
        if(strlen($password) < 8 || 
           !preg_match('/[A-Z]/', $password) ||
           !preg_match('/[a-z]/', $password) ||
           !preg_match('/[0-9]/', $password) ||
           !preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) {
            $response = ['success' => false, 'message' => 'Password does not meet requirements'];
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            
            try {
                $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                $stmt->execute([$username, $email, $hashed_password]);
                $response = ['success' => true, 'message' => 'Registration successful!'];
            } catch(PDOException $e) {
                $response = ['success' => false, 'message' => 'Username or email already exists!'];
            }
        }
    }
    
    elseif($input['action'] == 'login') {
        $username = $input['username'];
        $password = $input['password'];
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if($user && password_verify($password, $user['password'])) {
            $response = ['success' => true, 'message' => 'Login successful!', 'username' => $user['username']];
        } else {
            $response = ['success' => false, 'message' => 'Invalid username or password!'];
        }
    }
}

echo json_encode($response);
?>
