<?php
header('Content-Type: application/json');
session_start();

function sanitize($data){return htmlspecialchars(strip_tags(trim($data)));}

// Anti-spam: honeypot and token & minimum form time (3 sec)
$honeypot = $_POST['honeypot'] ?? '';
$token = $_POST['token'] ?? '';
$start_time = $_SESSION['start_time'] ?? time();

if(!empty($honeypot) || time()-$start_time<3){
    echo json_encode(['status'=>'error','message'=>'Bot detected']); exit;
}

$name = sanitize($_POST['name'] ?? '');
$email = sanitize($_POST['email'] ?? '');
$message = sanitize($_POST['message'] ?? '');

if(empty($name) || empty($email) || empty($message) || !filter_var($email, FILTER_VALIDATE_EMAIL)){
    echo json_encode(['status'=>'error','message'=>'Invalid input']); exit;
}

// Handle attachment
$attachment_path = '';
if(isset($_FILES['attachment']) && $_FILES['attachment']['error']==0){
    $allowed = ['jpg','png','pdf','docx','txt'];
    $ext = strtolower(pathinfo($_FILES['attachment']['name'],PATHINFO_EXTENSION));
    if(!in_array($ext,$allowed) || $_FILES['attachment']['size']>5*1024*1024){
        echo json_encode(['status'=>'error','message'=>'Invalid file']); exit;
    }
    $attachment_path = 'uploads/'.uniqid().'_'.basename($_FILES['attachment']['name']);
    if(!move_uploaded_file($_FILES['attachment']['tmp_name'],$attachment_path)){
        echo json_encode(['status'=>'error','message'=>'File upload failed']); exit;
    }
}

// Send Email
$to = "your-email@example.com";
$subject = "God Mode Contact Form: $name";
$body = "Name: $name\nEmail: $email\n\nMessage:\n$message";
$headers = "From: $email\r\nReply-To: $email";

if($attachment_path){
    $boundary = md5(time());
    $headers .= "\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{$boundary}\"";
    $body_message = "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n$body\r\n";
    $file_content = chunk_split(base64_encode(file_get_contents($attachment_path)));
    $body_message .= "--{$boundary}\r\nContent-Type: application/octet-stream; name=\"".basename($attachment_path)."\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"".basename($attachment_path)."\"\r\n\r\n{$file_content}\r\n--{$boundary}--";
} else {
    $body_message = $body;
}

if(mail($to,$subject,$body_message,$headers)){
    echo json_encode(['status'=>'success']);
}else{
    echo json_encode(['status'=>'error','message'=>'Mail could not be sent']);
}
?>