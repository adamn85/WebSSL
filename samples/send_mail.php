<?php

require '../src/SecurePHPMailer.class.php';

$mail = new SecurePHPMailer('user.crt', 'user.key');
// Send Email

try {
		
    //Server settings
    $mail->SMTPDebug = 1;       // Enable verbose debug output
    $mail->isSMTP();            // Set mailer to use SMTP
    $mail->Host       = '';     // Specify main and backup SMTP servers
    $mail->SMTPAuth   = true;   // Enable SMTP authentication
    $mail->Username   = '';     // SMTP username
    $mail->Password   = '';     // SMTP password
    $mail->SMTPSecure = 'ssl';  // Enable TLS encryption, `ssl` also accepted
    $mail->Port       = 465;    // TCP port to connect to

    //Recipients
    $mail->setFrom('', 'Mailer');
    $mail->addAddress('');     
    $mail->addAddress('');   	// Name is optional
    $mail->addReplyTo('', 'Information');

    // Format
    $mail->isHTML(true);

    // Content
    $mail->Subject = "PHPSecureServer";
	$mail->Body = '<h3>this is really secret uh</h3>';

	//$mail->sendSignedEmail();
	//$mail->sendEncryptedEmail('YourCertificate.crt');


}  catch (Exception $e) {
    echo $e->getMessage();
}


?>
