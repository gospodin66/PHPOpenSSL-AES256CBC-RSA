<?php
require "AES256CBC_RSA.php";
$openssl = new AES256CBC_RSA;
$user = $argv[1] ?? 'master';
$clrtxt = $argv[2] ?? '';
$passphrase = $argv[2] ?? '';
$openssl->generate_RSA_keypair($user);
$RSA_keys = $openssl->get_RSA_keypair_strings($user);
$cyphertxtpub = $openssl->encryptRSA($user, $passphrase, $clrtxt, 'public');
$cyphertxtpriv = $openssl->encryptRSA($user, $passphrase, $clrtxt, 'private');
$decryptedpub = $openssl->decryptRSA($user, $passphrase, $cyphertxtpriv, 'public');
$decryptedpriv = $openssl->decryptRSA($user, $passphrase, $cyphertxtpub, 'private');
echo "\r\nRSA::\r\n";
echo "Cyphertext with public: {$cyphertxtpub}\r\n\r\n";
echo "Cyphertext with private: {$cyphertxtpriv}\r\n\r\n";
echo "Decrypted with public: {$decryptedpub}\r\n";
echo "Decrypted with private: {$decryptedpriv}\r\n\r\n";
$AES_key = $openssl->fetch_AES_CBC_key();
$cyptertxt = $openssl->encrypt_cbc($clrtxt, $AES_key);
$decrypted = $openssl->decrypt_cbc($cyptertxt);
echo "\r\nAES-256-CBC::\r\n";
echo "Key: {$AES_key}\n\n";
echo "Cyphertext: {$cyptertxt}\n\n";
echo "Decrypted: {$decrypted}\n\n";
exit(0);
?>