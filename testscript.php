<?php
require "AES256CBC_RSA.php";
$openssl = new AES256CBC_RSA;

$passphrase = "hehehe";
$clrtxt = "This is a secret message! 666";
$user = "test";

$openssl->generate_RSA_keypair($user);
$RSA_keys = $openssl->get_RSA_keypair_strings($user);
$cyphertxtpub = $openssl->encryptRSA($user, $passphrase, $clrtxt, 'public');
$cyphertxtpriv = $openssl->encryptRSA($user, $passphrase, $clrtxt, 'private');
$decryptedpub = $openssl->decryptRSA($user, $passphrase, $cyphertxtpriv, 'public');
$decryptedpriv = $openssl->decryptRSA($user, $passphrase, $cyphertxtpub, 'private');
echo "\r\nRSA::\r\n";
var_dump($cyphertxtpub,$cyphertxtpriv,$decryptedpub,$decryptedpriv);

$AES_key = $openssl->fetch_AESCBC_key();
$cyptertxt = $openssl->encrypt_cbc($clrtxt, $AES_key);
$decrypted = $openssl->decrypt_cbc($cyptertxt);
echo "\r\nAES-CBC::\r\n";
var_dump($AES_key, $cyptertxt, $decrypted);

exit(0);
?>