<?php

$exit = 0;
$user = $argv[1] ?? 'master';
$clrtxt = $argv[2] ?? '';
$passphrase = $argv[3] ?? '';
$opt = $argv[4] ?? 'AES';

if($opt === 'AES'){
    require "AES256CBC.php";

    $openssl = new AES256CBC;
    $AES_key = $openssl->get_aes_key();
    $cyptertxt = $openssl->encrypt_cbc($clrtxt,$AES_key);
    $decrypted = $openssl->decrypt_cbc($cyptertxt,$AES_key);

    echo "Key: {$AES_key}\r\n";
    echo "Cyphertext: {$cyptertxt}\r\n";
    echo "Decrypted: {$decrypted}\r\n";
}
else if($opt === 'RSA'){
    require "RSA.php";

    $openssl = new RSA;
    $openssl->generate_RSA_keypair($user);
    $RSA_keys = $openssl->get_RSA_keypair_strings($user);

    $cyphertxtpub = $openssl->encryptRSA($user,$passphrase,$clrtxt,'public');
    $cyphertxtpriv = $openssl->encryptRSA($user,$passphrase,$clrtxt,'private');

    $decryptedpub = $openssl->decryptRSA($user,$passphrase,$cyphertxtpriv,'public');
    $decryptedpriv = $openssl->decryptRSA($user,$passphrase,$cyphertxtpub,'private');

    echo "Cyphertext with public: {$cyphertxtpub}\r\n\r\n";
    echo "Cyphertext with private: {$cyphertxtpriv}\r\n\r\n";
    echo "Decrypted with public: {$decryptedpub}\r\n";
    echo "Decrypted with private: {$decryptedpriv}\r\n";
} else {
    echo "Invalid encryption method option.\r\n";
    $exit = 1;
}

exit($exit);

?>