<?php
class AES256CBC_RSA {
    
    private const CYPHER = 'AES-256-CBC';
    private const OPTIONS = OPENSSL_RAW_DATA;
    private const HASH_ALGO = 'sha256';
    private const HASH_LEN = 32;
    private const PRIVATE_KEY_LENGTH = 4096;
    private const CRYPTO_HASH_ALGO_512 = 'sha512';
    private const KEYS_DIR = './keys';

    public function fetch_AES_CBC_key() : string {
        try {
            if(file_exists('.env') === false){
                echo "AES key not found.. Created new key.\n";
                $key = base64_encode(openssl_random_pseudo_bytes(32));
                if(false === file_put_contents('.env', $key)){
                    echo "Error saving AES key.\n";
                    $key = "";
                }
            } else { 
                if(($key = file_get_contents(".env")) === false){
                    echo "Error reading AES key.\n";
                    $key = "";
                }
            }
        } catch(\Throwable $e) {
            echo "Fetch AES CBC key error: {$e->getMessage()}\n";
            $key = "";
        }
        return $key;
    }

    public function generate_RSA_keypair(string $user = 'master') : bool {
        $private_path = self::KEYS_DIR."/$user/private.pem";
        $public_path  = self::KEYS_DIR."/$user/public.pem";
        $privateKeyString = file_exists($private_path) ? file_get_contents($private_path) : "";
        $publicKeyString  = file_exists($public_path)  ? file_get_contents($public_path)  : "";
        // generate keypair if !exists
        if(empty($privateKeyString) || empty($publicKeyString))
        {
            $keyPair = openssl_pkey_new([
                "digest_alg" => self::CRYPTO_HASH_ALGO_512,
                "private_key_bits" => self::PRIVATE_KEY_LENGTH,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ]);
            openssl_pkey_export($keyPair, $privateKeyString);
            $keyDetails = openssl_pkey_get_details($keyPair);
            $publicKeyString = $keyDetails["key"];
            if( ! file_exists(self::KEYS_DIR."/$user")){
                if( ! mkdir(self::KEYS_DIR."/$user", 0755, true)){
                    echo "mkdir() user-dir error.\n";
                    return false;
                }
            }
            if(file_put_contents($private_path, $privateKeyString) === false
             || file_put_contents($public_path, $publicKeyString) === false)
            {
                echo "Keypair store error.\n";
                return false;
            }
        }
        return true;
    }

    private function get_RSA_keypair(string $user = 'master', string $passphrase) : array {
        $private_path = self::KEYS_DIR."/$user/private.pem";
        $public_path  = self::KEYS_DIR."/$user/public.pem";
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : "";
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : "";
        if(empty($privateKeyString) || empty($publicKeyString)) {
            echo "Empty key strings.\n";
            return [];
        }
        if(false === ($publicKey = openssl_pkey_get_public([$publicKeyString, $passphrase]))) {
            echo "Malformed public key!\n";
        }
        if(false === ($privateKey = openssl_pkey_get_private([$privateKeyString, $passphrase]))) {
            echo "Malformed private key!\n";
        }
        return ['public' => $publicKey, 'private' => $privateKey];
    }

    public function get_RSA_keypair_strings(string $user = 'master') : array {
        $private_path = self::KEYS_DIR."/$user/private.pem";
        $public_path  = self::KEYS_DIR."/$user/public.pem";
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : "";
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : "";
        return ['public' => $publicKeyString, 'private' => $privateKeyString];
    }

    /**
     * 
     * @param user => username for encryption
     * @param passphrase => passphrase for encryption
     * @param data => data to encrypt
     * 
     * @return string
     */
    public function encryptRSA(string $user, string $passphrase, $data, string $keytype = 'public') : string {
        if(false === ($keypair = self::get_RSA_keypair($user, $passphrase))){
            echo "Error fetching RSA key.\n";
            return "";
        }
        if($keytype === 'public'){
            if(false === openssl_public_encrypt($data, $encryptedWithPublic, $keypair['public'])) {
                echo "Error encrypting with public key.\n";
                return "";
            }
        } else if($keytype === 'private'){
            if(false === openssl_private_encrypt($data, $encryptedWithPrivate, $keypair['private'])) {
                echo "Error encrypting with private key.\n";
                return "";
            }
        } else {
            echo "Invalid key type.\n";
            return "";
        }
        return (($keytype === 'public')
                ? base64_encode($encryptedWithPublic)
                : (($keytype === 'private')
                ? base64_encode($encryptedWithPrivate)
                : "")); 
    }

    /**
     * 
     * @param user => username for encryption
     * @param passphrase => passphrase for encryption
     * @param encryptedb64 => data to encrypt
     * 
     * @return string
     */
    public function decryptRSA(string $user, string $passphrase, string $encryptedb64, string $keytype = 'public') : string {
        if(false === ($keypair = self::get_RSA_keypair($user, $passphrase))){
            echo "Error fetching RSA key.\n";
            return "";
        }
        $encrypted = base64_decode($encryptedb64);
        if($keytype === 'public'){
            if(false === openssl_public_decrypt($encrypted, $decrtypted, $keypair['public'])) {
                echo "Error decrypting with public key what was encrypted with private key\n";
                return "";
            }
        } else if($keytype === 'private'){
            if(false === openssl_private_decrypt($encrypted, $decrtypted, $keypair['private'])) {
                echo "Error decrypting with private key what was encrypted with public key\n";
                return "";
            }
        } else {
            echo "Invalid key type.\n";
            return "";
        }
        return $decrtypted;
    }


    public function encrypt_cbc(string $clrtext, string $key = "") : string {
        if(($base64key = self::fetch_AES_CBC_key()) === null){
            echo "Error fetching key.\n";
            return "";
        }
        $key = base64_decode($base64key);
        try {
            $ivlen = openssl_cipher_iv_length(self::CYPHER);
            $iv = openssl_random_pseudo_bytes($ivlen);
            $ciphertext = openssl_encrypt($clrtext, self::CYPHER, $key, self::OPTIONS, $iv);
            $hmac = hash_hmac(self::HASH_ALGO, $iv.$ciphertext, $key, true);
            return base64_encode($iv.$hmac.$ciphertext);
        } catch (\Throwable $e){
            echo "Encrypt CBC error: {$e->getMessage()}\n";
        }
        return "";
    }

    public function decrypt_cbc($encrypted){
        if(empty($encrypted)){
            echo "Invalid/Empty cyphertext.\n";
            return "";
        }
        if(($base64key = self::fetch_AES_CBC_key()) === null){
            echo "Error fetching key.\n";
            return "";
        }
        $key = base64_decode($base64key);
        $encrypted = base64_decode($encrypted);
        try {
            $ivlen = openssl_cipher_iv_length(self::CYPHER);
            $iv = substr($encrypted, 0, $ivlen);
            $hmac = substr($encrypted, $ivlen, self::HASH_LEN);
            $ciphertext = substr($encrypted, ($ivlen+self::HASH_LEN));
            $clrtext = openssl_decrypt($ciphertext, self::CYPHER, $key, self::OPTIONS, $iv);
            if($clrtext === false){
                echo "Error decrypting data.\n";
                return "";
            }
            $calcmac = hash_hmac(self::HASH_ALGO, $iv.$ciphertext, $key, true);
            if(function_exists('hash_equals')){
                if (hash_equals($hmac, $calcmac)){
                    return $clrtext;
                }
            } else {
                if ($this->hash_equals_custom($hmac, $calcmac)){ 
                    return $clrtext;
                }
            }
            return "";
        } catch (\Throwable $e){
            echo "Decrypt CBC error: {$e->getMessage()}\n";
        }
        return "";
    }

    /**
     * (Optional)
     * hash_equals() function polyfilling.
     * PHP 5.6+ timing attack safe comparison
     */
    private function hash_equals_custom(string $knownString, string $userString) : bool {
        if (function_exists('mb_strlen')) {
            $kLen = mb_strlen($knownString, '8bit');
            $uLen = mb_strlen($userString, '8bit');
        } else {
            $kLen = strlen($knownString);
            $uLen = strlen($userString);
        }
        if ($kLen !== $uLen) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $kLen; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userString[$i]));
        }
        return (0 === $result);
    }

    private static function is_binary(string $s) : bool {
        return ( ! ctype_print($s)) ? true : false;
    }
}
?>