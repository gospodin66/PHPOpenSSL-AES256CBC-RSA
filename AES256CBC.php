<?php

class AES256CBC {
    
    private const ENCRYPTION_PARAMS = [
        'CYPHER' => 'AES-256-CBC',
        'OPTIONS' => OPENSSL_RAW_DATA,
        'HASH_ALGO' => 'sha256',
        'HASH_LEN' => 32,
    ];

    private $envfile = '.aes256cbc_key.hidden';
    private $aes_key = "";

    public function get_aes_key() : string {
        return $this->aes_key;
    }

    public function __construct() {
        try {
            if(file_exists($this->envfile) === false){
                echo self::ENCRYPTION_PARAMS['CYPHER']." key not found..\n";
                $this->aes_key = base64_encode(openssl_random_pseudo_bytes(32));
                echo "Created new key.\n";
                if(false === file_put_contents($this->envfile, $this->aes_key)){
                    echo "Error saving ".self::ENCRYPTION_PARAMS['CYPHER']." key.\n";
                    $this->aes_key = "";
                }
            } else { 
                if(($this->aes_key = file_get_contents($this->envfile)) === false){
                    echo "Error reading ".self::ENCRYPTION_PARAMS['CYPHER']." key.\n";
                    $this->aes_key = "";
                }
            }
        } catch(\Throwable $e) {
            echo "Fetch ".self::ENCRYPTION_PARAMS['CYPHER']." key error: {$e->getMessage()}\n";
            $this->aes_key = "";
        }
    }
   

    public function encrypt_cbc(string $clrtext, string $base64key = "") : string {
        // if(($base64key = self::fetch_AES_CBC_key()) === ""){
        //     echo "Error fetching ".self::ENCRYPTION_PARAMS['CYPHER']." key.\n";
        //     return "";
        // }
        $this->aes_key = base64_decode($base64key);
        $ivlen = openssl_cipher_iv_length(self::ENCRYPTION_PARAMS['CYPHER']);
        $iv = openssl_random_pseudo_bytes($ivlen);
        try {
            $ciphertext = openssl_encrypt($clrtext, self::ENCRYPTION_PARAMS['CYPHER'], $this->aes_key, self::ENCRYPTION_PARAMS['OPTIONS'], $iv);
        } catch (\Throwable $e){
            echo "Encrypt ".self::ENCRYPTION_PARAMS['CYPHER']." error: {$e->getMessage()}\n";
            return "";
        }
        $hmac = hash_hmac(self::ENCRYPTION_PARAMS['HASH_ALGO'], $iv.$ciphertext, $this->aes_key, true);
        return base64_encode($iv.$hmac.$ciphertext);
    }

    public function decrypt_cbc(string $encrypted, string $base64key) : string {
        if(empty($encrypted)){
            echo "Invalid/Empty cyphertext.\n";
            return "";
        }
        // if(($base64key = self::fetch_AES_CBC_key()) === ""){
        //     echo "Error fetching ".self::ENCRYPTION_PARAMS['CYPHER']." key.\n";
        //     return "";
        // }
        $this->aes_key = base64_decode($base64key);
        $encrypted = base64_decode($encrypted);
        $ivlen = openssl_cipher_iv_length(self::ENCRYPTION_PARAMS['CYPHER']);
        $iv = substr($encrypted, 0, $ivlen);
        $hmac = substr($encrypted, $ivlen, self::ENCRYPTION_PARAMS['HASH_LEN']);
        $ciphertext = substr($encrypted, ($ivlen+self::ENCRYPTION_PARAMS['HASH_LEN']));
        try {
            $clrtext = openssl_decrypt($ciphertext, self::ENCRYPTION_PARAMS['CYPHER'], $this->aes_key, self::ENCRYPTION_PARAMS['OPTIONS'], $iv);
            if($clrtext === false){
                echo "Error ".self::ENCRYPTION_PARAMS['CYPHER'].": data decrypt failed.\n";
                return "";
            }
            $calcmac = hash_hmac(self::ENCRYPTION_PARAMS['HASH_ALGO'], $iv.$ciphertext, $this->aes_key, true);
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
            echo "Decrypt ".self::ENCRYPTION_PARAMS['CYPHER']." error: {$e->getMessage()}\n";
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
        return ( ! ctype_print($s));
    }
}
?>