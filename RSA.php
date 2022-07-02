<?php

class RSA {

    private const RSA_KEYS_DIR = './RSA-keys';

    private const ENCRYPTION_PARAMS = [
        'PRIVATE_KEY_LENGTH' => 4096,
        'CRYPTO_HASH_ALGO_512' => 'sha512',
    ];

    public function generate_RSA_keypair(string $user = 'master') : bool {
        $private_path = self::RSA_KEYS_DIR."/$user/private.pem";
        $public_path  = self::RSA_KEYS_DIR."/$user/public.pem";
        $privateKeyString = file_exists($private_path) ? file_get_contents($private_path) : "";
        $publicKeyString  = file_exists($public_path)  ? file_get_contents($public_path)  : "";
        // generate keypair if !exists
        if(empty($privateKeyString) || empty($publicKeyString))
        {
            $keyPair = openssl_pkey_new([
                "digest_alg" => self::ENCRYPTION_PARAMS['CRYPTO_HASH_ALGO_512'],
                "private_key_bits" => self::ENCRYPTION_PARAMS['PRIVATE_KEY_LENGTH'],
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ]);
            openssl_pkey_export($keyPair, $privateKeyString);
            $keyDetails = openssl_pkey_get_details($keyPair);
            $publicKeyString = $keyDetails["key"];
            if( ! file_exists(self::RSA_KEYS_DIR."/$user")){
                if( ! mkdir(self::RSA_KEYS_DIR."/$user", 0755, true)){
                    echo "Error RSA: mkdir() user-dir error.\n";
                    return false;
                }
            }
            if(file_put_contents($private_path, $privateKeyString) === false
             || file_put_contents($public_path, $publicKeyString) === false)
            {
                echo "RSA keypair store error.\n";
                return false;
            }
        }
        return true;
    }
    
    private function get_RSA_keypair(string $user = 'master', string $passphrase) : array {
        $private_path = self::RSA_KEYS_DIR."/$user/private.pem";
        $public_path  = self::RSA_KEYS_DIR."/$user/public.pem";
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : "";
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : "";
        if(empty($privateKeyString) || empty($publicKeyString)) {
            echo "Empty key strings.\n";
            return [];
        }
        if(false === ($publicKey = openssl_pkey_get_public([$publicKeyString, $passphrase]))) {
            echo "Malformed public key!\n";
            return [];
        }
        if(false === ($privateKey = openssl_pkey_get_private([$privateKeyString, $passphrase]))) {
            echo "Malformed private key!\n";
            return [];
        }
        return ['public' => $publicKey, 'private' => $privateKey];
    }
    
    public function get_RSA_keypair_strings(string $user = 'master') : array {
        $private_path = self::RSA_KEYS_DIR."/$user/private.pem";
        $public_path  = self::RSA_KEYS_DIR."/$user/public.pem";
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
                echo "Error RSA: encrypt failed with public key.\n";
                return "";
            }
        } else if($keytype === 'private'){
            if(false === openssl_private_encrypt($data, $encryptedWithPrivate, $keypair['private'])) {
                echo "Error RSA: encrypt failed with private key.\n";
                return "";
            }
        } else {
            echo "Invalid RSA key type.\n";
            return "";
        }
        return ($keytype === 'public')   ? base64_encode($encryptedWithPublic)
             : (($keytype === 'private') ? base64_encode($encryptedWithPrivate)
             : ""); 
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
                echo "Error RSA: decrypt failed with public key what was encrypted with private key.\n";
                return "";
            }
        } else if($keytype === 'private'){
            if(false === openssl_private_decrypt($encrypted, $decrtypted, $keypair['private'])) {
                echo "Error RSA: decrypt failed with private key what was encrypted with public key.\n";
                return "";
            }
        } else {
            echo "Invalid RSA key type.\n";
            return "";
        }
        return $decrtypted;
    }
    
}

?>