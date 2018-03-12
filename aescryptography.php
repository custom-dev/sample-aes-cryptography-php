<?php
    function displayHelp() {
		echo "AesCryptography\n";
		echo "===============\n";
		echo "\n";
		echo "Usage:\n";
		echo "AesCryptography encrypt [input file] [output file]\n";
		echo "AesCryptography decrypt [input file] [output file]\n";
	}
	
	function getKey($password, $salt) {
		$key = hash_pbkdf2("sha1", $password, $salt, 100, 32, TRUE);
		return $key;
	}
	
	function decryptWithAes($cipherText, $key) {
		$iv = substr($cipherText, 0, 16);
		$encryptedText = substr($cipherText, 16);
		$data = openssl_decrypt($encryptedText, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
		
		if (ord($data[0]) == 1)
		{
			$signature = substr($data,1, 32);
			$content = substr($data, 32 + 1);
			$computedSignature = hash('sha256', $content, true);
			
			if ($signature != $computedSignature)
			{				
				echo "Corrupted data";
			}
			else
			{
				return $content;
			}
		}
		else
		{
			var_dump($data);
			echo "Corrupted data";
		}
		
		return null;
	}
	
	function encryptWithAes($plainText, $key) 
	{
		$iv = random_bytes(16);
		$sha256 = hash('sha256', $plainText, true);
		
		$contentToEncrypt = chr(1) . $sha256 . $plainText;
		$data = openssl_encrypt($contentToEncrypt, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
		return $iv . $data;
	}
	
	if ($argc != 4) {
		displayHelp();
		return;	
	}
	
	$command = $argv[1];
	$inputFile = $argv[2];
	$outputFile = $argv[3];
	
	// Salt used to generate the key
    // No special consideration about security (salt can be public)
	$salt = hex2bin('0001020304050607');
	
	// Password used to generate the key.
    // 
    // SECURITY NOTICE
    // ---------------
    // This is a SAMPLE program.
    // 
    // For security reasons, password MUST NOT BE :
    // - hardcoded in program (like in this program)
    // - passed as a argument of a command line utility 
    // 
    // Please use a secured method to retrieve the password.
	$password = '1234';
	
	$inputContent = file_get_contents($inputFile);
	$key = getKey($password, $salt);
	
	switch($command)
	{
		case 'encrypt':
			$outputContent = encryptWithAes($inputContent, $key);
			break;
		case 'decrypt':
			$outputContent = decryptWithAes($inputContent, $key);
			break;
		default:
			displayHelp();
			return;
	}
	
	file_put_contents($outputFile, $outputContent);
?>