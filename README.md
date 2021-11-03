# PruebasCifradoAes

Este cifrado esta implementado en C# obtenemos el mismo resultado que el método el cifrado en PHP:

$ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA);
$ciphertext64 = base64_encode($ciphertext);
