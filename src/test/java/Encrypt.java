import is.moo.cryptography.symmetric.ChaCha20Poly1305;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class Encrypt {

    String key = "DEUNGSIMANSIMCHADOLARONGSATE@EAT";
    String plainString = "Moomoo~ Says moo!";

    @Test
    public void keyLength() {
        assertEquals(32, key.length());
    }

    @Test
    public void encryptAndDecrypt() throws Exception {
        String enc = ChaCha20Poly1305.encrypt(plainString, key);
        String dec = ChaCha20Poly1305.decrypt(enc, key);
        assertEquals(plainString, dec);
    }


}
