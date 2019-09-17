package fr.delthas.libsilence.test;

import fr.delthas.libsilence.Message;
import fr.delthas.libsilence.MultimediaMessage;
import fr.delthas.libsilence.Silence;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Random;

public class SilenceTest {
  
  private Random random;
  
  @Before
  public void initRandom() {
    random = new Random(0xAE0AE0AE0AE0AE0AL);
  }
  
  private void handshake(Silence[] silence) {
    String key = silence[0].encryptKeyInit("1");
    Message message = silence[1].decrypt("0", key);
    Assert.assertNotNull(message);
    Assert.assertTrue(message.isKeyInit());
    Assert.assertTrue(message.isValid());
    String keyResponse = silence[1].encryptKeyResponse(message.asKeyInit());
    Assert.assertNotNull(keyResponse);
    Message messageResponse = silence[0].decrypt("1", keyResponse);
    Assert.assertNotNull(messageResponse);
    Assert.assertTrue(messageResponse.isValid());
    Assert.assertTrue(messageResponse.isKeyResponse());
    Assert.assertArrayEquals(silence[0].getSelfFingerprint(), message.asKeyInit().getFingerprint());
    Assert.assertArrayEquals(silence[1].getSelfFingerprint(), messageResponse.asKeyResponse().getFingerprint());
  }
  
  @Test
  public void handshakeTest() {
    Silence[] silence = {new Silence(), new Silence()};
    handshake(silence);
  }
  
  @Test
  public void multimediaTest() {
    Silence[] silence = {new Silence(), new Silence()};
    handshake(silence);
    byte[] data = new byte[16384];
    random.nextBytes(data);
    MultimediaMessage message = silence[0].encryptMultimedia("1", data);
    Assert.assertNotNull(message);
    byte[] received = silence[1].decryptMultimedia("0", message);
    Assert.assertNotNull(received);
    Assert.assertArrayEquals(data, received);
  }
}
