package fr.delthas.libsilence.test;

import fr.delthas.libsilence.Message;
import fr.delthas.libsilence.MultimediaMessage;
import fr.delthas.libsilence.Silence;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Optional;
import java.util.Random;

public class SilenceTest {
  
  private Random random;
  
  @Before
  public void initRandom() {
    random = new Random(0xAE0AE0AE0AE0AE0AL);
  }
  
  private void handshake(Silence[] silence) {
    String key = silence[0].encryptKeyInit("1");
    Optional<Message> message = silence[1].decrypt("0", key);
    Assert.assertTrue(message.isPresent());
    Message message_ = message.get();
    Assert.assertTrue(message_.isKeyInit());
    Assert.assertTrue(message_.isValid());
    Optional<String> keyOptional = silence[1].encryptKeyResponse(message_.asKeyInit());
    Assert.assertTrue(keyOptional.isPresent());
    key = keyOptional.get();
    Optional<Message> messageResponse = silence[0].decrypt("1", key);
    Assert.assertTrue(messageResponse.isPresent());
    Message messageResponse_ = messageResponse.get();
    Assert.assertTrue(messageResponse_.isValid());
    Assert.assertTrue(messageResponse_.isKeyResponse());
    Assert.assertArrayEquals(silence[0].getSelfFingerprint(), message_.asKeyInit().getFingerprint());
    Assert.assertArrayEquals(silence[1].getSelfFingerprint(), messageResponse_.asKeyResponse().getFingerprint());
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
    Optional<MultimediaMessage> message_ = silence[0].encryptMultimedia("1", data);
    Assert.assertTrue(message_.isPresent());
    MultimediaMessage message = message_.get();
    Optional<byte[]> received_ = silence[1].decryptMultimedia("0", message);
    Assert.assertTrue(received_.isPresent());
    byte[] received = received_.get();
    Assert.assertArrayEquals(data, received);
  }
}
