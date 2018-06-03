package fr.delthas.libsilence.test;

import fr.delthas.libsilence.Message;
import fr.delthas.libsilence.Silence;
import org.junit.Assert;
import org.junit.Test;

import java.util.Optional;

public class SilenceTest {
  @Test
  public void silenceTest() {
    Silence[] silence = {new Silence(), new Silence()};
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
}
