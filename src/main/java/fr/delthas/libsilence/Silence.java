package fr.delthas.libsilence;

import com.google.protobuf.ByteString;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.protocol.SignalProtos;
import org.whispersystems.libsignal.ratchet.*;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.KeyHelper;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * The entrypoint for all encrypt and decrypt operations. <b>For general, "getting started" library usage, see <a href="https://github.com/delthas/libsilence-java">the library README</a>.</b>
 * <p>
 * Start by constructing a Silence instance, either by creating a fresh new state with {@link #Silence()}, or by loading it from a saved state with {@link #Silence(InputStream)}. When you're done using the instance, you must save it using {@link #saveTo(OutputStream)}.
 * <p>
 * Use the {@code encryptXXX} methods to create/encrypt Silence messages before sending them, and {@link #decrypt(String, String)} to decrypt incoming messages.
 * <p>
 * The library fully supports calls by concurrent threads. All input and output Strings are considered UTF-8 encoded. All parameters and return values of the public methods must not be null.
 * <p>
 * For advanced usage, you can extend the Silence class to use the lower-level protected methods that start with {@code _}.
 *
 * @see Silence#encryptText(String, String)
 * @see Silence#decrypt(String, String)
 */
public class Silence {
  private static final String[] MESSAGE_TYPES = {"TSK", "TSM", "TSP", "TSE", "TSX"};
  private static final Base64.Encoder encoder;
  private static final Base64.Decoder decoder;
  
  static {
    encoder = Base64.getEncoder().withoutPadding();
    decoder = Base64.getDecoder();
  }
  
  private SerializableSignalProtocolStore sessionStore;
  private final Object lock = new Object();
  
  /**
   * Create a Silence instance from saved state. The input stream <b>MUST</b> read from data previously saved with {@link #saveTo(OutputStream)}.
   * <p>
   * To create a fresh new Silence instance on first user, use {@link #Silence()} instead.
   *
   * @param in The input stream to read the saved state from.
   * @throws IOException If an exception is thrown when reading from the stream, or if the data is invalid.
   *
   * @see #Silence()
   */
  public Silence(InputStream in) throws IOException {
    Objects.requireNonNull(in);
    sessionStore = new SerializableSignalProtocolStore(in);
  }
  
  /**
   * Create a fresh new Silence instance.
   * <p>
   * To create a Silence instance from previously saved state, use {@link #Silence(InputStream)} instead.
   *
   * @see #Silence(InputStream)
   */
  public Silence() {
    try {
      sessionStore = new SerializableSignalProtocolStore(null);
    } catch (IOException ex) {
      // will never happen
      throw new AssertionError(ex);
    }
  }
  
  /**
   * Save the current Silence state to the output stream.
   * <p>
   * The general contract regarding the state is that it may arbitrarily change after every single call to a {@code encryptXXX} or {@code decrypt} method, and that you <b>must</b> always use the current state to do all operations. This means that you must always load the state from a state saved after calling the last {@code encryptXXX} or {@code decrypt} method.
   * @param out The output stream to write the state to.
   * @throws IOException If an exception is thrown when reading from the stream, or if the data is invalid.
   */
  public final void saveTo(OutputStream out) throws IOException {
    synchronized (lock) {
      sessionStore.save(Objects.requireNonNull(out));
    }
  }
  
  /**
   * Creates a Silence secure session begin/key initialization message.
   * <p>
   * The returned String, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * <b>If a secure session was already established for this address, this will reset it, without sending a {@link Message.SessionEnd} message.</b> You may encrypt and send a {@link Message.SessionEnd} first to avoid this.
   * @param address The unique identifier for the contact for which the message must be encrypted.
   * @return The encrypted text message for the text.
   */
  public String encryptKeyInit(String address) {
    synchronized (lock) {
      return _encryptKeyInit(Objects.requireNonNull(address), true);
    }
  }
  
  /**
   * Creates a Silence key response message.
   * <p>
   * The returned String, if not null, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * <b>This will automatically accept the KeyInit message and start the secure session so you can send encrypted text messages with {@link #encryptText(String, String)} afterwards.</b>
   * <p>
   * The returned String will be null if the message couldn't be created, which happens if the {@link Message.KeyInit} message couldn't be trusted or if a secure session was already established. To end a secure session, send a session end message with {@link #encryptSessionEnd(String)} or decrypt one.
   * @param keyInit The previously received {@link Message.KeyInit} message to accept.
   * @return A String containing the key response message to be sent over the message transfer wire, or null if the message couldn't be created.
   */
  public String encryptKeyResponse(Message.KeyInit keyInit) {
    synchronized (lock) {
      _acceptKeyInit(Objects.requireNonNull(keyInit));
      return _encryptKeyResponse(keyInit);
    }
  }
  
  /**
   * Encrypts some text into a Silence encrypted text message.
   * <p>
   * The returned String, if not null, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * The returned String will be null if the message couldn't be encrypted, which happens if no secure session is currently established for this address.
   * <p>
   * <b>The text must not contain any null bytes (value 0).</b>
   * @param address The unique identifier for the contact for which the message must be encrypted.
   * @param text The text to encrypt.
   * @return A String containing the encrypted text message to be sent over the message transfer wire, or null if the text couldn't be encrypted.
   */
  public String encryptText(String address, String text) {
    Objects.requireNonNull(address);
    Objects.requireNonNull(text);
    synchronized (lock) {
      return _encryptText(address, text);
    }
  }
  
  /**
   * Encrypts a Silence session end message.
   * <p>
   * The returned String, if not null, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * <b>This will automatically end the secure session, you won't be able to encrypt or decrypt secure messages for this session after this call.</b> You can however create a new secure session.
   * <p>
   * The returned String will be null if the message couldn't be created, which happens which happens if no secure session is currently established for this address.
   * @param address The unique identifier for the contact for which the message must be encrypted.
   * @return A String containing the key response message to be sent over the message transfer wire, or null if the message couldn't be created.
   */
  public String encryptSessionEnd(String address) {
    Objects.requireNonNull(address);
    synchronized (lock) {
      String encrypted = _encryptSessionEnd(address);
      if (encrypted == null) {
        return null;
      }
      _endSession(address);
      return encrypted;
    }
  }
  
  /**
   * Encrypts some data into a Silence multimedia message (MMS).
   * <p>
   * This method can be used to encrypt multimedia messages, either to send them as MMS to Silence users, or to send them as is to users of this library (to be later decrypted with {@link #decryptMultimedia(String, MultimediaMessage)}.
   * <p>
   * Only encrypted messages can be sent as multimedia messages (not key init, key response or key end messages), but for this use case it is more efficient with regard to encrypted message length and processing speed than {@link #encryptText(String, String)} as it does not do any SMS-specific padding.
   * <p>
   * The data you pass can be any arbitrary binary data, but if the message is to be sent as an MMS, the data must be the exact encoded MMS PDU data (as would be returned by e.g. {@code PduComposer(context, message).make() from the Android internal MMS library}).
   * <p>
   * The returned {@link MultimediaMessage}, if not null, will contain both a plaintext subject and some encrypted data. If the message is to be sent as an MMS, the MMS PDU that must be sent should have the exact subject {@link MultimediaMessage#getSubject()}, and have a single PDU body part with content type {@code text/plain} and value {@link MultimediaMessage#getData()}.
   * <p>
   * The returned {@link MultimediaMessage} will be null if the message couldn't be encrypted, which happens if no secure session is currently established for this address.
   * @param address The unique identifier for the contact for which the message must be encrypted.
   * @param data The data to encrypt (in the case of an MMS, the encoded MMS PDU data).
   * @return A MultimediaMessage containing the encrypted multimedia message to be sent over the message transfer wire or by MMS, or null if the data couldn't be encrypted.
   * @see #decryptMultimedia(String, MultimediaMessage)
   */
  public MultimediaMessage encryptMultimedia(String address, byte[] data) {
    Objects.requireNonNull(address);
    Objects.requireNonNull(data);
    synchronized (lock) {
      SessionCipher sessionCipher = new SessionCipher(sessionStore, new SignalProtocolAddress(address, 1));
      try {
        CiphertextMessage ciphertextMessage = sessionCipher.encrypt(data);
        String encrypted = encoder.encodeToString(ciphertextMessage.serialize());
        String subject;
        try {
          byte[] postfix = new byte[6];
          SecureRandom.getInstance("SHA1PRNG").nextBytes(postfix);
    
          byte[] postfixEncoded = encoder.encode(postfix);
  
          MessageDigest md = MessageDigest.getInstance("SHA1");
          byte[] runningDigest = postfixEncoded;
  
          for (int i=0;i<1000;i++) {
            runningDigest = md.digest(runningDigest);
          }
  
          String prefix = encoder.encodeToString(new byte[]{runningDigest[0], runningDigest[1], runningDigest[2], runningDigest[3], runningDigest[4], runningDigest[5]});
          
          subject = prefix + new String(postfixEncoded);
        } catch (NoSuchAlgorithmException e) {
          throw new AssertionError(e);
        }
        return new MultimediaMessage(subject, encrypted);
      } catch (Exception e) {
        return null;
      }
    }
  }
  
  /**
   * Decrypts a Silence message.
   * <p>
   * <b>Since you cannot know whether received messages are Silence messages, you can use this endpoint for all incoming messages (this method will return null if the message is not a Silence message).</b>
   * <p>
   * The text you pass should be the exact String that was sent from the underlying message transfer wire (in general, this means the exact received SMS).
   * <p>
   * The returned Message, if not null, will be a valid {@link Message.KeyInit}, {@link Message.KeyResponse}, {@link Message.Text}, or {@link Message.SessionEnd} message corresponding to the text.
   * <p>
   * <b>Some automatic session processing can happen when decrypting a message, and a message should generally be decrypted only once. For example, decrypting a {@link Message.SessionEnd} message will automatically end the secure session.</b>. See the individual Message documentation for details.
   * <p>
   * The returned Message will be null if the message was not a valid Silence message or if it was invalid with regard to the secure session (for example, receiving a {@link Message.KeyInit} message when a session was already established).
   * @param address The unique identifier for the contact from which the message was received.
   * @param text The exact message that was received from the underlying message transfer wire.
   * @return A Message containing the decrypted Silence {@link Message}, or null if the message was not a valid Silence message or was invalid.
   */
  public Message decrypt(String address, String text) {
    Objects.requireNonNull(address);
    Objects.requireNonNull(text);
    synchronized (lock) {
      String header = _getHeader(address, text);
      if (header == null) {
        return null;
      }
      Message message = _decrypt(address, header, text);
      if (message != null && message.isValid()) {
        switch (message.getType()) {
          case KEY_RESPONSE:
            _acceptKeyResponse(message.asKeyResponse());
            break;
          case SESSION_END:
            _endSession(message.getAddress());
            break;
          default:
        }
      }
      return message;
    }
  }
  
  /**
   * Decrypts a Silence multimedia message (MMS).
   * <p>
   * This method can be used to decrypt multimedia messages from peers using Silence over MMS, but it can also be used to decrypt messages created from {@link #encryptMultimedia(String, byte[])} of this library.
   * <p>
   * Only encrypted messages can be sent as multimedia messages (not key init, key response or key end messages), but for this use case it is more efficient with regard to encrypted message length and processing speed as it does not do any SMS-specific padding.
   * <p>
   * <b>Since you cannot know whether received multimedia messages are Silence messages, you can use this endpoint for all incoming multimedia messages (this method will return null if the message is not a Silence message).</b>
   * <p>
   * The data you pass can be any arbitrary binary data, but if the incoming message is an MMS, it must be the exact String of the first MMS PDU part whose type is {@code text/plain}.
   * <p>
   * The returned byte array, if not null, will be a raw byte array representing the decrypted data. If the incoming message was an MMS, the decrypted data is the raw decrypted MMS PDU, that could be decoded by using e.g. {@code PduParser(data)} from the Android internal MMS library.
   * <p>
   * <b>Some automatic session processing can happen when decrypting a message, and a message should generally be decrypted only once.</b>
   * <p>
   * The returned byte array will be null if the message was not a valid Silence message or if it was invalid with regard to the secure session.
   * @param address The unique identifier for the contact from which the message was received.
   * @param message The encrypted multimedia message.
   * @return A byte array containing the decrypted data (in the case of an MMS, the raw decrypted MMS PDU data), or null if the message was not a valid Silence message or was invalid.
   * @see #encryptMultimedia(String, byte[])
   * @see MultimediaMessage
   */
  public byte[] decryptMultimedia(String address, MultimediaMessage message) {
    Objects.requireNonNull(address);
    Objects.requireNonNull(message);
    String subject = message.getSubject();
    String data = message.getData();
    if (subject.length() < 9)
      return null;
  
    String prefix = subject.substring(0, 8);
    String postfix = subject.substring(8);
  
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException e) {
      throw new InternalError(e);
    }
    byte[] runningDigest = postfix.getBytes();
  
    for (int i = 0; i < 1000; i++) {
      runningDigest = md.digest(runningDigest);
    }
  
    String calculatedPrefix = encoder.encodeToString(new byte[]{runningDigest[0], runningDigest[1], runningDigest[2], runningDigest[3], runningDigest[4], runningDigest[5]});
    
    if(!prefix.equals(calculatedPrefix)) {
      return null;
    }
  
    byte[] plainText;
    synchronized (lock) {
      byte[] decoded = decoder.decode(data.getBytes());
      SessionCipher sessionCipher = new SessionCipher(sessionStore, new SignalProtocolAddress(address, 1));
      try {
        try {
          plainText = sessionCipher.decrypt(new SignalMessage(decoded));
        } catch (InvalidMessageException e) {
          // workaround for Sprint appending a character at the end of MMS PDU body
          // text parts: try to decrypt without the last character if the decryption fails
          if (data.length() > 2) {
            byte[] original = data.getBytes();
            byte[] trimmed = new byte[original.length];
            System.arraycopy(original, 0, trimmed, 0, trimmed.length);
            decoded = decoder.decode(trimmed);
            plainText = sessionCipher.decrypt(new SignalMessage(decoded));
          } else {
            throw e;
          }
        }
      } catch (Exception e) {
        return null;
      }
    }
    
    return plainText;
  }
  
  /**
   * Returns the fingerprint of a contact with which a secure session is currently established.
   * <p>
   * To view the fingerprint as a string of hex characters, like in the Silence Android app, simply convert the byte array to a hex representation, for example by using {@link org.whispersystems.libsignal.util.Hex#toString(byte[])}, bundled as a dependency of this library.
   * <p>
   * The returned byte array will be null if no secure session is currently established with the specified contact.
   * @param address The unique identifier for the contact to get the fingerprint of.
   * @return A byte array containing the fingerprint of the contact, or null if no secure session with the contact is currently established.
   */
  public final byte[] getFingerprint(String address) {
    Objects.requireNonNull(address);
    synchronized (lock) {
      Objects.requireNonNull(address);
      SignalProtocolAddress address_ = new SignalProtocolAddress(address, 1);
      return sessionStore.loadSession(address_).getSessionState().serialize();
    }
  }
  
  /**
   * Returns your fingerprint (the one your contacts will see when they establish a secure session with you). This fingerprint is the same for all your contacts.
   * <p>
   * To view the fingerprint as a string of hex characters, like in the Silence Android app, simply convert the byte array to a hex representation, for example by using {@link org.whispersystems.libsignal.util.Hex#toString(byte[])}, bundled as a dependency of this library.
   * @return Your fingerprint.
   */
  public final byte[] getSelfFingerprint() {
    synchronized (lock) {
      return sessionStore.getIdentityKeyPair().getPublicKey().serialize();
    }
  }
  
  protected final String _encryptText(String address, String text) {
    return encrypt(address, text, "TSM");
  }
  
  protected final String _encryptKeyInit(String address, boolean resetSession) {
    SignalProtocolAddress remoteAddress = new SignalProtocolAddress(address, 1);
    try {
      int sequence = KeyHelper.getRandomSequence(65534) + 1;
      int flags = 0x01;
      ECKeyPair baseKey = Curve.generateKeyPair();
      ECKeyPair ratchetKey = Curve.generateKeyPair();
      IdentityKeyPair identityKey = sessionStore.getIdentityKeyPair();
      byte[] baseKeySignature = Curve.calculateSignature(identityKey.getPrivateKey(), baseKey.getPublicKey().serialize());
      SessionRecord sessionRecord = sessionStore.loadSession(remoteAddress);
      
      sessionRecord.getSessionState().setPendingKeyExchange(sequence, baseKey, ratchetKey, identityKey);
      sessionStore.storeSession(remoteAddress, sessionRecord);
      
      
      int supportedVersion = CiphertextMessage.CURRENT_VERSION;
      int version = CiphertextMessage.CURRENT_VERSION;
      
      byte[] versionBytes = {ByteUtil.intsToByteHighAndLow(version, supportedVersion)};
      SignalProtos.KeyExchangeMessage.Builder keyBuilder = SignalProtos.KeyExchangeMessage
              .newBuilder()
              .setId((sequence << 5) | flags)
              .setBaseKey(ByteString.copyFrom(baseKey.getPublicKey().serialize()))
              .setRatchetKey(ByteString.copyFrom(ratchetKey.getPublicKey().serialize()))
              .setIdentityKey(ByteString.copyFrom(identityKey.getPublicKey().serialize()));
      
      keyBuilder.setBaseKeySignature(ByteString.copyFrom(baseKeySignature));
      
      return encrypt(address, encoder.encodeToString(ByteUtil.combine(versionBytes, keyBuilder.build().toByteArray())), "TSK");
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }
  
  protected final void _acceptKeyInit(Message.KeyInit keyInit) {
    SignalProtocolAddress address = new SignalProtocolAddress(keyInit.getAddress(), 1);
    sessionStore.storeSession(address, keyInit.getSessionRecord());
    sessionStore.saveIdentity(address, keyInit.getParameters().getTheirIdentityKey());
  }
  
  protected final String _encryptKeyResponse(Message.KeyInit keyInit) {
    
    byte[] baseKeySignature;
    try {
      baseKeySignature = Curve.calculateSignature(keyInit.getParameters().getOurIdentityKey().getPrivateKey(), keyInit.getParameters().getOurBaseKey().getPublicKey().serialize());
    } catch (InvalidKeyException e) {
      // should never happen
      throw new IllegalStateException("invalid state");
    }
    
    int supportedVersion = CiphertextMessage.CURRENT_VERSION;
    int version = keyInit.getSessionRecord().getSessionState().getSessionVersion();
    ECPublicKey baseKey = keyInit.getParameters().getOurBaseKey().getPublicKey();
    ECPublicKey ratchetKey = keyInit.getParameters().getOurRatchetKey().getPublicKey();
    IdentityKey identityKey = keyInit.getParameters().getOurIdentityKey().getPublicKey();
    
    byte[] versionBytes = {ByteUtil.intsToByteHighAndLow(version, supportedVersion)};
    SignalProtos.KeyExchangeMessage.Builder keyBuilder = SignalProtos.KeyExchangeMessage
            .newBuilder()
            .setId((keyInit.getSequence() << 5) | keyInit.getFlags())
            .setBaseKey(ByteString.copyFrom(baseKey.serialize()))
            .setRatchetKey(ByteString.copyFrom(ratchetKey.serialize()))
            .setIdentityKey(ByteString.copyFrom(identityKey.serialize()));
    
    if (version >= 3) {
      keyBuilder.setBaseKeySignature(ByteString.copyFrom(baseKeySignature));
    }
    
    String encodedMessage = encoder.encodeToString(ByteUtil.combine(versionBytes, keyBuilder.build().toByteArray()));
    
    return encrypt(keyInit.getAddress(), encodedMessage, "TSK");
  }
  
  protected final String _encryptSessionEnd(String addressString) {
    return encrypt(addressString, "TERMINATE", "TSE");
  }
  
  protected final void _acceptKeyResponse(Message.KeyResponse keyResponse) {
    SignalProtocolAddress address = new SignalProtocolAddress(keyResponse.getAddress(), 1);
    sessionStore.storeSession(address, keyResponse.getSessionRecord());
    sessionStore.saveIdentity(address, keyResponse.getParameters().getTheirIdentityKey());
  }
  
  protected final void _endSession(String addressString) {
    SignalProtocolAddress address = new SignalProtocolAddress(addressString, 1);
    sessionStore.deleteSession(address);
  }
  
  private String encrypt(String addressString, String message, String type) {
    SignalProtocolAddress address = new SignalProtocolAddress(addressString, 1);
    byte[] decoded;
    if (type.equals("TSM") || type.equals("TSE")) {
      byte[] messageBody = message.getBytes(StandardCharsets.UTF_8);
      int paddedBodySize;
      if (messageBody.length <= 63) {
        paddedBodySize = 63;
      } else {
        int encryptedBodyLength = messageBody.length + 53;
        int messageRecordsForBody = 1 + (encryptedBodyLength / 114);
        if (encryptedBodyLength % 114 > 0) {
          messageRecordsForBody++;
        }
        paddedBodySize = 62 + (114 * (messageRecordsForBody - 1));
      }
      
      byte[] paddedBody = new byte[paddedBodySize];
      System.arraycopy(messageBody, 0, paddedBody, 0, messageBody.length);
      
      if (!sessionStore.containsSession(address)) {
        return null;
      }
      
      SessionCipher cipher = new SessionCipher(sessionStore, address);
      CiphertextMessage ciphertextMessage;
      try {
        ciphertextMessage = cipher.encrypt(paddedBody);
      } catch (UntrustedIdentityException e) {
        // should never happen (the cipher uses the latest stored session and exists)
        return null;
      }
      decoded = ciphertextMessage.serialize();
    } else {
      decoded = decoder.decode(message);
    }
    
    byte[] messageWithMultipartHeader = new byte[decoded.length + 1];
    System.arraycopy(decoded, 0, messageWithMultipartHeader, 1, decoded.length);
    messageWithMultipartHeader[0] = decoded[0];
    messageWithMultipartHeader[1] = (byte) 1;
    message = encoder.encodeToString(messageWithMultipartHeader);
    
    String typePrefix = "?" + type;
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException e) {
      throw new InternalError(e);
    }
    byte[] runningDigest = (typePrefix + message).getBytes();
    
    for (int i = 0; i < 1000; i++) {
      runningDigest = md.digest(runningDigest);
    }
    
    return encoder.encodeToString(new byte[]{runningDigest[0], runningDigest[1], runningDigest[2]}) + message;
  }
  
  protected final String _getHeader(String addressString, String message) {
    if (message.length() <= 4) {
      return null;
    }
    String type = null;
    for (String prefixType : MESSAGE_TYPES) {
      String prefix = message.substring(0, 4);
      String messageBody = message.substring(4);
      
      MessageDigest md;
      try {
        md = MessageDigest.getInstance("SHA1");
      } catch (NoSuchAlgorithmException e) {
        throw new AssertionError(e);
      }
      byte[] runningDigest = ("?" + prefixType + messageBody).getBytes(StandardCharsets.UTF_8);
      
      for (int i = 0; i < 1000; i++) {
        runningDigest = md.digest(runningDigest);
      }
      
      String calculatedPrefix = Base64.getEncoder().encodeToString(new byte[]{runningDigest[0], runningDigest[1], runningDigest[2]});
      
      if (prefix.equals(calculatedPrefix)) {
        type = prefixType;
        break;
      }
    }
    return type;
  }
  
  protected final Message _decrypt(String addressString, String type, String message) {
    try {
      SignalProtocolAddress address = new SignalProtocolAddress(addressString, 1);
      
      if (message.length() < 4) {
        return null;
      }
      byte[] decoded = decoder.decode(message.substring(4));
      
      byte[] stripped = new byte[decoded.length - 1];
      System.arraycopy(decoded, 1, stripped, 0, decoded.length - 1);
      stripped[0] = decoded[0];
      
      decoded = stripped;
      
      switch (type) {
        case "TSX":
        case "TSP":
          return null;
        case "TSK": {
          byte[][] parts = ByteUtil.split(decoded, 1, decoded.length - 1);
          int version = ByteUtil.highBitsToInt(parts[0][0]);
          
          if (version < CiphertextMessage.CURRENT_VERSION) {
            return null;
          }
          
          if (version > CiphertextMessage.CURRENT_VERSION) {
            return null;
          }
          
          SignalProtos.KeyExchangeMessage keyExchangeMessage = SignalProtos.KeyExchangeMessage.parseFrom(parts[1]);
          
          if (!keyExchangeMessage.hasId() || !keyExchangeMessage.hasBaseKey() ||
                  !keyExchangeMessage.hasRatchetKey() || !keyExchangeMessage.hasIdentityKey() ||
                  !keyExchangeMessage.hasBaseKeySignature()) {
            return null;
          }
          
          int sequence = keyExchangeMessage.getId() >> 5;
          int flags = keyExchangeMessage.getId() & 0x1f;
          ECPublicKey baseKey = Curve.decodePoint(keyExchangeMessage.getBaseKey().toByteArray(), 0);
          byte[] baseKeySignature = keyExchangeMessage.getBaseKeySignature().toByteArray();
          ECPublicKey ratchetKey = Curve.decodePoint(keyExchangeMessage.getRatchetKey().toByteArray(), 0);
          IdentityKey identityKey = new IdentityKey(keyExchangeMessage.getIdentityKey().toByteArray(), 0);
          
          boolean initial = (flags & 0x01) != 0;
          
          if (!sessionStore.isTrustedIdentity(address, identityKey, null)) {
            if (initial) {
              return new Message.KeyInit(addressString, identityKey.serialize());
            }
            return new Message.KeyResponse(addressString, identityKey.serialize());
          }
          
          if (initial) {
            flags = 0x02;
            SessionRecord sessionRecord = sessionStore.loadSession(address);
            
            if (!Curve.verifySignature(identityKey.getPublicKey(),
                    baseKey.serialize(),
                    baseKeySignature)) {
              return new Message.KeyInit(addressString, identityKey.serialize());
            }
            
            SymmetricSignalProtocolParameters.Builder builder = SymmetricSignalProtocolParameters.newBuilder();
            
            if (!sessionRecord.getSessionState().hasPendingKeyExchange()) {
              builder.setOurIdentityKey(sessionStore.getIdentityKeyPair())
                      .setOurBaseKey(Curve.generateKeyPair())
                      .setOurRatchetKey(Curve.generateKeyPair());
            } else {
              builder.setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())
                      .setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())
                      .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey());
              flags |= 0x04;
            }
            
            builder.setTheirBaseKey(baseKey)
                    .setTheirRatchetKey(ratchetKey)
                    .setTheirIdentityKey(identityKey);
            
            SymmetricSignalProtocolParameters parameters = builder.create();
            
            if (!sessionRecord.isFresh()) { sessionRecord.archiveCurrentState(); }
            
            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters);
            
            return new Message.KeyInit(addressString, true, identityKey.serialize(), flags, sequence, sessionRecord, parameters);
          } else {
            SessionRecord sessionRecord = sessionStore.loadSession(address);
            SessionState sessionState = sessionRecord.getSessionState();
            boolean hasPendingKeyExchange = sessionState.hasPendingKeyExchange();
            
            if (!hasPendingKeyExchange || sessionState.getPendingKeyExchangeSequence() != sequence) {
              return new Message.KeyResponse(addressString, identityKey.serialize());
            }
            
            SymmetricSignalProtocolParameters.Builder builder = SymmetricSignalProtocolParameters.newBuilder();
            
            builder.setOurBaseKey(sessionRecord.getSessionState().getPendingKeyExchangeBaseKey())
                    .setOurRatchetKey(sessionRecord.getSessionState().getPendingKeyExchangeRatchetKey())
                    .setOurIdentityKey(sessionRecord.getSessionState().getPendingKeyExchangeIdentityKey())
                    .setTheirBaseKey(baseKey)
                    .setTheirRatchetKey(ratchetKey)
                    .setTheirIdentityKey(identityKey);
            
            if (!sessionRecord.isFresh()) { sessionRecord.archiveCurrentState(); }
            
            SymmetricSignalProtocolParameters parameters = builder.create();
            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters);
            
            if (!Curve.verifySignature(identityKey.getPublicKey(),
                    baseKey.serialize(),
                    baseKeySignature)) {
              return new Message.KeyResponse(addressString, identityKey.serialize());
            }
            
            return new Message.KeyResponse(addressString, true, identityKey.serialize(), sessionRecord, parameters);
          }
        }
        case "TSM":
        case "TSE": {
          SignalMessage signalMessage = new SignalMessage(decoded);
          SessionCipher sessionCipher = new SessionCipher(sessionStore, address);
          byte[] plaintext;
          try {
            plaintext = sessionCipher.decrypt(signalMessage);
          } catch (InvalidMessageException | DuplicateMessageException | LegacyMessageException | NoSessionException | UntrustedIdentityException e) {
            return getInvalidText(addressString, type);
          }
  
          int messageLength = plaintext.length;
          for (int i = 0; i < plaintext.length; i++) {
            if (plaintext[i] == (byte) 0x00) {
              messageLength = i;
              break;
            }
          }
          
          message = new String(plaintext, 0, messageLength, StandardCharsets.UTF_8);
          if (type.equals("TSE")) {
            return new Message.SessionEnd(addressString, "TERMINATE".equals(message));
          }
          return new Message.Text(addressString, true, message);
        }
        default:
          throw new AssertionError("impossible header: " + type);
      }
    } catch (Exception ex) {
      return getInvalidText(addressString, type);
    }
  }
  
  private static Message getInvalidText(String address, String type) {
    if (type.equals("TSM")) {
      return new Message.Text(address, false, "");
    }
    return new Message.SessionEnd(address, false);
  }
  
  static {
    
    // ugly piece of code to bypass Oracle JRE stupid restriction on key lengths
    // Silence requires a 256-bit key AES cipher, but Oracle will only allow a key length <= 128-bit due to US export laws
    
    // the normal ways to fix this are:
    // a) to stop using Oracle JRE
    // b) to replace two files in the Oracle JRE folder (see http://stackoverflow.com/a/3864276)
    // c) to use a simple 128-bit key instead of a 256-bit one
    // d) to use an external Cipher implementation (like BouncyCastle)
    
    // however, none of these ways are practical, or lightweight enough
    // so we have to manually override the permissions on key lengths using reflection
    
    // ugly reflection hack start (we have to override a private static final field from a package-private class...)
    
    String errorString = "Failed manually overriding key-length permissions. "
            + "Please open an issue at https://github.com/delthas/libsilence-java/issues/ if you see this message. "
            + "Try doing this to fix the problem: http://stackoverflow.com/a/3864276";
    
    int newMaxKeyLength;
    try {
      if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
        Class<?> c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
        Constructor<?> con = c.getDeclaredConstructor();
        con.setAccessible(true);
        Object allPermissionCollection = con.newInstance();
        Field f = c.getDeclaredField("all_allowed");
        f.setAccessible(true);
        f.setBoolean(allPermissionCollection, true);
        
        c = Class.forName("javax.crypto.CryptoPermissions");
        con = c.getDeclaredConstructor();
        con.setAccessible(true);
        Object allPermissions = con.newInstance();
        f = c.getDeclaredField("perms");
        f.setAccessible(true);
        //noinspection unchecked
        ((Map) f.get(allPermissions)).put("*", allPermissionCollection);
        
        c = Class.forName("javax.crypto.JceSecurityManager");
        f = c.getDeclaredField("defaultPolicy");
        f.setAccessible(true);
        Field mf = Field.class.getDeclaredField("modifiers");
        mf.setAccessible(true);
        mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
        // override a final field
        // this field won't be optimized out by the compiler because it is set at run-time
        f.set(null, allPermissions);
        
        newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
      }
    } catch (Exception e) {
      System.err.println(errorString);
      throw new RuntimeException(errorString, e);
    }
    if (newMaxKeyLength < 256) {
      // hack failed
      System.err.println(errorString);
      throw new RuntimeException(errorString);
    }
  }
}
