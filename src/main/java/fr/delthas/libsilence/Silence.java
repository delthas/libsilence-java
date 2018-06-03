package fr.delthas.libsilence;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalProtos;
import org.whispersystems.libsignal.ratchet.*;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Pair;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
  private Object lock = new Object();
  
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
   * The returned String, if present, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * <b>This will automatically accept the KeyInit message and start the secure session so you can send encrypted text messages with {@link #encryptText(String, String)} afterwards.</b>
   * <p>
   * The returned Optional will be empty if the message couldn't be created, which happens if the {@link Message.KeyInit} message couldn't be trusted or if a secure session was already established. To end a secure session, send a session end message with {@link #encryptSessionEnd(String)} or decrypt one.
   * @param keyInit The previously received {@link Message.KeyInit} message to accept.
   * @return An Optional containing the key response message to be sent over the message transfer wire, or empty if the message couldn't be created.
   */
  public Optional<String> encryptKeyResponse(Message.KeyInit keyInit) {
    synchronized (lock) {
      _acceptKeyInit(Objects.requireNonNull(keyInit));
      return Optional.of(_encryptKeyResponse(keyInit));
    }
  }
  
  /**
   * Encrypts some text into a Silence encrypted text message.
   * <p>
   * The returned String, if present, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * The returned Optional will be empty if the message couldn't be encrypted, which happens if no secure session is currently established for this address.
   * @param address The unique identifier for the contact for which the message must be encrypted.
   * @param text The text to encrypt.
   * @return An Optional containing the encrypted text message to be sent over the message transfer wire, or empty if the text couldn't be encrypted.
   */
  public Optional<String> encryptText(String address, String text) {
    Objects.requireNonNull(address);
    Objects.requireNonNull(text);
    synchronized (lock) {
      return Optional.ofNullable(_encryptText(address, text));
    }
  }
  
  /**
   * Encrypts a Silence session end message.
   * <p>
   * The returned String, if present, will be the exact String you will need to send on your underlying message transfer wire (in general, this means sending an SMS with this exact text).
   * <p>
   * <b>This will automatically end the secure session, you won't be able to encrypt or decrypt secure messages for this session after this call.</b> You can however create a new secure session.
   * <p>
   * The returned Optional will be empty if the message couldn't be created, which happens which happens if no secure session is currently established for this address.
   * @param address The unique identifier for the contact for which the message must be encrypted.
   * @return An Optional containing the key response message to be sent over the message transfer wire, or empty if the message couldn't be created.
   */
  public Optional<String> encryptSessionEnd(String address) {
    Objects.requireNonNull(address);
    synchronized (lock) {
      String encrypted = _encryptSessionEnd(address);
      if (encrypted == null) {
        return Optional.empty();
      }
      _endSession(address);
      return Optional.of(encrypted);
    }
  }
  
  /**
   * Decrypts a Silence message.
   * <p>
   * <b>Since you cannot know whether received messages are Silence messages, you can use this endpoint for all incoming messages (this method will return an empty Optional is the meessage is not a Silence message).</b>
   * <p>
   * The text you pass should be the exact String that was sent from the underlying message transfer wire (in general, this means the exact received SMS).
   * <p>
   * The returned Message, if present, will be a valid {@link Message.KeyInit}, {@link Message.KeyResponse}, {@link Message.Text}, or {@link Message.SessionEnd} message corresponding to the text.
   * <p>
   * <b>Some automatic session processing can happen when decrypting a message, and a message should generally be decrypted only once. For example, decrypting a {@link Message.SessionEnd} message will automatically end the secure session.</b>. See the individual Message documentation for details.
   * <p>
   * The returned Optional will be empty if the message was not a valid Silence message or if it was invalid with regard to the secure session (for example, receiving a {@link Message.KeyInit} message when a session was already established).
   * @param address The unique identifier for the contact from which the message was received.
   * @param text The exact message that was received from the underlying message transfer wire.
   * @return An Optional containing the decrypted Silence {@link Message}, or empty if the message was not a valid Silence message or was invalid.
   */
  public Optional<Message> decrypt(String address, String text) {
    Objects.requireNonNull(address);
    Objects.requireNonNull(text);
    synchronized (lock) {
      Optional<String> header = _getHeader(address, text);
      if (!header.isPresent()) {
        return Optional.empty();
      }
      Optional<Message> message = _decrypt(address, header.get(), text);
      if (message.isPresent() && message.get().isValid()) {
        Message m = message.get();
        switch (m.getType()) {
          case KEY_RESPONSE:
            _acceptKeyResponse(m.asKeyResponse());
            break;
          case SESSION_END:
            _endSession(m.getAddress());
            break;
          default:
        }
      }
      return message;
    }
  }
  
  /**
   * Returns the fingerprint of a contact with which a secure session is currently established.
   * <p>
   * To view the fingerprint as a string of hex characters, like in the Silence Android app, simply convert the byte array to a hex representation, for example by using {@link org.whispersystems.libsignal.util.Hex#toString(byte[])}, bundled as a dependency of this library.
   * <p>
   * The returned Optional will be empty if no secure session is currently established with the specified contact.
   * @param address The unique identifier for the contact to get the fingerprint of.
   * @return An Optional containing the fingerprint of the contact, or empty if no secure session with the contact is currently established.
   */
  public final Optional<byte[]> getFingerprint(String address) {
    Objects.requireNonNull(address);
    synchronized (lock) {
      Objects.requireNonNull(address);
      SignalProtocolAddress address_ = new SignalProtocolAddress(address, 1);
      return Optional.ofNullable(sessionStore.loadSession(address_).getSessionState().serialize());
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
      CiphertextMessage ciphertextMessage = null;
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
    MessageDigest md = null;
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
  
  protected final Optional<String> _getHeader(String addressString, String message) {
    if (message.length() <= 4) {
      return Optional.empty();
    }
    String type = null;
    for (String prefixType : MESSAGE_TYPES) {
      String prefix = message.substring(0, 4);
      String messageBody = message.substring(4);
      
      MessageDigest md = null;
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
    return Optional.ofNullable(type);
  }
  
  protected final Optional<Message> _decrypt(String addressString, String type, String message) {
    try {
      SignalProtocolAddress address = new SignalProtocolAddress(addressString, 1);
      
      if (message.length() < 4) {
        return Optional.empty();
      }
      byte[] decoded = decoder.decode(message.substring(4));
      
      byte[] stripped = new byte[decoded.length - 1];
      System.arraycopy(decoded, 1, stripped, 0, decoded.length - 1);
      stripped[0] = decoded[0];
      
      decoded = stripped;
      
      switch (type) {
        case "TSX":
        case "TSP":
          return Optional.empty();
        case "TSK": {
          byte[][] parts = ByteUtil.split(decoded, 1, decoded.length - 1);
          int version = ByteUtil.highBitsToInt(parts[0][0]);
          
          if (version < CiphertextMessage.CURRENT_VERSION) {
            return Optional.empty();
          }
          
          if (version > CiphertextMessage.CURRENT_VERSION) {
            return Optional.empty();
          }
          
          SignalProtos.KeyExchangeMessage keyExchangeMessage = SignalProtos.KeyExchangeMessage.parseFrom(parts[1]);
          
          if (!keyExchangeMessage.hasId() || !keyExchangeMessage.hasBaseKey() ||
                  !keyExchangeMessage.hasRatchetKey() || !keyExchangeMessage.hasIdentityKey() ||
                  !keyExchangeMessage.hasBaseKeySignature()) {
            return Optional.empty();
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
              return Optional.of(new Message.KeyInit(addressString, identityKey.serialize()));
            }
            return Optional.of(new Message.KeyResponse(addressString, identityKey.serialize()));
          }
          
          if (initial) {
            flags = 0X02;
            SessionRecord sessionRecord = sessionStore.loadSession(address);
            
            if (!Curve.verifySignature(identityKey.getPublicKey(),
                    baseKey.serialize(),
                    baseKeySignature)) {
              return Optional.of(new Message.KeyInit(addressString, identityKey.serialize()));
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
            
            return Optional.of(new Message.KeyInit(addressString, true, identityKey.serialize(), flags, sequence, sessionRecord, parameters));
          } else {
            
            SessionRecord sessionRecord = sessionStore.loadSession(address);
            SessionState sessionState = sessionRecord.getSessionState();
            boolean hasPendingKeyExchange = sessionState.hasPendingKeyExchange();
            
            if (!hasPendingKeyExchange || sessionState.getPendingKeyExchangeSequence() != sequence) {
              return Optional.of(new Message.KeyResponse(addressString, identityKey.serialize()));
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
              return Optional.of(new Message.KeyResponse(addressString, identityKey.serialize()));
            }
            
            return Optional.of(new Message.KeyResponse(addressString, true, identityKey.serialize(), sessionRecord, parameters));
          }
        }
        case "TSM":
        case "TSE": {
          byte[][] messageParts = ByteUtil.split(decoded, 1, decoded.length - 1 - 8, 8);
          byte version = messageParts[0][0];
          byte[] messageBytes = messageParts[1];
          
          if (ByteUtil.highBitsToInt(version) <= 1) {
            return getInvalidText(addressString, type);
          }
          
          if (ByteUtil.highBitsToInt(version) > 3) {
            return getInvalidText(addressString, type);
          }
          
          SignalProtos.SignalMessage whisperMessage = null;
          try {
            whisperMessage = SignalProtos.SignalMessage.parseFrom(messageBytes);
          } catch (InvalidProtocolBufferException e) {
            return getInvalidText(addressString, type);
          }
          
          if (!whisperMessage.hasCiphertext() ||
                  !whisperMessage.hasCounter() ||
                  !whisperMessage.hasRatchetKey()) {
            return getInvalidText(addressString, type);
          }
          
          ECPublicKey senderRatchetKey = null;
          try {
            senderRatchetKey = Curve.decodePoint(whisperMessage.getRatchetKey().toByteArray(), 0);
          } catch (InvalidKeyException e) {
            return getInvalidText(addressString, type);
          }
          int messageVersion = ByteUtil.highBitsToInt(version);
          int counter = whisperMessage.getCounter();
          byte[] ciphertext = whisperMessage.getCiphertext().toByteArray();
          byte[] plaintext = null;
          
          if (!sessionStore.containsSession(address)) {
            return getInvalidText(addressString, type);
          }
          
          SessionRecord sessionRecord = sessionStore.loadSession(address);
          
          
          Iterator<SessionState> previousStates = sessionRecord.getPreviousSessionStates().iterator();
          
          {
            SessionState sessionState = new SessionState(sessionRecord.getSessionState());
            
            if (!sessionState.hasSenderChain()) {
              return getInvalidText(addressString, type);
            }
            
            if (messageVersion != sessionState.getSessionVersion()) {
              return getInvalidText(addressString, type);
            }
            
            ChainKey chainKey;
            if (sessionState.hasReceiverChain(senderRatchetKey)) {
              chainKey = sessionState.getReceiverChainKey(senderRatchetKey);
            } else {
              RootKey rootKey = sessionState.getRootKey();
              ECKeyPair ourEphemeral = sessionState.getSenderRatchetKeyPair();
              Pair<RootKey, ChainKey> receiverChain = rootKey.createChain(senderRatchetKey, ourEphemeral);
              ECKeyPair ourNewEphemeral = Curve.generateKeyPair();
              Pair<RootKey, ChainKey> senderChain = receiverChain.first().createChain(senderRatchetKey, ourNewEphemeral);
              
              sessionState.setRootKey(senderChain.first());
              sessionState.addReceiverChain(senderRatchetKey, receiverChain.second());
              sessionState.setPreviousCounter(Math.max(sessionState.getSenderChainKey().getIndex() - 1, 0));
              sessionState.setSenderChain(ourNewEphemeral, senderChain.second());
              
              chainKey = receiverChain.second();
            }
            
            MessageKeys messageKeys;
            if (chainKey.getIndex() > counter) {
              if (sessionState.hasMessageKeys(senderRatchetKey, counter)) {
                messageKeys = sessionState.removeMessageKeys(senderRatchetKey, counter);
              } else {
                return getInvalidText(addressString, type);
              }
            } else {
              if (counter - chainKey.getIndex() > 2000) {
                return getInvalidText(addressString, type);
              }
              while (chainKey.getIndex() < counter) {
                messageKeys = chainKey.getMessageKeys();
                sessionState.setMessageKeys(senderRatchetKey, messageKeys);
                chainKey = chainKey.getNextChainKey();
              }
              sessionState.setReceiverChainKey(senderRatchetKey, chainKey.getNextChainKey());
              messageKeys = chainKey.getMessageKeys();
            }
            
            byte[][] parts = ByteUtil.split(decoded, decoded.length - 8, 8);
            
            Mac macInstance = null;
            try {
              macInstance = Mac.getInstance("HmacSHA256");
            } catch (NoSuchAlgorithmException e) {
              throw new AssertionError(e);
            }
            macInstance.init(messageKeys.getMacKey());
            
            if (messageVersion >= 3) {
              macInstance.update(sessionState.getRemoteIdentityKey().getPublicKey().serialize());
              macInstance.update(sessionState.getLocalIdentityKey().getPublicKey().serialize());
            }
            
            byte[] fullMac = macInstance.doFinal(parts[0]);
            byte[] ourMac = ByteUtil.trim(fullMac, 8);
            
            byte[] theirMac = parts[1];
            
            if (!MessageDigest.isEqual(ourMac, theirMac)) {
              return getInvalidText(addressString, type);
            }
            
            Cipher cipher;
            
            if (version >= 3) {
              cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
              cipher.init(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
            } else {
              cipher = Cipher.getInstance("AES/CTR/NoPadding");
              byte[] ivBytes = new byte[16];
              ByteUtil.intToByteArray(ivBytes, 0, counter);
              IvParameterSpec iv = new IvParameterSpec(ivBytes);
              cipher.init(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), iv);
            }
            plaintext = cipher.doFinal(ciphertext);
            
            sessionState.clearUnacknowledgedPreKeyMessage();
            sessionRecord.setState(sessionState);
          }
          
          while (plaintext == null && previousStates.hasNext()) {
            {
              SessionState promotedState = new SessionState(previousStates.next());
              
              if (!promotedState.hasSenderChain()) {
                return getInvalidText(addressString, type);
              }
              
              if (messageVersion != promotedState.getSessionVersion()) {
                return getInvalidText(addressString, type);
              }
              
              ChainKey chainKey;
              if (promotedState.hasReceiverChain(senderRatchetKey)) {
                chainKey = promotedState.getReceiverChainKey(senderRatchetKey);
              } else {
                RootKey rootKey = promotedState.getRootKey();
                ECKeyPair ourEphemeral = promotedState.getSenderRatchetKeyPair();
                Pair<RootKey, ChainKey> receiverChain = rootKey.createChain(senderRatchetKey, ourEphemeral);
                ECKeyPair ourNewEphemeral = Curve.generateKeyPair();
                Pair<RootKey, ChainKey> senderChain = receiverChain.first().createChain(senderRatchetKey, ourNewEphemeral);
                
                promotedState.setRootKey(senderChain.first());
                promotedState.addReceiverChain(senderRatchetKey, receiverChain.second());
                promotedState.setPreviousCounter(Math.max(promotedState.getSenderChainKey().getIndex() - 1, 0));
                promotedState.setSenderChain(ourNewEphemeral, senderChain.second());
                
                chainKey = receiverChain.second();
              }
              
              MessageKeys messageKeys;
              if (chainKey.getIndex() > counter) {
                if (promotedState.hasMessageKeys(senderRatchetKey, counter)) {
                  messageKeys = promotedState.removeMessageKeys(senderRatchetKey, counter);
                } else {
                  return getInvalidText(addressString, type);
                }
              } else {
                if (counter - chainKey.getIndex() > 2000) {
                  return getInvalidText(addressString, type);
                }
                while (chainKey.getIndex() < counter) {
                  messageKeys = chainKey.getMessageKeys();
                  promotedState.setMessageKeys(senderRatchetKey, messageKeys);
                  chainKey = chainKey.getNextChainKey();
                }
                promotedState.setReceiverChainKey(senderRatchetKey, chainKey.getNextChainKey());
                messageKeys = chainKey.getMessageKeys();
              }
              
              byte[][] parts = ByteUtil.split(decoded, decoded.length - 8, 8);
              
              Mac macInstance = Mac.getInstance("HmacSHA256");
              macInstance.init(messageKeys.getMacKey());
              
              if (messageVersion >= 3) {
                macInstance.update(promotedState.getRemoteIdentityKey().getPublicKey().serialize());
                macInstance.update(promotedState.getLocalIdentityKey().getPublicKey().serialize());
              }
              
              byte[] fullMac = macInstance.doFinal(parts[0]);
              byte[] ourMac = ByteUtil.trim(fullMac, 8);
              
              byte[] theirMac = parts[1];
              
              if (!MessageDigest.isEqual(ourMac, theirMac)) {
                return getInvalidText(addressString, type);
              }
              
              Cipher cipher;
              
              if (version >= 3) {
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
              } else {
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                byte[] ivBytes = new byte[16];
                ByteUtil.intToByteArray(ivBytes, 0, counter);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                cipher.init(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), iv);
              }
              plaintext = cipher.doFinal(ciphertext);
              
              promotedState.clearUnacknowledgedPreKeyMessage();
              
              previousStates.remove();
              sessionRecord.promoteState(promotedState);
            }
          }
          
          if (plaintext == null) {
            return getInvalidText(addressString, type);
          }
          
          sessionStore.storeSession(address, sessionRecord);
          
          int paddingBeginsIndex = 0;
          for (int i = 1; i < plaintext.length; i++) {
            if (plaintext[i] == (byte) 0x00) {
              paddingBeginsIndex = i;
              break;
            }
          }
          if (paddingBeginsIndex != 0) {
            byte[] messagePaddingBytes = new byte[paddingBeginsIndex];
            System.arraycopy(plaintext, 0, messagePaddingBytes, 0, messagePaddingBytes.length);
            plaintext = messagePaddingBytes;
          }
          
          message = new String(plaintext, StandardCharsets.UTF_8);
          if (type.equals("TSE")) {
            return Optional.of(new Message.SessionEnd(addressString, "TERMINATE".equals(message)));
          }
          return Optional.of(new Message.Text(addressString, true, message));
        }
        default:
          throw new AssertionError("impossible header: " + type);
      }
    } catch (Exception ex) {
      return getInvalidText(addressString, type);
    }
  }
  
  private static Optional<Message> getInvalidText(String address, String type) {
    if (type.equals("TSM")) {
      return Optional.of(new Message.Text(address, false, ""));
    }
    return Optional.of(new Message.SessionEnd(address, false));
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
