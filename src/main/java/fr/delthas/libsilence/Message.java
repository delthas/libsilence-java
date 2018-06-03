package fr.delthas.libsilence;

import org.whispersystems.libsignal.ratchet.SymmetricSignalProtocolParameters;
import org.whispersystems.libsignal.state.SessionRecord;

/**
 * A received Silence message. <b>For general message information, see <a href="https://github.com/delthas/libsilence-java">the library README</a>.</b>
 * <p>
 * A Message can be either a {@link KeyInit}, a {@link KeyResponse}, a {@link Text}, or a {@link SessionEnd} message. The {@code isXXX} and {@code asXXX} are convenience methods to check the concrete class of the Message and cast to it. You can also switch on the Message {@link #getType()}.
 * <p>
 * A Message can be valid or invalid, where invalid means it had an invalid internal format or data, or that the message was not trusted or expected with regard to the current secure session. By default (that is, if you don't extend the {@link Silence} class to add custom message processing), only the valid messages will be returned, so {@link #isValid()} will <b>always be true</b>.
 */
@SuppressWarnings("AbstractClassWithoutAbstractMethods")
public abstract class Message {
  /**
   * The type of a {@link Message}, to be used in type switches with {@link #getType()}.
   */
  public enum Type {
    /**
     * The type of a {@link Text} message.
     */
    TEXT,
    /**
     * The type of a {@link KeyInit} message.
     */
    KEY_INIT,
    /**
     * The type of a {@link KeyResponse} message.
     */
    KEY_RESPONSE,
    /**
     * The type of a {@link SessionEnd} message.
     */
    SESSION_END,
  }
  
  private String address;
  private boolean valid;
  
  // package-private because the user shouldn't create new subclasses
  Message(String address, boolean valid) {
    this.address = address;
    this.valid = valid;
  }
  
  /**
   * Returns the type of this {@link Message} as an enum for simple type switches.
   * @return The type of this {@link Message}.
   */
  public Type getType() {
    if (this instanceof Text) {
      return Type.TEXT;
    }
    if (this instanceof KeyInit) {
      return Type.KEY_INIT;
    }
    if (this instanceof KeyResponse) {
      return Type.KEY_RESPONSE;
    }
    if (this instanceof SessionEnd) {
      return Type.SESSION_END;
    }
    throw new AssertionError("impossible message type " + getClass().getSimpleName());
  }
  
  /**
   * Convenience method for {@code (Text)message}.
   * @return This Message cast as a {@link Text} message.
   */
  public Text asText() {
    if (this instanceof Text) {
      return (Text) this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() + ", not a Text");
  }
  
  /**
   * Convenience method for {@code (KeyInit)message}.
   * @return This Message cast as a {@link KeyInit} message.
   */
  public KeyInit asKeyInit() {
    if (this instanceof KeyInit) {
      return (KeyInit) this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() + ", not a KeyInit");
  }
  
  /**
   * Convenience method for {@code (KeyResponse)message}.
   * @return This Message cast as a {@link KeyResponse} message.
   */
  public KeyResponse asKeyResponse() {
    if (this instanceof KeyResponse) {
      return (KeyResponse) this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() + ", not a KeyResponse");
  }
  
  /**
   * Convenience method for {@code (SessionEnd)message}.
   * @return This Message cast as a {@link SessionEnd} message.
   */
  public SessionEnd asSessionEnd() {
    if (this instanceof SessionEnd) {
      return (SessionEnd) this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() + ", not a SessionEnd");
  }
  
  /**
   * Convenience method for {@code message instanceof Message.Text}.
   * @return true if this message is a {@link Text} message.
   */
  public boolean isText() {
    if (this instanceof Text) {
      return true;
    }
    return false;
  }
  
  /**
   * Convenience method for {@code message instanceof Message.KeyInit}.
   * @return true if this message is a {@link KeyInit} message.
   */
  public boolean isKeyInit() {
    if (this instanceof KeyInit) {
      return true;
    }
    return false;
  }
  
  /**
   * Convenience method for {@code message instanceof Message.KeyResponse}.
   * @return true if this message is a {@link KeyResponse} message.
   */
  public boolean isKeyResponse() {
    if (this instanceof KeyResponse) {
      return true;
    }
    return false;
  }
  
  /**
   * Convenience method for {@code message instanceof Message.SessionEnd}.
   * @return true if this message is a {@link SessionEnd} message.
   */
  public boolean isSessionEnd() {
    if (this instanceof SessionEnd) {
      return true;
    }
    return false;
  }
  
  /**
   * Returns the address from which this message was received (which is the {@code address} parameter you put when calling {@link Silence#decrypt(String, String)}.
   * @return The address from which this message was received.
   */
  public String getAddress() {
    return address;
  }
  
  /**
   * Returns whether the message was valid when received. An invalid means it had an invalid internal format or data, or that the message was not trusted or expected with regard to the current secure session.
   * @return true if the message was valid.
   */
  public boolean isValid() {
    return valid;
  }
  
  /**
   * An encrypted Session message containing text (corresponds to the TSM header).
   * <p>
   * No automatic secure session processing is done when decrypting this message besides an internal state update.
   *
   * @see Message.Type#TEXT
   * @see Silence#encryptText(String, String)
   */
  public static final class Text extends Message {
    private String text;
    
    Text(String address, boolean valid, String text) {
      super(address, valid);
      this.text = text;
    }
  
    /**
     * Returns the text of this encrypted Session text message (as sent by the contact before they called {@link Silence#encryptText(String, String)}).
     * @return The text of this encrypted Session text message.
     */
    public String getText() {
      return text;
    }
  }
  
  /**
   * A Silence secure session begin/key initialization message (corresponds to the TSK header).
   * <p>
   * No automatic secure session processing is done when decrypting this message besides an internal state update. To accept this key and start a secure session, encrypt a key response message with {@link Silence#encryptKeyResponse(KeyInit)} (and send it).
   *
   * @see Message.Type#KEY_INIT
   * @see Silence#encryptKeyInit(String)
   * @see Silence#encryptKeyResponse(KeyInit)
   */
  public static final class KeyInit extends Message {
    private byte[] fingerprint;
    private int flags;
    private int sequence;
    private SessionRecord sessionRecord;
    private SymmetricSignalProtocolParameters parameters;
    
    KeyInit(String address, boolean valid, byte[] fingerprint, int flags, int sequence, SessionRecord sessionRecord, SymmetricSignalProtocolParameters parameters) {
      super(address, valid);
      this.fingerprint = fingerprint;
      this.flags = flags;
      this.sequence = sequence;
      this.sessionRecord = sessionRecord;
      this.parameters = parameters;
    }
    
    KeyInit(String address, byte[] fingerprint) {
      this(address, false, fingerprint, 0, 0, null, null);
    }
  
    /**
     * Returns the fingerprint of the contact as sent in this key initialization message.
     * <p>
     * If the message is valid, then this returns exactly the same as {@link Silence#getFingerprint(String)} for this address just after you encrypt a {@link KeyResponse} for this message with {@link Silence#encryptKeyResponse(KeyInit)}.
     * @return The fingerprint of the contact as sent in this key initialization message.
     */
    public byte[] getFingerprint() {
      return fingerprint;
    }
    
    SessionRecord getSessionRecord() {
      return sessionRecord;
    }
    
    SymmetricSignalProtocolParameters getParameters() {
      return parameters;
    }
    
    int getFlags() {
      return flags;
    }
    
    int getSequence() {
      return sequence;
    }
  }
  
  /**
   * A Silence key response message (corresponds to the TSK header).
   * <p>
   * When receiving a valid key response message (for the latest previously valid {@link KeyInit} message received), it will automatically be accepted during the {@link Silence#decrypt(String, String)} call and will start a new Silence secure session.
   *
   * @see Message.Type#KEY_RESPONSE
   * @see Silence#encryptKeyResponse(KeyInit)
   */
  public static final class KeyResponse extends Message {
    private byte[] fingerprint;
    private SessionRecord sessionRecord;
    private SymmetricSignalProtocolParameters parameters;
    
    KeyResponse(String address, boolean valid, byte[] fingerprint, SessionRecord sessionRecord, SymmetricSignalProtocolParameters parameters) {
      super(address, valid);
      this.fingerprint = fingerprint;
      this.sessionRecord = sessionRecord;
      this.parameters = parameters;
    }
    
    KeyResponse(String address, byte[] fingerprint) {
      this(address, false, fingerprint, null, null);
    }
  
    /**
     * Returns the fingerprint of the contact as sent in this key response message.
     * <p>
     * If the message is valid, then this returns exactly the same as {@link Silence#getFingerprint(String)} for this address just after you {@link Silence#decrypt(String, String)} this message.
     * @return The fingerprint of the contact as sent in this key initialization message.
     */
    public byte[] getFingerprint() {
      return fingerprint;
    }
    
    SessionRecord getSessionRecord() {
      return sessionRecord;
    }
    
    SymmetricSignalProtocolParameters getParameters() {
      return parameters;
    }
  }
  
  /**
   * A Silence session end message (corresponds to the TSE header).
   * <p>
   * When receiving a valid session end message, the current secure session will automatically be ended during the call to {@link Silence#decrypt(String, String)}. You can establish a new secure session afterwards.
   *
   * @see Message.Type#SESSION_END
   * @see Silence#encryptSessionEnd(String)
   */
  public static final class SessionEnd extends Message {
    SessionEnd(String address, boolean valid) {
      super(address, valid);
    }
  }
}
