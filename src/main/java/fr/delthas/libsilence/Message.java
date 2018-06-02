package fr.delthas.libsilence;

import org.whispersystems.libsignal.ratchet.SymmetricSignalProtocolParameters;
import org.whispersystems.libsignal.state.SessionRecord;

@SuppressWarnings("AbstractClassWithoutAbstractMethods")
public abstract class Message {
  
  public enum Type {
    TEXT,
    KEY_INIT,
    KEY_REPLY,
    SESSION_END,
  }
  
  private String address;
  private boolean valid;
  
  // package-private because the user shouldn't create new subclasses
  Message(String address, boolean valid) {
    this.address = address;
    this.valid = valid;
  }
  
  public Type getType() {
    if(this instanceof Text) {
      return Type.TEXT;
    }
    if(this instanceof KeyInit) {
      return Type.KEY_INIT;
    }
    if(this instanceof KeyResponse) {
      return Type.KEY_REPLY;
    }
    if(this instanceof SessionEnd) {
      return Type.SESSION_END;
    }
    throw new AssertionError("impossible message type " + getClass().getSimpleName());
  }
  
  public Text asText() {
    if(this instanceof Text) {
      return (Text)this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() +", not a Text");
  }
  
  public KeyInit asKeyInit() {
    if(this instanceof KeyInit) {
      return (KeyInit)this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() +", not a KeyInit");
  }
  
  public KeyResponse asKeyResponse() {
    if(this instanceof KeyResponse) {
      return (KeyResponse)this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() +", not a KeyResponse");
  }
  
  public SessionEnd asSessionEnd() {
    if(this instanceof SessionEnd) {
      return (SessionEnd)this;
    }
    throw new IllegalArgumentException("this message is a " + getClass().getSimpleName() +", not a SessionEnd");
  }
  
  public boolean isText() {
    if(this instanceof Text) {
      return true;
    }
    return false;
  }
  
  public boolean isKeyInit() {
    if(this instanceof KeyInit) {
      return true;
    }
    return false;
  }
  
  public boolean isKeyResponse() {
    if(this instanceof KeyResponse) {
      return true;
    }
    return false;
  }
  
  public boolean isSessionEnd() {
    if(this instanceof SessionEnd) {
      return true;
    }
    return false;
  }
  
  public String getAddress() {
    return address;
  }
  
  public boolean isValid() {
    return valid;
  }
  
  public static final class Text extends Message {
    private String text;
  
    Text(String address, boolean valid, String text) {
      super(address, valid);
      this.text = text;
    }
  
    public String getText() {
      return text;
    }
  }
  
  public static final class KeyInit extends Message {
    private byte[] fingerprint;
    private int flags;
    private int sequence;
    private SessionRecord sessionRecord;
    private SymmetricSignalProtocolParameters parameters;
  
    public KeyInit(String address, boolean valid, byte[] fingerprint, int flags, int sequence, SessionRecord sessionRecord, SymmetricSignalProtocolParameters parameters) {
      super(address, valid);
      this.fingerprint = fingerprint;
      this.flags = flags;
      this.sequence = sequence;
      this.sessionRecord = sessionRecord;
      this.parameters = parameters;
    }
  
    public KeyInit(String address, byte[] fingerprint) {
      this(address, false, fingerprint, 0, 0, null, null);
    }
  
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
  
  public static final class KeyResponse extends Message {
    private byte[] fingerprint;
    private SessionRecord sessionRecord;
    private SymmetricSignalProtocolParameters parameters;
  
    public KeyResponse(String address, boolean valid, byte[] fingerprint, SessionRecord sessionRecord, SymmetricSignalProtocolParameters parameters) {
      super(address, valid);
      this.fingerprint = fingerprint;
      this.sessionRecord = sessionRecord;
      this.parameters = parameters;
    }
  
    public KeyResponse(String address, byte[] fingerprint) {
      this(address, false, fingerprint, null, null);
    }
  
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
  
  public static final class SessionEnd extends Message {
    SessionEnd(String address, boolean valid) {
      super(address, valid);
    }
  }
  
}
