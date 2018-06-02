package fr.delthas.libsilence;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

class SerializableSignalProtocolStore implements SignalProtocolStore {
  private Map<SignalProtocolAddress, byte[]> sessions = new HashMap<>();
  private final Map<SignalProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();
  private final IdentityKeyPair identityKeyPair;
  private final int localRegistrationId;
  
  public SerializableSignalProtocolStore(InputStream in) throws IOException {
    if (in == null) {
      identityKeyPair = KeyHelper.generateIdentityKeyPair();
      localRegistrationId = KeyHelper.generateRegistrationId(false);
      return;
    }
    try (DataInputStream dis = new DataInputStream(in)) {
      int size = dis.readInt();
      for (int i = 0; i < size; ++i) {
        String keyNumber = dis.readUTF();
        int keyId = dis.readInt();
        byte[] value = new byte[dis.readInt()];
        dis.readFully(value);
        sessions.put(new SignalProtocolAddress(keyNumber, keyId), value);
      }
  
      size = dis.readInt();
      for (int i = 0; i < size; ++i) {
        String keyNumber = dis.readUTF();
        int keyId = dis.readInt();
        byte[] value = new byte[dis.readInt()];
        dis.readFully(value);
        trustedKeys.put(new SignalProtocolAddress(keyNumber, keyId), new IdentityKey(value, 0));
      }
  
      byte[] value = new byte[dis.readInt()];
      dis.readFully(value);
      identityKeyPair = new IdentityKeyPair(value);
      
      localRegistrationId = dis.readInt();
    } catch(IOException ex) {
      throw ex;
    } catch(Exception ex) {
      throw new IOException("invalid input data", ex);
    }
  }
  
  public void save(OutputStream out) throws IOException {
    try(DataOutputStream dos = new DataOutputStream(out)) {
      dos.writeInt(sessions.size());
      for(Map.Entry<SignalProtocolAddress, byte[]> entry : sessions.entrySet()) {
        dos.writeUTF(entry.getKey().getName());
        dos.writeInt(entry.getKey().getDeviceId());
        dos.writeInt(entry.getValue().length);
        dos.write(entry.getValue());
      }
  
      dos.writeInt(trustedKeys.size());
      for(Map.Entry<SignalProtocolAddress, IdentityKey> entry : trustedKeys.entrySet()) {
        dos.writeUTF(entry.getKey().getName());
        dos.writeInt(entry.getKey().getDeviceId());
        byte[] data = entry.getValue().serialize();
        dos.writeInt(data.length);
        dos.write(data);
      }
  
      byte[] data = identityKeyPair.serialize();
      dos.writeInt(data.length);
      dos.write(data);
  
      dos.writeInt(localRegistrationId);
    }
  }
  
  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }
  
  @Override
  public int getLocalRegistrationId() {
    return localRegistrationId;
  }
  
  @Override
  public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    IdentityKey existing = trustedKeys.get(address);
    
    if (!identityKey.equals(existing)) {
      trustedKeys.put(address, identityKey);
      return true;
    } else {
      return false;
    }
  }
  
  @Override
  public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
    IdentityKey trusted = trustedKeys.get(address);
    return (trusted == null || trusted.equals(identityKey));
  }
  
  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public boolean containsPreKey(int preKeyId) {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public void removePreKey(int preKeyId) {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public SessionRecord loadSession(SignalProtocolAddress address) {
    try {
      if (containsSession(address)) {
        return new SessionRecord(sessions.get(address));
      } else {
        return new SessionRecord();
      }
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
  
  @Override
  public List<Integer> getSubDeviceSessions(String name) {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public void storeSession(SignalProtocolAddress address, SessionRecord record) {
    sessions.put(address, record.serialize());
  }
  
  @Override
  public boolean containsSession(SignalProtocolAddress address) {
    return sessions.containsKey(address);
  }
  
  @Override
  public void deleteSession(SignalProtocolAddress address) {
    sessions.remove(address);
  }
  
  @Override
  public void deleteAllSessions(String name) {
    for (SignalProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name)) {
        sessions.remove(key);
      }
    }
  }
  
  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public List<SignedPreKeyRecord> loadSignedPreKeys() {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public boolean containsSignedPreKey(int signedPreKeyId) {
    throw new AssertionError("should never be called");
  }
  
  @Override
  public void removeSignedPreKey(int signedPreKeyId) {
    throw new AssertionError("should never be called");
  }
}
