package fr.delthas.libsilence;

import java.util.Objects;

/**
 * An encrypted multimedia message (Silence encrypted MMS). <b>For general message information, see <a href="https://github.com/delthas/libsilence-java">the library README</a>.</b>
 * <p>
 * A MultimediaMessage cannot carry any key init, response, or session end semantics, it can only be used as an encrypted message. Using multimedia message is more efficient for both encrypted message size and processing speed than using {@link Silence#encryptText(String, String)}.
 * <p>
 * If a MultimediaMessage was received from an actual MMS, or is to be sent as an actual MMS, it must be used in a specific way to be compatible with peers using Silence (see {@link #getSubject()}, {@link #getData()}. Otherwise, its subject and data fields have no specific meaning.
 * <p>
 * A multimedia message can be decrypted with {@link Silence#decryptMultimedia(String, MultimediaMessage)}, or encrypted from plain data with {@link Silence#encryptMultimedia(String, byte[])}.
 */
public final class MultimediaMessage {
  private final String subject;
  private final String data;
  
  /**
   * Creates a new multimedia message from an encrypted subject and data. In the case of an MMS, {@code subject} and {@code data} are specific values to get from the MMD PDU (see the documentation of {@link #getSubject()} and {@link #getData()}.
   * @param subject The subject of the multimedia message.
   * @param data The encrypted data of the multimedia message.
   * @see #getSubject()
   * @see #getData()
   * @see Silence#encryptMultimedia(String, byte[])
   */
  public MultimediaMessage(String subject, String data) {
    Objects.requireNonNull(subject);
    Objects.requireNonNull(data);
    this.subject = subject;
    this.data = data;
  }
  
  /**
   * Returns the subject of the multimedia message. In the case of an MMS, this is the exact MMS PDU subject header value, as returned by e.g. {@code MultimediaMessagePdu.getSubject().getString()} of the Android internal MMS library).
   * @return The subject of this multimedia message.
   */
  public String getSubject() {
    return subject;
  }
  
  /**
   * Returns the encrypted data of the multimedia message. In the case of an MMS, this is the exact first MMS PDU body part value whose content type is {@code text/plain}.
   * @return The encrypted data of this multimedia message.
   */
  public String getData() {
    return data;
  }
  
  @Override
  public boolean equals(Object o) {
    if (this == o) { return true; }
    if (o == null || getClass() != o.getClass()) { return false; }
    MultimediaMessage multimediaMessage = (MultimediaMessage) o;
    return subject.equals(multimediaMessage.subject) &&
            data.equals(multimediaMessage.data);
  }
  
  @Override
  public int hashCode() {
    return Objects.hash(subject, data);
  }
}
