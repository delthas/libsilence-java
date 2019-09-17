# libsilence-java

## Introduction

libsilence-java is a lightweight API for the Silence protocol (previously known as SMSSecure, forked from TextSecure, now Signal).

This API lets you:
- Start and end secure sessions with other Silence users (using this library or the Silence Android app)
- Send and receive secure Silence text messages
- Review your and others' identity fingerprints
- ***New:*** Send and receive secure Silence multimedia messages

*This library does not currently support Silence PreKeys.*

## Install

libsilence-java requires Java >= 8 to run. You can get this library using Maven by adding this to your ```pom.xml```:

```xml
 <dependencies>
    <dependency>       
           <groupId>fr.delthas</groupId>
           <artifactId>libsilence-java</artifactId>
           <version>0.2.0</version>
    </dependency>
</dependencies>
```

## Quick overview of the Silence protocol

The Silence protocol is currently used over SMS, where each Silence message corresponds to one (possibly concatenated) SMS, and MMS. The encrypted messages created and decrypted by the library could be used over any underlying message transfer medium.

Silence uses asymmetric encryption with one set of public and private keys for each contact (though an identity fingerprint is shared for all these keys). To start a secure session with a contact, you must send a `KeyInit` message, to which your contact must respond with a `KeyResponse` message. The secure session is then established and you and your contact can send encrypted `Text` messages to each other. When you want to end a secure session, you must send a `SessionEnd` message.

**The Silence messages are:**

| Name | `libsilence-java` methods and classes | Description |
| :---: |     :---      |         :--- |
| **TSK**   | `encryptKeyInit()` `Message.KeyInit`     | Message sent for starting a secure session, contains a generated public key |
| **TSK**   | `encryptKeyResponse()` `Message.KeyResponse`     | Message sent in response to a `KeyInit` message, contains a generated public key  |
| **TSM**     | `encryptText()` `Message.Text`       | Encrypted text message sent when a secure session is established     |
| **TSE**     | `encryptSessionEnd()` `Message.SessionEnd`       | Message sent for ending a secure session (you must not respond to this message)      |

In addition to these text messages (sent as SMS), Silence supports sending and receiving encrypted multimedia messages (sent as MMS). These messages do not carry any session key init/response/end meaning and can only be used after a session is established.

## Quick example

All calls are made through a `Silence` object, which should be saved and loaded every time it is used, since it stores state about the secure sessions (like public and private keys).

The `Message` classes represent incoming encrypted text messages.

`libsilence-java` needs to store state for each session, so you must provide a String `address` for all `encrypt*` and `decrypt` calls, so that Silence knows which session the message corresponds to. In the case of the Silence Android app, the addresses are always phone numbers, but you could use whatever identifier you want. It will only be used as a (case-sensitive) hashmap key. 


Let's walk through a very basic example to discover the basic endpoints of the library.
```java
// Initialiaze a fresh new Silence state
Silence silence = new Silence();

String address = "+15141201245";
// Here the address is a phone number but it could be anything (see above)

// Encrypt a KeyInit message to start a secure session
String keyInit = silence.encryptKeyInit(address);

// Send the message over a message transfer wire to your contact
// (in the case of the Silence app, this would simply send this exact String as a SMS)
send(keyInit);


// Receive the response message from your contact over a message transfer wire
// (in the case of the Silence app, this would receive this exact String from a SMS)
String response = receive();


// Parse the incoming message
Message message = silence.decrypt(address, response);
// The Message will be null if the message wasn't a Silence protocol message
// or if it was invalid
if(message == null) {
  // Handle this exceptional case
  return;
}

// The Message can be a Message.KeyInit, a Message.KeyResponse, a Message.Text,
// or a Message.SessionEnd. Here, it should be a KeyResponse message
if(!message.isKeyResponse()) {
  // Handle this exceptional case
  return;
}

Message.KeyResponse keyResponse = message.asKeyResponse();
// By default the key response is automatically accepted and stored,
// so we don't have to anything about this message
// For this example purpose, let's print its fingerprint
byte[] fingerprint = keyResponse.getFingerprint();
String hexFingerprint = Hex.toString(fingerprint);
System.out.println(hexFingerprint);

// Now that the session is established, let's send a secure text message
String text = "Very secure text message!!";

String encryptedText = silence.encryptText(address, text); 
// The String will be null if the message couldn't be encrypted because no secure
// session is currently established. In our example case, this wouldn't happen
if(encryptedText == null) {
  // Handle this exceptional case
  return;
}

// Send the message over a message transfer wire to your contact
// (in the case of the Silence app, this would simply send this exact String as a SMS)
send(encryptedText);


// Let's create a hypothetical loop that would print all received encrypted messages
// until the session ends
outer: while(true) {
  String encrypted = receive();
  message = silence.decrypt(address, encrypted);
  // Ignore invalid messages
  if(message == null) {
    continue;
  }
  
  // You can use a switch rather than if/else conditions on .isXXX()
  switch(message.getType()) {
    case TEXT:
      // The encrypted message is a text message
      Message.Text receivedText = message.asText();
      // getText() returns its decrypted text
      System.out.println(receivedText.getText());
      break;
    case SESSION_END:
      // Your contact sent a session end message, the session has ended automatically
      // No need to send any message back or do any processing
      break outer;
    default:
      // Ignore other message types for this example
      break;
  }
}

// The session has ended. We could start a new one by sending a
// KeyInit message or waiting to receive one


// Let's store the state before we exit. The state contains public and private keys
// for all sessions, and other session internal data. The state must be saved even
// when if no new session was created since last run.
try(OutputStream out = Files.newOutputStream(Paths.get("silence.dat"))) {
  silence.saveTo(out);
} catch(IOException ex) {
  // Called if an underlying IOException happened when writing to the stream
  // Handle the exceptional case
  return;
}

// ...

// Next time you start Silence, load it from the saved state instead
// of creating a fresh state
try(InputStream in = Files.newInputStream(Paths.get("silence.dat"))) {
  silence = new Silence(in);
} catch(IOException ex) {
  // Called if an underlying IOException happened when reading from the stream,
  // or if the data was invalid. Handle the exceptional case
  return;
}

// Let's send a secure multimedia message to a peer (without considering MMS compatibility for now).
byte[] dataSend = /* ... */;

MultimediaMessage encryptedMessage = silence.encryptMultimedia(address, dataSend);
// The MultimediaMessage will be null if the message couldn't be encrypted because no secure
// session is currently established. In our example case, this wouldn't happen
if(encryptedMessage == null) {
  // Handle this exceptional case
  return;
}

// Send the message over a multimedia message transfer wire to your contact
sendMultimedia(encryptedMessage);


// Receive the response message from your contact over a multimedia message transfer wire
// A MultimediaMessage is simply a text subject and a text (encrypted, encoded) body
MultimediaMessage response = receiveMultimedia();

// Parse the incoming message
byte[] dataReceived = silence.decryptMultimedia(address, response);
// The byte array will be null if the message wasn't a Silence protocol message
// or if it was invalid
if(dataReceived == null) {
  // Handle this exceptional case
  return;
}
// dataReceived is equal to dataSend


// ...

// Now let's consider MMS. Using MMS is harder because the encrypted subject and data from
// the MultimediaMessage correspond to specific parts of the MMS PDU that wraps it.
// libsilence-java deliberately does not depend on any specific MMS library because
// there is no standard MMS library on Android.

// To send an encrypted MMS, you must first create an unencrypted MMS PDU and serialize it to a byte array.
// On Android this means using e.g. PduBody, PduPart, and PduComposer.make()
byte[] pduData = new PduComposer(context, pdu).make();

MultimediaMessage encryptedMessage = silence.encryptMultimedia(address, pduData);
if(encryptedMessage == null) {
  return;
}

// You must then construct a new MMS PDU with specific fields taken from the returned MultimediaMessage:
// - encryptedMessage.getSubject() must be set as the MMS PDU subject header
// - encryptedMessage.getData() must be set as the MMS PDU body part body of
//   a part whose content type must be "text/plain"

// Not trivial!
sendMms(makePduFromMultimediaMessage(encryptedMessage));

// Now let's receive an MMS. First, you'll receive an encrypted MMS PDU.
// You must extract the subject and body values from the MMS PDU as follows:
// - subject is the MMS PDU subject header
// - body is the data of the first MMS PDU body part whose content type is "text/plain"

// Not trivial!
MultimediaMessage received = makeMultimediaMessageFromPdu(pdu);

byte[] dataReceived_ = silence.decryptMultimedia(address, received);
if(dataReceived == null) {
  return;
}
// The decrypted data is equal to pduData and is the byte representation of an unencrypted MMS PDU.

// You must then decode the MMS PDU from this byte array to access the original MMS PDU body parts.
// On Android this means using e.g. PduBody, PduPart, and PduParser.parse()
MultimediaMessagePdu message = PduParser(data, true).parse()
```

## Documentation

The javadoc for the API is located at: http://www.javadoc.io/doc/fr.delthas/libsilence-java/

This library is synchronized so you can call all methods from multiple threads.

For advanced usage of the library, you can extend the Silence class to be able to directly use the lower-level methods used internally by the public methods. These protected methods all start with `_`. See the source code for an example of how these methods are currently used.

## Building

Simply run ```mvn install```.

## Misceallenous

### Tech

libsilence-java uses a very small set of libraries in order to run:

* [signal-protocol-java](https://github.com/signalapp/libsignal-protocol-java) - Cryptographic support for the Silence protocol
* [JUnit](http://junit.org) - The famous testing library

### License

MIT
