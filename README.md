# libsilence-java

## Introduction

libsilence-java is a lightweight API for the Silence protocol (previously known as SMSSecure, forked from TextSecure, now Signal).

This API lets you:
- Start and end secure sessions with other Silence users (using this library or the Silence Android app)
- Send and receive secure Silence text messages
- Review your and others' identity fingerprints

*This library does not currently support sending and receiving MMS, nor does it support Silence PreKeys.*

## Install

libsilence-java requires Java >= 8 to run. You can get this library using Maven by adding this to your ```pom.xml```:

```xml
 <dependencies>
    <dependency>       
           <groupId>fr.delthas</groupId>
           <artifactId>libsilence-java</artifactId>
           <version>0.1.0</version>
    </dependency>
</dependencies>
```

## Quick overview of the Silence protocol

The Silence protocol is currently only used over SMS, where each Silence message corresponds to one (possibly concatenated) SMS, but could be used over any underlying message transfer medium.

Silence uses asymmetric encryption with one set of public and private keys for each contact (though an identity fingerprint is shared for all these keys). To start a secure session with a contact, you must send a `KeyInit` message, to which your contact must respond with a `KeyResponse` message. The secure session is then established and you and your contact can send encrypted `Text` messages to each other. When you want to end a secure session, you must send a `SessionEnd` message.

**The Silence messages are:**

| Name | `libsilence-java` methods and classes | Description |
| :---: |     :---      |         :--- |
| **TSK**   | `encryptKeyInit()` `Message.KeyInit`     | Message sent for starting a secure session, contains a generated public key |
| **TSK**   | `encryptKeyResponse()` `Message.KeyResponse`     | Message sent in response to a `KeyInit` message, contains a generated public key  |
| **TSM**     | `encryptText()` `Message.Text`       | Encrypted text message sent when a secure session is established     |
| **TSE**     | `encryptSessionEnd()` `Message.SessionEnd`       | Message sent for ending a secure session (you must not respond to this message)      |

## Quick example

All calls are made through a `Silence` object, which should be saved and loaded every time it is used, since it stores state about the secure sessions (like public and private keys).

The `Message` classes represent incoming encrypted messages.

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
Optional<Message> message = silence.decrypt(address, response);
// The Optional will be empty if the message wasn't a Silence protocol message
// or if it was invalid
if(!message.isPresent()) {
  // Handle this exceptional case
  return;
}

Message message_ = message.get();
// The Message can be a Message.KeyInit, a Message.KeyResponse, a Message.Text,
// or a Message.SessionEnd. Here, it should be a KeyResponse message
if(!message_.isKeyResponse()) {
  // Handle this exceptional case
  return;
}

Message.KeyResponse keyResponse = message_.asKeyResponse();
// By default the key response is automatically accepted and stored,
// so we don't have to anything about this message
// For this example purpose, let's print its fingerprint
byte[] fingerprint = keyResponse.getFingerprint();
String hexFingerprint = Hex.toString(fingerprint);
System.out.println(hexFingerprint);

// Now that the session is established, let's send a secure text message
String text = "Very secure text message!!";

Optional<String> encryptedText = silence.encryptText(address, text); 
// The Optional will be empty if the message couldn't be encrypted because no secure
// session is currently established. In our example case, this wouldn't happen
if(!encryptedText.isPresent()) {
  // Handle this exceptional case
  return;
}

// Send the message over a message transfer wire to your contact
// (in the case of the Silence app, this would simply send this exact String as a SMS)
send(encryptedText.get());


// Let's create a hypothetical loop that would print all received encrypted messages
// until the session ends
outer: while(true) {
  String encrypted = receive();
  message = silence.decrypt(address, encrypted);
  // Ignore invalid messages
  if(!message.isPresent()) {
    continue;
  }
  
  message_ = message.get();
  // You can use a switch rather than if/else conditions on .isXXX()
  switch(message_.getType()) {
    case TEXT:
      // The encrypted message is a text message
      Message.Text receivedText = message_.asText();
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
