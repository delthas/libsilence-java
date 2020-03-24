package fr.delthas.libsilence;

import java.io.UnsupportedEncodingException;

final class Base64 {
  
  private static final byte[] ENCODE_TABLE = {(byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G', (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N', (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U', (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g', (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n', (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u', (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z', (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'+', (byte)'/'};
  
  private Base64() {}
  
  private static int decodeSingle(byte input) {
    if (input >= 'A' && input <= 'Z') {
      return input - 'A';
    }
    if (input >= 'a' && input <= 'z') {
      return input - 'a' + 26;
    }
    if (input >= '0' && input <= '9') {
      return input - '0' + 52;
    }
    if (input == '+') {
      return 62;
    }
    if (input == '/') {
      return 63;
    }
    throw new IllegalArgumentException("invalid base64 data");
  }
  
  static byte[] encode(byte[] input) {
    int full = input.length / 3;
    int remaining = input.length % 3;
    int length = full * 4;
    if (remaining != 0) {
      length += 4;
    }
    byte[] output = new byte[length];
    for (int i = 0; i < full; i++) {
      int c = ((input[i * 3] & 0xFF) << 16) | ((input[i * 3 + 1] & 0xFF) << 8) | (input[i * 3 + 2] & 0xFF);
      output[i * 4] = ENCODE_TABLE[c >>> 18];
      output[i * 4 + 1] = ENCODE_TABLE[(c >>> 12) & 0b111111];
      output[i * 4 + 2] = ENCODE_TABLE[(c >>> 6) & 0b111111];
      output[i * 4 + 3] = ENCODE_TABLE[c & 0b111111];
    }
    if (remaining == 1) {
      int c = (input[full * 3] & 0xFF) << 4;
      output[full * 4] = ENCODE_TABLE[c >>> 6];
      output[full * 4 + 1] = ENCODE_TABLE[c & 0b111111];
      output[full * 4 + 2] = '=';
      output[full * 4 + 3] = '=';
    } else if (remaining == 2) {
      int c = (((input[full * 3] & 0xFF) << 8) | (input[full * 3 + 1] & 0xFF)) << 2;
      output[full * 4] = ENCODE_TABLE[c >>> 12];
      output[full * 4 + 1] = ENCODE_TABLE[(c >>> 6) & 0b111111];
      output[full * 4 + 2] = ENCODE_TABLE[c & 0b111111];
      output[full * 4 + 3] = '=';
    }
    return output;
  }
  
  static byte[] decode(byte[] input) {
    int full = input.length / 4;
    int remaining = input.length % 4;
    if (remaining == 0 && full >= 1) {
      if (input[input.length - 1] == '=') {
        full--;
        remaining = 3;
        if (input[input.length - 2] == '=') {
          remaining = 2;
        }
      }
    }
    int length = full * 3;
    if (remaining != 0) {
      length += remaining - 1;
    }
    byte[] output = new byte[length];
    for (int i = 0; i < full; i++) {
      int c = (decodeSingle(input[i * 4]) << 18) | (decodeSingle(input[i * 4 + 1]) << 12) | (decodeSingle(input[i * 4 + 2]) << 6) | decodeSingle(input[i * 4 + 3]);
      output[i * 3] = (byte) (c >>> 16);
      output[i * 3 + 1] = (byte) (c >>> 8);
      output[i * 3 + 2] = (byte) c;
    }
    if (remaining == 2) {
      int c = (decodeSingle(input[full * 4]) << 6) | decodeSingle(input[full * 4 + 1]);
      output[full * 3] = (byte) (c >>> 4);
    } else if (remaining == 3) {
      int c = (decodeSingle(input[full * 4]) << 12) | (decodeSingle(input[full * 4 + 1]) << 6) | decodeSingle(input[full * 4 + 2]);
      output[full * 3] = (byte) (c >>> 10);
      output[full * 3 + 1] = (byte) (c >>> 2);
    }
    return output;
  }
  
  static String encodeToString(byte[] input) {
    try {
      return new String(encode(input), "US-ASCII");
    } catch (UnsupportedEncodingException e) {
      // will never happen
      throw new InternalError(e);
    }
  }
  
  static byte[] decode(String input) {
    try {
      return decode(input.getBytes("US-ASCII"));
    } catch (UnsupportedEncodingException e) {
      // will never happen
      throw new InternalError(e);
    }
  }
}
