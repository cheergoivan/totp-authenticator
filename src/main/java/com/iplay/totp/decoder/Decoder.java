package com.iplay.totp.decoder;

public interface Decoder {
	byte[] decode(String input);
}
