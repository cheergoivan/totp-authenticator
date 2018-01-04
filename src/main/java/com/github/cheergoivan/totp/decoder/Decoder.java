package com.github.cheergoivan.totp.decoder;

public interface Decoder {
	byte[] decode(String input);
}
