package com.github.cheergoivan.totp.decoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1Decoder implements Decoder {

	private static final String ALGORITHM = "SHA-1";

	@Override
	public byte[] decode(String input) {
		MessageDigest msgDigest = getMessageDigest(ALGORITHM);
		msgDigest.update(input.getBytes(StandardCharsets.UTF_8), 0, input.length());
		return msgDigest.digest();
	}

	private MessageDigest getMessageDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
