package com.github.cheergoivan.totp.decoder;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1Decoder implements Decoder{

	@Override
	public byte[] decode(String input) {
		MessageDigest msgDigest = getMessageDigest("SHA-1");
		try {
			msgDigest.update(input.getBytes("UTF-8"), 0, input.length());
		} catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException(e);
		}
		return msgDigest.digest();
	}
	
	private MessageDigest getMessageDigest(String algorithm){
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
