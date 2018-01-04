package com.github.cheergoivan.totp;

public enum HMACHashAlgorithm {

	SHA_1("HmacSHA1"), SHA_256("HmacSHA256"), SHA_512("HmacSHA512");
	
	private String algorithm;

	private HMACHashAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return algorithm;
	}
}
