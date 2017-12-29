package com.iplay.totp;

public enum HAMCHashAlgorithm {

	SHA1("HmacSHA1");
	
	private String algorithm;

	private HAMCHashAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return algorithm;
	}
}
