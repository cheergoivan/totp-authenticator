package com.iplay.totp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author Ivan
 */
public class TOTPAuthenticator {

	/**
	 * the Unix time to start counting time steps (default value is 0)
	 */
	private static final long TIME_START = 0L;

	/**
	 * the length of generated time-based one-time password (default value is 6)
	 */
	private int totpLength;

	/**
	 * the time step in seconds
	 */
	private int timeStepSize;

	/**
	 * When an OTP is generated at the end of a time-step window, the receiving
	 * time most likely falls into the next time-step window. A validation
	 * system SHOULD typically set a policy for an acceptable OTP transmission
	 * delay window for validation. The validation system should compare OTPs
	 * not only with the receiving timestamp but also the past timestamps that
	 * are within the transmission delay. The allowedPastValidationWindows
	 * represents the number of previous time-step windows that the
	 * authenticator will calculate and if a calculated OTP in a time-step
	 * window matches user input, then the validation is considered as
	 * successful. The default value is 2.
	 * 
	 * @see <a href="https://tools.ietf.org/html/rfc6238#section-5.2">Validation
	 *      and Time-Step Size</a>
	 */
	private int allowedPastValidationWindows;

	/**
	 * The allowedFutureValidationWindows is similar to
	 * {@link #allowedFutureValidationWindows allowedPastValidationWindows} but
	 * it represents the number of following time-step windows that the
	 * authenticator will calculate. The default value is 0.
	 * 
	 */
	private int allowedFutureValidationWindows;

	/**
	 * The default value is SHA1
	 */
	private HAMCHashAlgorithm hashAlgorithm;

	private TOTPAuthenticator() {
	}

	private TOTPAuthenticator(int totpLength, int timeStepSize, int allowedPastValidationWindows,
			int allowedFutureValidationWindows, HAMCHashAlgorithm hashAlgorithm) {
		super();
		this.totpLength = totpLength;
		this.timeStepSize = timeStepSize;
		this.allowedPastValidationWindows = allowedPastValidationWindows;
		this.allowedFutureValidationWindows = allowedFutureValidationWindows;
		this.hashAlgorithm = hashAlgorithm;
	}

	public static class TOTPAuthenticatorBuilder {
		private int totpLength;
		private int timeStepSize;
		private int allowedPastValidationWindows;
		private int allowedFutureValidationWindows;
		private HAMCHashAlgorithm hashAlgorithm;

		private TOTPAuthenticatorBuilder() {
		}

		public TOTPAuthenticatorBuilder totpLength(int totpLength) {
			this.totpLength = totpLength;
			return this;
		}

		public TOTPAuthenticatorBuilder timeStepSize(int timeStepSize) {
			this.timeStepSize = timeStepSize;
			return this;
		}

		public TOTPAuthenticatorBuilder allowedPastValidationWindows(int allowedPastValidationWindows) {
			this.allowedPastValidationWindows = allowedPastValidationWindows;
			return this;
		}

		public TOTPAuthenticatorBuilder allowedFutureValidationWindows(int allowedFutureValidationWindows) {
			this.allowedFutureValidationWindows = allowedFutureValidationWindows;
			return this;
		}

		public TOTPAuthenticatorBuilder hashAlgorithm(HAMCHashAlgorithm hashAlgorithm) {
			this.hashAlgorithm = hashAlgorithm;
			return this;
		}

		public TOTPAuthenticator build() {
			return new TOTPAuthenticator(totpLength, timeStepSize, allowedPastValidationWindows,
					allowedFutureValidationWindows, hashAlgorithm);
		}
	}

	public boolean validateTotp(byte[] key, String totpFromProver) {
		if (isTotp(totpFromProver)) {
			final long receivedTimeStepWindow = getTimeStepWindowFromTimestamp(System.currentTimeMillis());
			for (int i = 0 - allowedPastValidationWindows; i <= allowedFutureValidationWindows; i++) {
				String totpCalculated = calculateTotp(key, receivedTimeStepWindow + i);
				if (totpCalculated.equals(totpFromProver)) {
					return true;
				}
			}
		}
		return false;
	}

	private String calculateTotp(byte[] key, long timeStepWindow) {
		byte[] data = new byte[8];
		long value = timeStepWindow;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}
		SecretKeySpec signKey = new SecretKeySpec(key, hashAlgorithm.getAlgorithm());
		try {
			// Step 1:Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
			Mac mac = Mac.getInstance(hashAlgorithm.getAlgorithm());
			mac.init(signKey);
			byte[] hmac_result = mac.doFinal(data);
			// Step 2: Generate a 4-byte string,from byte hmac_result[offset]

			int offset = hmac_result[hmac_result.length - 1] & 0xF;
			int truncatedHash = (hmac_result[offset] & 0x7f) << 24 | (hmac_result[offset + 1] & 0xff) << 16
					| (hmac_result[offset + 2] & 0xff) << 8 | (hmac_result[offset + 3] & 0xff);
			// Step 3:Compute an HOTP value

			truncatedHash %= ((int) Math.pow(10, totpLength));
			String totp = Integer.toString(truncatedHash);
			while (totp.length() < totpLength) {
				totp = "0" + totp;
			}
			return totp;
		} catch (NoSuchAlgorithmException | InvalidKeyException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private long getTimeStepWindowFromTimestamp(long milliSeconds) {
		return (milliSeconds - TIME_START) / TimeUnit.SECONDS.toMillis(timeStepSize);
	}

	private boolean isTotp(String str) {
		if (str != null) {
			if (str.length() == totpLength) {
				for (char c : str.toCharArray()) {
					if (!Character.isDigit(c)) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}

}
