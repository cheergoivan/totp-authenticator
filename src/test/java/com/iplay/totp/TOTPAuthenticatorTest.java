package com.iplay.totp;

import static org.junit.Assert.assertTrue;

import java.util.concurrent.TimeUnit;

import org.junit.Test;

public class TOTPAuthenticatorTest {

	@Test
	public void test() {
		TOTPAuthenticator auth = TOTPAuthenticator.builder().allowedPastValidationWindows(1).build();
		String secret = "#@GSDAjsjbdfi";
		String totp = auth.generateTOTP(secret);
		System.out.println(totp);
		assertTrue(auth.validateTOTP(secret, totp));
		try {
			TimeUnit.SECONDS.sleep((auth.getAllowedPastValidationWindows() + 1) * auth.getTimeStepSize());
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		assertTrue(!auth.validateTOTP(secret, totp));
	}
}
