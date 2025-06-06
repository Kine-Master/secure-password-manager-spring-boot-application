package com.example.secure_password_manager_app;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
// Add @TestPropertySource to provide dummy values for the secrets during testing.
// This prevents the PlaceholderResolutionException when .env isn't loaded by the test runner
@TestPropertySource(properties = {
		"GOOGLE_CLIENT_ID=test-client-id",
		"GOOGLE_CLIENT_SECRET=test-client-secret",
		// JWT_SECRET must be long enough for HS256 (32 bytes = 43 Base64 chars).
		// Provide a sufficiently long dummy string.
		"JWT_SECRET=aVeryLongAndSecureRandomStringForTestingPurposes1234567890abcdefghijklmnopqrstuvwxyz"
})
class SecureRecipeAppApplicationTests {

	@Test
	void contextLoads() {
		// This test simply checks if the Spring application context can load successfully.
		// It's a basic sanity check that your application can start without major configuration errors.
	}

}