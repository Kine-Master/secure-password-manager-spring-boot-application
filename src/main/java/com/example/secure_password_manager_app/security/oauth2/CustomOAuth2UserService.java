package com.example.secure_password_manager_app.security.oauth2;

import com.example.secure_password_manager_app.auth.AuthProvider;
import com.example.secure_password_manager_app.exception.OAuth2AuthenticationProcessingException;
import com.example.secure_password_manager_app.model.User;
import com.example.secure_password_manager_app.repository.UserRepository;
import com.example.secure_password_manager_app.role.Role;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * Custom OAuth2 User Service that loads user details from the OAuth2 provider.
 * Handles JIT registration and updates for users logging in via Google.
 */
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (Exception ex) {
            // Reraising the exception as InternalAuthenticationServiceException is required
            // for Spring Security to properly handle it and redirect to failure handler.
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        // Extracting user attributes from the OAuth2User object
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId(); // e.g., "google"

        if (provider.equalsIgnoreCase(AuthProvider.GOOGLE.toString())) {
            String googleId = (String) attributes.get("sub"); // Google's unique ID for the user
            String email = (String) attributes.get("email");
            String name = (String) attributes.get("name");

            if (StringUtils.isEmpty(email)) {
                throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
            }

            Optional<User> userOptional = userRepository.findByEmail(email);
            User user;

            if (userOptional.isPresent()) {
                user = userOptional.get();
                // If user exists, check if they used a different provider previously
                if (!user.getAuthProvider().equals(AuthProvider.valueOf(provider.toUpperCase()))) {
                    throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                            user.getAuthProvider() + " account. Please use your " + user.getAuthProvider() +
                            " account to login.");
                }
                // Update existing user's details (e.g., last login, name if changed)
                user.setLastLogin(LocalDateTime.now());
                user.setFullName(name); // Update name in case it changed
                user.setGoogleId(googleId); // Ensure googleId is set
                user = userRepository.save(user);
            } else {
                // New user - perform JIT registration
                user = registerNewOAuth2User(provider, attributes, googleId, email, name);
            }

            // Set the OAuth2 attributes on the User object for future reference in the security context
            user.setAttributes(oAuth2User.getAttributes());
            return user; // The User model now implements OAuth2User, so we can return it directly.

        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + provider + " is not supported yet.");
        }
    }

    private User registerNewOAuth2User(String provider, Map<String, Object> attributes, String googleId, String email, String name) {
        User user = User.builder()
                .username(email) // For Google users, username can be their email
                .email(email)
                .fullName(name)
                .authProvider(AuthProvider.valueOf(provider.toUpperCase()))
                .googleId(googleId)
                .roles(Collections.singleton(Role.USER)) // New Google users are assigned 'USER' role by default
                .createdAt(LocalDateTime.now())
                .lastLogin(LocalDateTime.now())
                .build();

        return userRepository.save(user);
    }
}