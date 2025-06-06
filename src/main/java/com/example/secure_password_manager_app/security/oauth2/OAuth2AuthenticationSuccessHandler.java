package com.example.secure_password_manager_app.security.oauth2;

import com.example.secure_password_manager_app.security.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser; // Keep this import
import org.springframework.security.oauth2.core.user.OAuth2User; // Keep this import

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static com.example.secure_password_manager_app.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

/**
 * Handles successful OAuth2 authentication. Generates a JWT token and redirects
 * the user to the frontend with the token.
 */
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${application.oauth2.authorized-redirect-uri}")
    private String authorizedRedirectUri;

    private final JwtService jwtService;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    public OAuth2AuthenticationSuccessHandler(JwtService jwtService, HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.jwtService = jwtService;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(jakarta.servlet.http.Cookie::getValue);

        // Ensure the redirect URI is authorized to prevent open redirect vulnerabilities
        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new IllegalArgumentException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        String targetUrl = redirectUri.orElse(authorizedRedirectUri);

        OAuth2User oauth2User;
        if (authentication.getPrincipal() instanceof DefaultOidcUser) {
            oauth2User = (DefaultOidcUser) authentication.getPrincipal();
        } else if (authentication.getPrincipal() instanceof OAuth2User) {
            oauth2User = (OAuth2User) authentication.getPrincipal();
        } else {
            // If it's neither DefaultOidcUser nor OAuth2User, something is wrong with the flow.
            // Log this, or re-throw a more specific exception.
            logger.error("Authentication principal is not an OAuth2User or DefaultOidcUser. Type: " + authentication.getPrincipal().getClass().getName());
            throw new IllegalArgumentException("Authentication principal is not a recognized OAuth2User type. Cannot generate token.");
        }

        // Generate both JWT (access token) and Refresh Token
        String jwtToken = jwtService.generateToken(oauth2User);
        String refreshToken = jwtService.generateRefreshToken(oauth2User);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", jwtToken)
                .queryParam("refresh_token", refreshToken)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        URI authorizedUri = URI.create(authorizedRedirectUri);

        return authorizedUri.getHost().equalsIgnoreCase(clientRedirectUri.getHost()) &&
                authorizedUri.getPort() == clientRedirectUri.getPort();
    }
}