package com.example.secure_password_manager_app.security;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays; // Import Arrays

/**
 * Custom JWT Authentication Filter. Intercepts incoming requests to validate
 * JWT tokens and set the user's authentication context.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; // This will be CustomUserDetailsService

    // Define public endpoints that should bypass JWT validation if no token is present
    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/auth/register",
            "/api/v1/auth/authenticate",
            // Add any other public endpoints here, e.g., for OAuth2 or health checks
            // "/oauth2/", // Example if you have OAuth2 login initiation
            // "/error",   // Spring Boot's default error path
            // "/h2-console" // If you expose H2 console and want it unfiltered
    };

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String requestURI = request.getRequestURI();

        // Check if the request is for a public endpoint AND there's no JWT token.
        // If true, we let it pass through immediately without JWT validation.
        boolean isPublicEndpoint = Arrays.stream(PUBLIC_ENDPOINTS).anyMatch(requestURI::startsWith);
        boolean hasNoAuthHeader = (authHeader == null || !authHeader.startsWith("Bearer "));

        if (isPublicEndpoint && hasNoAuthHeader) {
            filterChain.doFilter(request, response);
            return; // Essential to return here to stop further filter processing for this request
        }

        // If it's not a public endpoint OR there *is* an auth header (even on a public endpoint,
        // which might indicate a token from a previous session), then proceed with JWT validation.
        if (hasNoAuthHeader) {
            // This part handles cases where a non-public endpoint is accessed without a token.
            // Spring Security's later filters will handle the "access denied" or redirection.
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        final String userEmail = jwtService.extractUsername(jwt); // Assuming username in JWT is email

        // If userEmail is extracted and no authentication is currently set in the security context
        if (userEmail != null && !userEmail.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails;
            try {
                userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            } catch (UsernameNotFoundException e) {
                // If the user doesn't exist for a given token, it means the token is invalid
                // or refers to a deleted user. Log it and let the request fail or proceed
                // to other authentication methods if configured.
                System.out.println("User not found for token: " + userEmail + ". Token is invalid.");
                // Clear security context to prevent further issues with this invalid token
                SecurityContextHolder.clearContext();
                filterChain.doFilter(request, response);
                return;
            }


            if (jwtService.isTokenValid(jwt, userDetails)) {
                // If token is valid, create an authentication token and set it in the SecurityContext
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // Credentials are null as user is already authenticated via token
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                // Token is invalid (e.g., expired, malformed signature)
                System.out.println("JWT token is invalid or expired for user: " + userEmail);
                SecurityContextHolder.clearContext(); // Clear context for invalid token
            }
        } else if (userEmail != null && userEmail.isEmpty()) {
            // This handles cases where extractUsername returns an empty string (e.g., malformed token)
            System.out.println("JWT token contained an empty username. Invalid token.");
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}