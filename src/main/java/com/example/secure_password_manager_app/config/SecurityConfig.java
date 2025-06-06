package com.example.secure_password_manager_app.config;

import jakarta.servlet.http.HttpServletResponse;
import com.example.secure_password_manager_app.security.JwtAuthenticationFilter;
import com.example.secure_password_manager_app.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.example.secure_password_manager_app.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.example.secure_password_manager_app.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.example.secure_password_manager_app.security.oauth2.CustomOAuth2UserService; // Make sure this import is present
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Central Spring Security configuration for the application.
 * Defines security filter chain, authorization rules, CORS, session management,
 * JWT authentication, and OAuth2 login integration.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Enables @PreAuthorize and @PostAuthorize annotations
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider; // From ApplicationConfig
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    // Inject CustomOAuth2UserService here. Spring will create it as a bean.
    // Ensure CustomOAuth2UserService is marked with @Service and has its own @RequiredArgsConstructor or @Autowired fields.
    private final CustomOAuth2UserService customOAuth2UserService;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. CORS Configuration
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 2. CSRF Protection: Disabled as we are using stateless JWTs
                .csrf(AbstractHttpConfigurer::disable)
                // 3. Exception Handling (e.g., unauthorized access, access denied)
                .exceptionHandling(exceptions -> exceptions
                        // For unauthenticated users trying to access protected resources
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
                        // For authenticated users lacking necessary roles/authorities
                        .accessDeniedHandler((request, response, accessDeniedException) ->
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied"))
                )
                // 4. Authorize HTTP Requests
                .authorizeHttpRequests(authorize -> authorize
                        // Public endpoints (authentication, H2 console, OAuth2 redirects)
                        .requestMatchers(
                                "/api/v1/auth/**",
                                "/oauth2/**", // OAuth2 endpoints (authorization, callback)
                                "/h2-console/**" // H2 console for development (disable in production)
                        ).permitAll()
                        // Admin-only endpoints
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        // Other API endpoints require authentication (for USER or ADMIN)
                        .requestMatchers("/api/v1/**").authenticated()
                        // Any other request needs to be authenticated
                        .anyRequest().authenticated()
                )
                // 5. Session Management: Stateless for JWT
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 6. Authentication Provider: Used for local login
                .authenticationProvider(authenticationProvider)
                // 7. JWT Filter: Custom filter for JWT validation
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // 8. OAuth2 Login Configuration
                .oauth2Login(oauth2 -> oauth2
                        // Authorization request repository for storing state in cookies
                        .authorizationEndpoint(auth -> auth
                                .baseUri("/oauth2/authorize") // Base URI for initiating OAuth2 flow (e.g., /oauth2/authorize/google)
                                .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
                        )
                        // Callback URI where OAuth2 provider redirects after authentication
                        .redirectionEndpoint(redirect -> redirect
                                .baseUri("/oauth2/callback/*") // Matches /oauth2/callback/google etc.
                        )
                        // Custom OAuth2 user service for JIT registration/updates
                        .userInfoEndpoint(userInfo -> userInfo
                                // THIS IS THE FIX: Directly use the injected customOAuth2UserService bean
                                .userService(customOAuth2UserService)
                        )
                        // Handlers for OAuth2 success and failure
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                );

        // Required for H2 console to work with Spring Security
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

        return http.build();
    }

    // CORS Configuration Bean
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow specific origins (your frontend URL)
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173", "http://127.0.0.1:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*")); // Allow all headers
        configuration.setAllowCredentials(true); // Allow sending credentials (cookies, auth headers)
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Apply CORS to all paths
        return source;
    }
}