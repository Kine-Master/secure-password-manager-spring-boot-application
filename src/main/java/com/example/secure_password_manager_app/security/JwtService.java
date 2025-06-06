package com.example.secure_password_manager_app.security;

import com.example.secure_password_manager_app.model.User; // Keep this import for your local User model
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User; // Import OAuth2User
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service for JWT token generation, extraction, and validation.
 */
@Service
public class JwtService {

    @Value("${application.security.jwt.secret}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Existing method for UserDetails (for local users)
    public String generateToken(UserDetails userDetails) {
        // Add roles to the token as a custom claim
        Map<String, Object> claims = new HashMap<>();
        if (userDetails instanceof User) {
            claims.put("roles", ((User) userDetails).getRoles());
            claims.put("email", ((User) userDetails).getEmail());
        }
        return generateToken(claims, userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails.getUsername(), jwtExpiration); // Use userDetails.getUsername()
    }

    public String generateToken(OAuth2User oauth2User) {
        Map<String, Object> claims = new HashMap<>();

        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String googleId = oauth2User.getAttribute("sub");

        claims.put("email", email);
        claims.put("name", name);
        claims.put("googleId", googleId);

        String subject = (email != null) ? email : googleId;

        return buildToken(claims, subject, jwtExpiration);
    }

    // Existing method for UserDetails refresh token
    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails.getUsername(), refreshExpiration);
    }

    // *** NEW METHOD: generateRefreshToken for OAuth2User ***
    public String generateRefreshToken(OAuth2User oauth2User) {
        Map<String, Object> claims = new HashMap<>();

        // Include just enough information to identify the user for refresh token purposes
        String email = oauth2User.getAttribute("email");
        String googleId = oauth2User.getAttribute("sub");

        claims.put("email", email);
        claims.put("googleId", googleId);

        String subject = (email != null) ? email : googleId; // Prefer email as subject

        return buildToken(claims, subject, refreshExpiration);
    }
    // *** END NEW METHOD ***

    // Modified buildToken to accept a String subject directly
    private String buildToken(
            Map<String, Object> extraClaims,
            String subject, // Now takes String subject
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(subject) // Use the passed subject
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), io.jsonwebtoken.SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public boolean isTokenValid(String token, OAuth2User oauth2User) {
        final String subject = extractUsername(token);
        String oauth2UserIdentifier = oauth2User.getAttribute("email");
        return (subject != null && subject.equals(oauth2UserIdentifier)) && !isTokenExpired(token);
    }


    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}