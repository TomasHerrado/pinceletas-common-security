package ar.edu.utn.frc.tup.tesis.pinceletas_common_security;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

/**
 * Servicio para generación y validación de tokens JWT
 * Compartido entre todos los microservicios
 */
@Service
@Slf4j
public class JwtService {
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(SecurityConstants.JWT_SECRET.getBytes());
    }

    /**
     * Genera un token JWT con email y rol del usuario
     * @param email Email del usuario
     * @param role Rol del usuario (USER, ADMIN, etc.)
     * @return Token JWT firmado
     */
    public String generateToken(String email, String role) {
        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + SecurityConstants.JWT_EXPIRATION))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Sobrecarga para mantener compatibilidad (sin rol explícito)
     */
    public String generateToken(String email) {
        return generateToken(email, "USER");
    }

    /**
     * Extrae el email (subject) del token
     */
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * Extrae el rol del usuario del token
     */
    public String extractRole(String token) {
        Object role = getClaims(token).get("role");
        return role != null ? role.toString() : "USER";
    }

    /**
     * Valida si el token es válido y no ha expirado
     */
    public boolean isTokenValid(String token) {
        try {
            getClaims(token);
            return !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            log.warn("Token expirado: {}", e.getMessage());
            return false;
        } catch (JwtException e) {
            log.error("Token inválido: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene la fecha de expiración del token
     */
    public Date getExpirationDate(String token) {
        return getClaims(token).getExpiration();
    }

    // ============================================
    // Métodos privados
    // ============================================

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }
}
