package ar.edu.utn.frc.tup.tesis.pinceletas_common_security;

/**
 * Constantes de seguridad compartidas entre todos los microservicios
 * ⚠️ IMPORTANTE: Estos valores deben ser iguales en todos los servicios
 */
public class SecurityConstants {

    // ⚠️ EN PRODUCCIÓN: Usar variables de entorno
    // Esta SECRET debe ser la misma en TODOS los microservicios
    public static final String JWT_SECRET = "supersecretkeysupersecretkeysupersecretkey";

    // Tiempo de expiración del token: 1 hora
    public static final long JWT_EXPIRATION = 1000 * 60 * 60;

    // Header de autorización
    public static final String JWT_HEADER = "Authorization";

    // Prefijo del token
    public static final String JWT_PREFIX = "Bearer ";

    // Constructor privado para evitar instanciación
    private SecurityConstants() {
        throw new IllegalStateException("Utility class");
    }
}
