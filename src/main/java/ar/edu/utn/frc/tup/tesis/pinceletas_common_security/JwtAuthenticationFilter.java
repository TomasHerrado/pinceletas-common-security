package ar.edu.utn.frc.tup.tesis.pinceletas_common_security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

/**
 * Filtro JWT para validar tokens en cada request
 * Compartido entre todos los microservicios
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestPath = request.getRequestURI();
        log.debug("Procesando request: {} {}", request.getMethod(), requestPath);

        final String token = getTokenFromRequest(request);

        if (token == null) {
            log.debug("No se encontró token JWT para: {}", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (jwtService.isTokenValid(token)) {
                String email = jwtService.extractUsername(token);
                String role = jwtService.extractRole(token);

                log.debug("Token válido para usuario: {} con rol: {}", email, role);

                // Crear autenticación con el rol extraído del token
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                email,
                                null,
                                Collections.singletonList(
                                        new SimpleGrantedAuthority("ROLE_" + role)
                                )
                        );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);

                log.debug("Usuario autenticado exitosamente: {}", email);
            } else {
                log.warn("Token inválido para request: {}", requestPath);
            }
        } catch (Exception e) {
            log.error("Error procesando JWT para {}: {}", requestPath, e.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extrae el token del header Authorization
     */
    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(SecurityConstants.JWT_HEADER);

        if (StringUtils.hasText(authHeader) &&
                authHeader.startsWith(SecurityConstants.JWT_PREFIX)) {
            return authHeader.substring(7); // Remover "Bearer "
        }

        return null;
    }

    /**
     * Define qué rutas NO deben pasar por este filtro
     * Puede ser sobrescrito en cada microservicio según necesidad
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // Rutas públicas comunes a todos los microservicios
        return path.startsWith("/api/auth/") ||
                path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs/") ||
                path.startsWith("/h2-console/") ||
                path.equals("/health") ||
                path.equals("/actuator/health");
    }
}
