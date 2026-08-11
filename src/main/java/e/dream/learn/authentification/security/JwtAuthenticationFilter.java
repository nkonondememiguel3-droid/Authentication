package e.dream.learn.authentification.security;

import e.dream.learn.authentification.model.ActiveTokens;
import e.dream.learn.authentification.model.dto.ApiErrorResponse;
import e.dream.learn.authentification.repository.ActiveTokenRepository;
import e.dream.learn.authentification.repository.UserRepository;
import e.dream.learn.authentification.service.CustomUserDetailsService;
import e.dream.learn.authentification.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final e.dream.learn.authentification.service.CustomUserDetailsService userDetailsService;
    private final e.dream.learn.authentification.repository.ActiveTokenRepository activeTokenRepository;

    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String clientMacAddress = request.getHeader("X-Device-Mac");
        final String jwt;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);

        try {
            username = jwtService.extractUsername(jwt);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                String accessTokenSignature = jwt.substring(jwt.lastIndexOf('.') + 1);
                var statefulTokenOpt = activeTokenRepository.findByAccessTokenId(accessTokenSignature);

                if (statefulTokenOpt.isEmpty() || statefulTokenOpt.get().isRevoked()) {
                    log.warn("Stateful Auth Rejected: Token is missing or revoked.");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked.");
                    return;
                }

                if (clientMacAddress == null || clientMacAddress.isBlank()) {
                    log.warn("Hardware Auth Rejected: Missing X-Device-Mac header.");
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing hardware identifier header.");
                    return;
                }

                UserDetails userDetails = this.userDetailsService.loadUserByActualName(username);

                if (jwtService.isTokenValid(jwt, userDetails)) {
                    List<String> roles = jwtService.extractRoles(jwt);
                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException e) { // 2. Catch the exact short-lived token expiration event
            log.warn("Filter Interception: Access Token has expired natively. Message: {}", e.getMessage());
            handleFilterException(response, HttpStatus.UNAUTHORIZED, "Token Expired", "Your access token has expired. Please use your refresh token to request a new session.");

        } catch (JwtException e) { // Catch other cryptographic failures (malformed tokens, wrong keys)
            log.error("Filter Interception: Invalid cryptographic token parsing error: {}", e.getMessage());
            handleFilterException(response, HttpStatus.UNAUTHORIZED, "Invalid Token", "The provided authentication token signature is invalid.");
        }
    }

    /**
     * Helper method to serialize your custom error structure directly into the response stream.
     */
    private void handleFilterException(HttpServletResponse response, HttpStatus status, String error, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiErrorResponse errorPayload = new ApiErrorResponse(
                status.value(),
                error,
                message,
                LocalDateTime.now()
        );

        // 2. Simply use the injected bean directly. No manual configuration needed!
        response.getWriter().write(objectMapper.writeValueAsString(errorPayload));
    }
}
