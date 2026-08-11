package e.dream.learn.authentification.security;

import e.dream.learn.authentification.model.ActiveTokens;
import e.dream.learn.authentification.repository.ActiveTokenRepository;
import e.dream.learn.authentification.service.CustomUserDetailsService;
import e.dream.learn.authentification.service.JwtService;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;
    @Mock
    private CustomUserDetailsService userDetailsService;
    @Mock
    private ActiveTokenRepository activeTokenRepository;
    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private UserDetails mockUserDetails;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext(); // Ensure a clean security context before each test run

        mockUserDetails = User.withUsername("miguel_dev")
                .password("protected_password")
                .authorities("ROLE_employee", "ROLE_technician")
                .build();
    }

    // ============================================================================
    // 1. SCENARIO: NO JWT TOKEN SUPPLIED
    // ============================================================================
    @Test
    void shouldSkipFilterIfAuthorizationHeaderIsMissing() throws ServletException, IOException {
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // The filter must pass the request down the chain without populating the context or throwing errors
        verify(filterChain, times(1)).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    // ============================================================================
    // 2. SCENARIO: TOKEN EXISTS BUT IS REVOKED IN POSTGRESQL
    // ============================================================================
    @Test
    void shouldReturnUnauthorizedIfTokenIsRevokedInDatabase() throws ServletException, IOException {
        String dummyJwt = "header.payload.signature_abc123";
        request.addHeader("Authorization", "Bearer " + dummyJwt);

        when(jwtService.extractUsername(dummyJwt)).thenReturn("miguel_dev");

        // Mock a stateful token row that has been manually revoked (is_revoked = true)
        ActiveTokens revokedTokenSession = new ActiveTokens(
                1L, 42L, 100L, "refresh_token_xyz", "signature_abc123", true,
                LocalDateTime.now().plusSeconds(10), LocalDateTime.now()
        );
        when(activeTokenRepository.findByAccessTokenId("signature_abc123")).thenReturn(Optional.of(revokedTokenSession));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Expect an instant 401 response and check that the chain execution stops
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getErrorMessage()).contains("Token has been revoked");
        verify(filterChain, never()).doFilter(request, response);
    }

    // ============================================================================
    // 3. SCENARIO: VALID TOKEN PRESENT BUT MISSING THE MANDATORY DESKTOP MAC HEADER
    // ============================================================================
    @Test
    void shouldReturnBadRequestIfDeviceMacHeaderIsMissing() throws ServletException, IOException {
        String dummyJwt = "header.payload.signature_abc123";
        request.addHeader("Authorization", "Bearer " + dummyJwt);
        // "X-Device-Mac" header is intentionally left out

        when(jwtService.extractUsername(dummyJwt)).thenReturn("miguel_dev");

        ActiveTokens activeTokenSession = new ActiveTokens(
                1L, 42L, 100L, "refresh_token_xyz", "signature_abc123", false,
                LocalDateTime.now().plusSeconds(10), LocalDateTime.now()
        );
        when(activeTokenRepository.findByAccessTokenId("signature_abc123")).thenReturn(Optional.of(activeTokenSession));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Expect a 400 Bad Request since desktop clients are required to send their hardware identity
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getErrorMessage()).contains("Missing hardware identifier header");
        verify(filterChain, never()).doFilter(request, response);
    }

    // ============================================================================
    // 4. SCENARIO: COMPLETE STATEFUL AUTHENTICATION SUCCESS
    // ============================================================================
    @Test
    void shouldAuthenticateSuccessfullyWithValidTokenAndMacHeader() throws ServletException, IOException {
        String dummyJwt = "header.payload.signature_abc123";
        request.addHeader("Authorization", "Bearer " + dummyJwt);
        request.addHeader("X-Device-Mac", "00-14-22-01-23-45"); // Valid hardware header provided

        when(jwtService.extractUsername(dummyJwt)).thenReturn("miguel_dev");

        ActiveTokens activeTokenSession = new ActiveTokens(
                1L, 42L, 100L, "refresh_token_xyz", "signature_abc123", false,
                LocalDateTime.now().plusSeconds(10), LocalDateTime.now()
        );
        when(activeTokenRepository.findByAccessTokenId("signature_abc123")).thenReturn(Optional.of(activeTokenSession));
        when(userDetailsService.loadUserByActualName("miguel_dev")).thenReturn(mockUserDetails);
        when(jwtService.isTokenValid(dummyJwt, mockUserDetails)).thenReturn(true);
        when(jwtService.extractRoles(dummyJwt)).thenReturn(List.of("ROLE_employee", "ROLE_technician"));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Verification checks
        verify(filterChain, times(1)).doFilter(request, response); // Request is allowed to continue down the line
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull(); // Security Context successfully populated
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("miguel_dev");

        // Assert that your multiple roles are accurately loaded into the security context authorities map
        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .extracting("authority")
                .containsExactlyInAnyOrder("ROLE_employee", "ROLE_technician");
    }

}