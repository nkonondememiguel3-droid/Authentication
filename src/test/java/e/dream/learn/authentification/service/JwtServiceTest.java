package e.dream.learn.authentification.service;

import static org.junit.jupiter.api.Assertions.*;

import e.dream.learn.authentification.model.User;
import e.dream.learn.authentification.model.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {
    private JwtService jwtService;
    private User mockUser;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();

        // Setup a mock user with multiple roles to evaluate claims packing
        mockUser = new User(
                1L,
                "miguel_dev",
                "miguel@gmail.com",
                "hashed_password_xyz",
                true,
                Set.of(new UserRole("employee"), new UserRole("technician"))
        );
    }

    @Test
    void shouldGenerateValidAccessTokenWithMultiRoleClaims() {
        String token = jwtService.generateAccessToken(mockUser);

        assertThat(token).isNotBlank();

        // Extract parameters from the token to confirm encryption/decryption consistency
        String extractedUsername = jwtService.extractUsername(token);
        List<String> extractedRoles = jwtService.extractRoles(token);

        assertThat(extractedUsername).isEqualTo("miguel_dev");
        assertThat(extractedRoles).containsExactlyInAnyOrder("ROLE_employee", "ROLE_technician");
    }

    @Test
    void shouldGenerateRefreshTokenWithValidSubject() {
        String refreshToken = jwtService.generateRefreshToken(mockUser);

        assertThat(refreshToken).isNotBlank();
        assertThat(jwtService.extractUsername(refreshToken)).isEqualTo("miguel_dev");
    }

    @Test
    void shouldConfirmTokenIsValidForMatchingUserContext() {
        String token = jwtService.generateAccessToken(mockUser);

        boolean isValid = jwtService.isTokenValid(token, mockUser);

        assertThat(isValid).isTrue();
    }
}