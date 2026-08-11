package e.dream.learn.authentification.security;

import e.dream.learn.authentification.model.RegisteredDevice;
import e.dream.learn.authentification.model.User;
import e.dream.learn.authentification.model.UserRole;
import e.dream.learn.authentification.model.dto.LoginRequest;
import e.dream.learn.authentification.model.dto.RegistrationRequest;
import e.dream.learn.authentification.model.dto.TokenResponse;
import e.dream.learn.authentification.repository.ActiveTokenRepository;
import e.dream.learn.authentification.repository.RegisteredDeviceRepository;
import e.dream.learn.authentification.repository.UserRepository;
import e.dream.learn.authentification.service.AuthenticationService;
import e.dream.learn.authentification.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import e.dream.learn.authentification.model.ActiveTokens;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.when;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock private UserRepository userRepository;
    @Mock private RegisteredDeviceRepository deviceRepository;
    @Mock private ActiveTokenRepository tokenRepository;
    @Mock private JwtService jwtService;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthenticationService authenticationService;

    private User mockUser;
    private RegisteredDevice mockDevice;

    @BeforeEach
    void setUp() {
        mockUser = new User(
                42L,
                "test_user",
                "test@company.com",
                "hashed_password",
                true,
                Set.of(new UserRole("employee"), new UserRole("technician"))
        );

        mockDevice = new RegisteredDevice(
                100L,
                42L,
                "00-14-22-01-23-45",
                "Office-Desktop",
                true,
                LocalDateTime.now()
        );
    }

    // ============================================================================
    // 1. REGISTRATION TESTS
    // ============================================================================

    @Test
    void shouldRegisterNewUserAndAutoApprovePrimaryDevice() {
        RegistrationRequest request = new RegistrationRequest(
                "test_user", "test@company.com", "password123",
                "00-14-22-01-23-45", "Office-Desktop", Set.of("employee")
        );

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.password())).thenReturn("hashed_password");
        when(userRepository.save(any(User.class))).thenReturn(mockUser);

        String message = authenticationService.register(request);

        assertThat(message).contains("successfully", "auto-approved");
        verify(userRepository, times(1)).save(any(User.class));
        verify(deviceRepository, times(1)).save(any(RegisteredDevice.class));
    }

    @Test
    void shouldFailRegistrationIfEmailAlreadyExists() {
        RegistrationRequest request = new RegistrationRequest(
                "test_user", "test@company.com", "password123",
                "00-14-22-01-23-45", "Office-Desktop", Set.of("employee")
        );

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(mockUser));

        assertThatThrownBy(() -> authenticationService.register(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("email already exists");
    }

    // ============================================================================
    // 2. LOGIN TESTS
    // ============================================================================

    @Test
    void shouldAuthenticateSuccessfullyAndGenerateStatefulTokens() {
        LoginRequest request = new LoginRequest("test@company.com", "password123", "00-14-22-01-23-45", "Office-Desktop");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(mockUser));
        when(deviceRepository.findByUserIdAndMacAddressAndIsApprovedTrue(42L, request.macAddress()))
                .thenReturn(Optional.of(mockDevice));
        when(jwtService.generateAccessToken(mockUser)).thenReturn("header.payload.access_sig");
        when(jwtService.generateRefreshToken(mockUser)).thenReturn("header.payload.refresh_sig");

        TokenResponse response = authenticationService.login(request);

        assertThat(response.accessToken()).isEqualTo("header.payload.access_sig");
        assertThat(response.refreshToken()).isEqualTo("header.payload.refresh_sig");

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(tokenRepository, times(1)).save(any(ActiveTokens.class));
    }

    @Test
    void shouldFailLoginIfHardwareMacAddressIsNotApproved() {
        LoginRequest request = new LoginRequest("test@company.com", "password123", "UNAUTHORIZED-MAC-XYZ", "Hacker-Laptop");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(mockUser));
        when(deviceRepository.findByUserIdAndMacAddressAndIsApprovedTrue(42L, request.macAddress()))
                .thenReturn(Optional.empty()); // Device lookup fails/not approved

        assertThatThrownBy(() -> authenticationService.login(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("device is not approved");
    }

    // ============================================================================
    // 3. REFRESH TOKEN LOOP TESTS
    // ============================================================================

    @Test
    void shouldRotateTokensSuccessfullyWithinValid10SecondWindow() {
        ActiveTokens storedSession = new ActiveTokens(
                1L, 42L, 100L, "old_refresh_token", "old_access_sig", false,
                LocalDateTime.now().plusSeconds(5), LocalDateTime.now() // Inside the 10s expiration
        );

        when(tokenRepository.findByRefreshToken("old_refresh_token")).thenReturn(Optional.of(storedSession));
        when(userRepository.findById(42L)).thenReturn(Optional.of(mockUser));
        when(jwtService.generateAccessToken(mockUser)).thenReturn("new.access.sig");
        when(jwtService.generateRefreshToken(mockUser)).thenReturn("new.refresh.sig");

        TokenResponse response = authenticationService.refreshSessionToken("old_refresh_token");

        assertThat(response.accessToken()).isEqualTo("new.access.sig");
        assertThat(response.refreshToken()).isEqualTo("new.refresh.sig");

        verify(tokenRepository, times(1)).delete(storedSession); // Checks rotational replacement cleanup
        verify(tokenRepository, times(1)).save(any(ActiveTokens.class)); // Verifies next window insertion
    }

    @Test
    void shouldRejectTokenRotationIfRefreshWindowHasExpired() {
        ActiveTokens expiredSession = new ActiveTokens(
                1L, 42L, 100L, "expired_token", "old_access_sig", false,
                LocalDateTime.now().minusSeconds(1), LocalDateTime.now() // Expired 1 second ago
        );

        when(tokenRepository.findByRefreshToken("expired_token")).thenReturn(Optional.of(expiredSession));

        assertThatThrownBy(() -> authenticationService.refreshSessionToken("expired_token"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Session expired");
    }

    @Test
    void shouldRejectTokenRotationIfSessionHasBeenManuallyRevoked() {
        ActiveTokens revokedSession = new ActiveTokens(
                1L, 42L, 100L, "revoked_token", "old_access_sig", true, // Marked revoked
                LocalDateTime.now().plusSeconds(8), LocalDateTime.now()
        );

        when(tokenRepository.findByRefreshToken("revoked_token")).thenReturn(Optional.of(revokedSession));

        assertThatThrownBy(() -> authenticationService.refreshSessionToken("revoked_token"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("token has been revoked");
    }

}