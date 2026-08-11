package e.dream.learn.authentification.service;

import e.dream.learn.authentification.model.ActiveTokens;
import e.dream.learn.authentification.model.RegisteredDevice;
import e.dream.learn.authentification.model.User;
import e.dream.learn.authentification.model.UserRole;
import e.dream.learn.authentification.model.dto.LoginRequest;
import e.dream.learn.authentification.model.dto.RegistrationRequest;
import e.dream.learn.authentification.model.dto.TokenResponse;
import e.dream.learn.authentification.repository.ActiveTokenRepository;
import e.dream.learn.authentification.repository.RegisteredDeviceRepository;
import e.dream.learn.authentification.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RegisteredDeviceRepository deviceRepository;
    private final ActiveTokenRepository tokenRepository;
    private final JwtService jwtService;

    @Transactional
    public TokenResponse login(LoginRequest request) {
        log.info("Processing login request for hardware device MAC: {}", request.macAddress());

        // 1. Validate traditional email/password credentials via Spring Security
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        // 2. Fetch user profile from database
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials."));

        // 3. HARDWARE BINDING: Check if this desktop machine is registered and approved
        RegisteredDevice device = deviceRepository
                .findByUserIdAndMacAddressAndIsApprovedTrue(user.id(), request.macAddress())
                .orElseThrow(() -> {
                    log.warn("Access Denied: Machine MAC [{}] is not approved for user {}", request.macAddress(), user.email());
                    return new BadCredentialsException("This device is not approved for this account.");
                });

        // 4. Cryptographically build both tokens using our modern JwtService
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Extract the unique crypto signature from the access token to act as our fast stateful tracking ID
        String accessTokenId = accessToken.substring(accessToken.lastIndexOf('.') + 1);

        // 5. STATEFUL TRACKING: Save the active token context row in PostgreSQL
        ActiveTokens activeTokenSession = new ActiveTokens(
                null,
                user.id(),
                device.id(),
                refreshToken,
                accessTokenId,
                false,
                LocalDateTime.now().plusSeconds(10), // Enforce strict 10-second refresh lifetime boundary
                LocalDateTime.now()
        );
        tokenRepository.save(activeTokenSession);

        return new TokenResponse(accessToken, refreshToken);
    }

    @Transactional
    public TokenResponse refreshSessionToken(String refreshTokenString) {
        log.info("Processing stateful refresh token verification loop...");

        // 1. Look up refresh token state row inside PostgreSQL
        ActiveTokens storedToken = tokenRepository.findByRefreshToken(refreshTokenString)
                .orElseThrow(() -> new BadCredentialsException("Invalid or unrecognized session token."));

        // 2. Enforce stateful invalidation rules
        if (storedToken.isRevoked()) {
            log.warn("Refresh Blocked: Session token has been marked as REVOKED in database.");
            throw new BadCredentialsException("This token has been revoked.");
        }

        if (storedToken.expiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Refresh Blocked: 10-second lifetime window has EXPIRED.");
            throw new BadCredentialsException("Session expired. Please log in again.");
        }

        // 3. Load user context linked to token row
        User user = userRepository.findById(storedToken.userId())
                .orElseThrow(() -> new BadCredentialsException("User profile linked to token no longer exists."));

        // 4. Revoke old token state to prevent Token Reuse Attacks (Rotational Strategy)
        tokenRepository.delete(storedToken);

        // 5. Issue clean updated token set
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);
        String newAccessTokenId = newAccessToken.substring(newAccessToken.lastIndexOf('.') + 1);

        ActiveTokens nextTokenSession = new ActiveTokens(
                null,
                user.id(),
                storedToken.deviceId(),
                newRefreshToken,
                newAccessTokenId,
                false,
                LocalDateTime.now().plusSeconds(10), // Next strict 10-second window
                LocalDateTime.now()
        );
        tokenRepository.save(nextTokenSession);

        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    // Inject PasswordEncoder into your AuthenticationService constructor if not already there
    private final PasswordEncoder password_encoder;

    @Transactional
    public String register(RegistrationRequest request) {
        log.info("Processing new user registration for email: {}", request.email());

        // 1. Check if email or username already exists to prevent duplicates
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new BadCredentialsException("An account with this email already exists.");
        }
        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new BadCredentialsException("Username is already taken.");
        }

        // 2. Map String roles to UserRole structural models
        Set<UserRole> mappedRoles = request.roles().stream()
                .map(UserRole::new)
                .collect(Collectors.toSet());

        // 3. Create and save the new User record
        User newUser = new User(
                null,
                request.username(),
                request.email(),
                password_encoder.encode(request.password()), // Strictly hash the password
                true, // enabled by default
                mappedRoles
        );
        User savedUser = userRepository.save(newUser);

        // 4. Automatically link and approve the registering machine's MAC address
        RegisteredDevice primaryDevice = new RegisteredDevice(
                null,
                savedUser.id(),
                request.macAddress(),
                request.deviceName() != null ? request.deviceName() : "Primary Desktop",
                true, // Automatically approved on initial sign-up
                java.time.LocalDateTime.now()
        );
        deviceRepository.save(primaryDevice);

        log.info("User {} successfully registered with device MAC {}", savedUser.username(), request.macAddress());
        return "User registered successfully! Your hardware device has been auto-approved.";
    }

    @Transactional
    public String logout(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new BadCredentialsException("No valid authorization session token provided.");
        }

        // 1. Extract the raw JWT string from the Header
        String jwt = authHeader.substring(7);

        // 2. Extract the unique cryptographic signature acting as our access token tracking ID
        String accessTokenId = jwt.substring(jwt.lastIndexOf('.') + 1);

        log.info("Processing secure stateful logout for Access Token signature ID: {}", accessTokenId);

        // 3. Locate the session row in PostgreSQL and remove it
        tokenRepository.findByAccessTokenId(accessTokenId).ifPresentOrElse(
                tokenSession -> {
                    tokenRepository.delete(tokenSession);
                    log.info("PostgreSQL session ledger row deleted successfully. Session destroyed.");
                },
                () -> log.warn("Logout warning: No active session row found for token signature.")
        );

        // 4. Clear the local Spring Security Context thread holder completely
        SecurityContextHolder.clearContext();

        return "Logged out successfully. Stateful desktop session terminated.";
    }

}
