package e.dream.learn.authentification.controller;

import e.dream.learn.authentification.model.dto.LoginRequest;
import e.dream.learn.authentification.model.dto.RefreshTokenRequest;
import e.dream.learn.authentification.model.dto.RegistrationRequest;
import e.dream.learn.authentification.model.dto.TokenResponse;
import e.dream.learn.authentification.repository.ActiveTokenRepository;
import e.dream.learn.authentification.service.AuthenticationService;
import e.dream.learn.authentification.security.SecurityConfig;
import e.dream.learn.authentification.service.CustomUserDetailsService;
import e.dream.learn.authentification.service.JwtService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import tools.jackson.databind.ObjectMapper;

import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthenticationService authenticationService;

    @MockitoBean private JwtService jwtService;
    @MockitoBean private CustomUserDetailsService userDetailsService;
    @MockitoBean private ActiveTokenRepository activeTokenRepository;

    // ============================================================================
    // 1. REGISTRATION ENDPOINT TESTS
    // ============================================================================
    @Test
    void shouldReturnOkMessageOnSuccessfulRegistration() throws Exception {
        RegistrationRequest registrationRequest = new RegistrationRequest(
                "miguel_dev",
                "miguel@gmail.com",
                "password123",
                "00-14-22-01-23-45",
                "Tech-Lab-Desktop",
                Set.of("employee")
        );

        when(authenticationService.register(any(RegistrationRequest.class)))
                .thenReturn("User registered successfully! Your hardware device has been auto-approved.");

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully! Your hardware device has been auto-approved."));
    }

    // ============================================================================
    // 2. LOGIN ENDPOINT TESTS
    // ============================================================================
    @Test
    void shouldReturnTokenBundleOnSuccessfulLogin() throws Exception {
        LoginRequest loginRequest = new LoginRequest(
                "miguel@gmail.com",
                "password123",
                "00-14-22-01-23-45",
                "Tech-Lab-Desktop"
        );
        TokenResponse tokenResponse = new TokenResponse("mock-access-token", "mock-refresh-token");

        when(authenticationService.login(any(LoginRequest.class))).thenReturn(tokenResponse);

        mockMvc.perform(post("/api/v1/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                // FIXED: Changed fields from camelCase to snake_case to match payload structure
                .andExpect(jsonPath("$.access_token").value("mock-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("mock-refresh-token"));
    }

    @Test
    void shouldReturnUnauthorizedStatusWhenCredentialsOrMacAreInvalid() throws Exception {
        LoginRequest invalidRequest = new LoginRequest(
                "wrong@gmail.com",
                "wrongpass",
                "BAD-MAC-ADDRESS",
                "Hacker-Machine"
        );

        when(authenticationService.login(any(LoginRequest.class)))
                .thenThrow(new BadCredentialsException("This device is not approved for this account."));

        mockMvc.perform(post("/api/v1/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isUnauthorized());
    }

    // ============================================================================
    // 3. REFRESH TOKEN ENDPOINT TESTS
    // ============================================================================
    @Test
    void shouldRotateTokensSuccessfullyWithin10SecondWindow() throws Exception {
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest("valid-live-refresh-token-string");
        TokenResponse structuralTokenResponse = new TokenResponse("next-access-token", "next-refresh-token");

        when(authenticationService.refreshSessionToken("valid-live-refresh-token-string"))
                .thenReturn(structuralTokenResponse);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                // FIXED: Changed fields from camelCase to snake_case to match payload structure
                .andExpect(jsonPath("$.access_token").value("next-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("next-refresh-token"));
    }

}