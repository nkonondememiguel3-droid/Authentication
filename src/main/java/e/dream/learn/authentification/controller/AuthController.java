package e.dream.learn.authentification.controller;

import e.dream.learn.authentification.model.dto.LoginRequest;
import e.dream.learn.authentification.model.dto.RefreshTokenRequest;
import e.dream.learn.authentification.model.dto.RegistrationRequest;
import e.dream.learn.authentification.model.dto.TokenResponse;
import e.dream.learn.authentification.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> authenticateDesktopClient(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authenticationService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> rotateSessionTokens(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authenticationService.refreshSessionToken(request.refreshToken()));
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerDesktopClient(@RequestBody RegistrationRequest request) {
        String confirmationMessage = authenticationService.register(request);
        return ResponseEntity.ok(confirmationMessage);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> terminateDesktopSession(@RequestHeader("Authorization") String authHeader) {
        String confirmationMessage = authenticationService.logout(authHeader);
        return ResponseEntity.ok(confirmationMessage);
    }

}
