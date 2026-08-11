package e.dream.learn.authentification.model.dto;

import java.util.Set;

public record RegistrationRequest(
        String username,
        String email,
        String password,
        String macAddress,
        String deviceName,
        Set<String> roles) {
}
