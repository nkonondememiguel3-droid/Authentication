package e.dream.learn.authentification.model.dto;

public record LoginRequest(String email, String password, String deviceName, String macAddress) {
}
