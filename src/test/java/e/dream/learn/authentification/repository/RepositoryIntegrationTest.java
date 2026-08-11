package e.dream.learn.authentification.repository;

import e.dream.learn.authentification.model.ActiveTokens;
import e.dream.learn.authentification.model.RegisteredDevice;
import e.dream.learn.authentification.model.User;
import e.dream.learn.authentification.model.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jdbc.test.autoconfigure.DataJdbcTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DataJdbcTest
@ActiveProfiles("test") // loads application-test.properties
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class RepositoryIntegrationTest {

    @Autowired
    private UserRepository user_repository;
    @Autowired
    private ActiveTokenRepository active_token_repository;
    @Autowired
    private RegisteredDeviceRepository registered_device_repository;

    private User saved_user;
    private RegisteredDevice saved_device;

    @BeforeEach
    void setUp() {
        active_token_repository.deleteAll();
        registered_device_repository.deleteAll();
        user_repository.deleteAll();

        // register a new user with multiple roles
        User user = new User(
                null,
                "miguel_dev",
                "miguel@gmail.com",
                "hash12345",
                true,
                Set.of(new UserRole("employee"), new UserRole("technician"))
        );
        saved_user = user_repository.save(user);

        // register a new device for the previously created user
        RegisteredDevice device = new RegisteredDevice(
                null,
                saved_user.id(),
                "00-14-22-01-23-45",
                "Tech-Lab-Desktop",
                true,
                LocalDateTime.now()
        );
        saved_device = registered_device_repository.save(device);
    }

    @Test
    void shouldFindUserByEmailAndLoadMultipleRoles() {
        Optional<User> found_user_opt = user_repository.findByEmail("miguel@gmail.com");

        assertThat(found_user_opt).isPresent();
        User found_user = found_user_opt.get();
        assertThat(found_user.getUsername()).isEqualTo("miguel_dev");

        assertThat(found_user.roles()).hasSize(2);
        assertThat(found_user.getAuthorities())
                .extracting("authority")
                .containsExactlyInAnyOrder("ROLE_employee", "ROLE_technician");

    }

    @Test
    void shouldFindUserByMacAddressUsingCustomJoinQuery() {
        Optional<User> foundUserOpt = user_repository.findByMacAddress("00-14-22-01-23-45");

        assertThat(foundUserOpt).isPresent();
        assertThat(foundUserOpt.get().id()).isEqualTo(saved_user.id());
    }

    @Test
    void shouldVerifyApprovedDeviceByUserIdAndMac() {
        Optional<RegisteredDevice> approvedDevice = registered_device_repository
                .findByUserIdAndMacAddressAndIsApprovedTrue(saved_user.id(), "00-14-22-01-23-45");

        assertThat(approvedDevice).isPresent();
        assertThat(approvedDevice.get().deviceName()).isEqualTo("Tech-Lab-Desktop");
    }

    @Test
    void shouldSaveAndFindStatefulActiveTokens() {
        ActiveTokens token = new ActiveTokens(
                null,
                saved_user.id(),
                saved_device.id(),
                "sample-refresh-token-uuid-12345",
                "sample-access-token-sig-54321",
                false,
                LocalDateTime.now().plusSeconds(10), // 10-second refresh expiration
                LocalDateTime.now()
        );

        ActiveTokens savedToken = active_token_repository.save(token);
        Optional<ActiveTokens> foundTokenOpt = active_token_repository.findByRefreshToken("sample-refresh-token-uuid-12345");

        assertThat(foundTokenOpt).isPresent();
        assertThat(foundTokenOpt.get().accessTokenId()).isEqualTo("sample-access-token-sig-54321");
        assertThat(foundTokenOpt.get().isRevoked()).isFalse();
    }
}
