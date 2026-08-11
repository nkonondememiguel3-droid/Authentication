package e.dream.learn.authentification.service;

import e.dream.learn.authentification.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("Attempting to load user by username: {}", email);

        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("Authentification failed: User with email {} not founc in database.", email);
                    return new UsernameNotFoundException("User not found with email: " + email);
                });
    }

    /*
      Helper method to look a user by his actual name if needed.
     */
    public UserDetails loadUserByActualName(String username) throws UsernameNotFoundException {
        log.info("Loading user profile via user name: {}", username);

        return userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User lookup failed: Username {} not found", username);
                    return new UsernameNotFoundException("Username not found with username: " + username);
                });
    }
}
