package e.dream.learn.authentification.service;

import e.dream.learn.authentification.model.User;
import e.dream.learn.authentification.model.UserRole;
import e.dream.learn.authentification.repository.UserRepository;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService userDetailsService;

    private User mockUser;

    @BeforeEach
    void setUp() {
        mockUser = new User(
                1L,
                "miguel_dev",
                "miguel@gmail.com",
                "hashed_password_xyz",
                true,
                Set.of(new UserRole("employee"))
        );
    }

    @Test
    void shouldLoadUserSuccessfullyByEmailAddress() {
        when(userRepository.findByEmail("miguel@gmail.com")).thenReturn(Optional.of(mockUser));

        // Act (loadUserByUsername is configured to process emails)
        UserDetails result = userDetailsService.loadUserByUsername("miguel@gmail.com");

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("miguel_dev");
        assertThat(result.getPassword()).isEqualTo("hashed_password_xyz");
        verify(userRepository, times(1)).findByEmail("miguel@gmail.com");
    }

    @Test
    void shouldThrowExceptionWhenLoadingUserByEmailFails() {
        when(userRepository.findByEmail("unknown@gmail.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("unknown@gmail.com"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found with email");
    }

    @Test
    void shouldLoadUserSuccessfullyByActualUsernameString() {
        when(userRepository.findByUsername("miguel_dev")).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByActualName("miguel_dev");

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("miguel_dev");
        verify(userRepository, times(1)).findByUsername("miguel_dev");
    }
}