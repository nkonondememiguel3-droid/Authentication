package e.dream.learn.authentification.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Table("active_tokens")
public record ActiveTokens(
        @Id Long id,
        @Column("user_id") long userId,
        @Column("device_id") long deviceId,
        @Column("refresh_token") String refreshToken,
        @Column("access_token_id") String accessTokenId,
        @Column("is_revoked") boolean isRevoked,
        @Column("expires_at") LocalDateTime expiresAt,
        @Column("created_at") LocalDateTime createdAt
) {
}
