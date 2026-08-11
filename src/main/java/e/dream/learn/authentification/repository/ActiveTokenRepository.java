package e.dream.learn.authentification.repository;

import e.dream.learn.authentification.model.ActiveTokens;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ActiveTokenRepository extends CrudRepository<ActiveTokens, Long> {

    // finds the session state via the active refresh token string
    Optional<ActiveTokens> findByRefreshToken(String refreshToken);

    // finds a token by its short-lived access token id string
    Optional<ActiveTokens> findByAccessTokenId(String accessTokenId);

    // used to clear or invalidate all previous sessions when a user logs out globally
    Iterable<ActiveTokens> findByUserIdAndIsRevokedFalse(long userId);

}
