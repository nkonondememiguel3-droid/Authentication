package e.dream.learn.authentification.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Table("registered_device")
public record RegisteredDevice(
        @Id Long id,
        @Column("user_id") long userId,
        @Column("mac_address") String macAddress,
        @Column("device_name") String deviceName,
        @Column("is_approved") boolean isApproved,
        @Column("registered_at") LocalDateTime registeredAt
) {
}
