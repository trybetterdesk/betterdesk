// Package db defines the database interface and models for the NeoDesk server.
// Implementations: sqlite.go (default), postgres.go (PostgreSQL via pgx/v5).
package db

import (
	"errors"
	"strings"
	"time"
)

// Peer represents a registered RustDesk device.
type Peer struct {
	ID           string     `json:"id"`
	UUID         string     `json:"uuid"`
	PK           []byte     `json:"pk"`
	IP           string     `json:"ip"`
	User         string     `json:"user,omitempty"`
	Hostname     string     `json:"hostname,omitempty"`
	OS           string     `json:"os,omitempty"`
	Version      string     `json:"version,omitempty"`
	Status       string     `json:"status"` // ONLINE, OFFLINE, DEGRADED, CRITICAL
	NATType      int        `json:"nat_type"`
	LastOnline   time.Time  `json:"last_online"`
	CreatedAt    time.Time  `json:"created_at"`
	Disabled     bool       `json:"disabled"`
	Banned       bool       `json:"banned"`
	BanReason    string     `json:"ban_reason,omitempty"`
	BannedAt     *time.Time `json:"banned_at,omitempty"`
	SoftDeleted  bool       `json:"soft_deleted"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
	Note         string     `json:"note,omitempty"`
	Tags         string     `json:"tags,omitempty"`
	DisplayName  string     `json:"display_name"`             // Admin-set alias (overrides hostname in UI)
	DeviceType   string     `json:"device_type,omitempty"`    // CDAP: desktop, mobile, headless, kiosk, etc.
	LinkedPeerID string     `json:"linked_peer_id,omitempty"` // CDAP: paired device (e.g., mobile→desktop)
	HeartbeatSeq int64      `json:"-"`                        // internal heartbeat counter
}

// RemoteTarget represents a manually configured RDP or VNC endpoint.
// Credentials are stored encrypted and are never included in JSON responses.
type RemoteTarget struct {
	ID                   string     `json:"id"`
	OrgID                string     `json:"org_id,omitempty"`
	Name                 string     `json:"name"`
	Protocol             string     `json:"protocol"` // rdp or vnc
	Platform             string     `json:"platform,omitempty"`
	Host                 string     `json:"host"`
	Port                 int        `json:"port"`
	Username             string     `json:"username,omitempty"`
	CredentialMode       string     `json:"credential_mode"` // saved, prompt, none
	CredentialCiphertext string     `json:"-"`
	CredentialNonce      string     `json:"-"`
	CredentialKeyID      string     `json:"-"`
	TLSMode              string     `json:"tls_mode"` // required, preferred, disabled
	CertFingerprint      string     `json:"cert_fingerprint,omitempty"`
	Enabled              bool       `json:"enabled"`
	LastTestAt           *time.Time `json:"last_test_at,omitempty"`
	LastTestStatus       string     `json:"last_test_status,omitempty"`
	LastTestError        string     `json:"last_test_error,omitempty"`
	CreatedBy            string     `json:"created_by,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ServerConfig stores runtime configuration in the database.
type ServerConfig struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// User represents an API user account.
// Authentication provider values for User.AuthProvider. Determines how an
// account is allowed to authenticate. A user bound to a non-local provider
// can ONLY authenticate via that provider — password login is rejected even
// when a username collides with a local account.
const (
	AuthProviderLocal = "local" // local password (PBKDF2/bcrypt)
	AuthProviderLDAP  = "ldap"  // LDAP / Active Directory
	AuthProviderOIDC  = "oidc"  // OpenID Connect / OAuth2 SSO
)

type User struct {
	ID                int64  `json:"id"`
	Username          string `json:"username"`
	PasswordHash      string `json:"-"`
	Role              string `json:"role"`            // admin, operator, viewer
	IsServerAdmin     bool   `json:"is_server_admin"` // Phase 3: separate server admin flag
	AuthProvider      string `json:"auth_provider"`   // local, ldap, oidc
	TOTPSecret        string `json:"-"`
	TOTPEnabled       bool   `json:"totp_enabled"`
	TOTPRecoveryCodes string `json:"-"` // JSON array of bcrypt-hashed recovery codes (H4)
	CreatedAt         string `json:"created_at"`
	LastLogin         string `json:"last_login,omitempty"`
	// CredentialsChangedAt is when the password or the second factor last
	// changed, in Unix seconds; 0 when never since the column exists. A
	// sign-in token issued before it is no longer good.
	CredentialsChangedAt int64 `json:"-"`
	// Disabled says the account may not sign in and its tokens are refused;
	// the account and its history stay. UpdateUser leaves it as it is:
	// SetUserDisabled changes it.
	Disabled bool `json:"-"`
}

// RolePermission represents a custom permission override for a role.
// Stored in the role_permissions table. If no override exists for a role+permission,
// the default from auth.DefaultRolePermissions is used.
type RolePermission struct {
	ID         int64  `json:"id"`
	Role       string `json:"role"`
	Permission string `json:"permission"` // e.g. "device.view", "user.manage"
	Granted    bool   `json:"granted"`    // true = allowed, false = denied
}

// ClientSession represents a RustDesk desktop client login session (opaque bearer token).
type ClientSession struct {
	ID         int64  `json:"id"`
	TokenHash  string `json:"-"`
	UserID     int64  `json:"user_id"`
	ClientID   string `json:"client_id"`
	ClientUUID string `json:"client_uuid"`
	ExpiresAt  string `json:"expires_at"`
	LastUsed   string `json:"last_used,omitempty"`
	CreatedAt  string `json:"created_at"`
	Revoked    bool   `json:"revoked"`
	IPAddress  string `json:"ip_address,omitempty"`
}

// APIKey represents a scoped API key for programmatic access.
type APIKey struct {
	ID        int64  `json:"id"`
	KeyHash   string `json:"-"`
	KeyPrefix string `json:"key_prefix"` // First 8 chars for identification
	Name      string `json:"name"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	LastUsed  string `json:"last_used,omitempty"`
}

// IDChangeHistory tracks peer ID changes.
type IDChangeHistory struct {
	OldID     string    `json:"old_id"`
	NewID     string    `json:"new_id"`
	ChangedAt time.Time `json:"changed_at"`
	Reason    string    `json:"reason,omitempty"`
}

// PeerIDState describes whether an ID is available, active, or reserved by a
// soft-deleted peer row.
type PeerIDState string

const (
	PeerIDMissing     PeerIDState = "missing"
	PeerIDActive      PeerIDState = "active"
	PeerIDSoftDeleted PeerIDState = "soft_deleted"
)

var (
	ErrPeerNotFound      = errors.New("db: peer not found")
	ErrPeerIDExists      = errors.New("db: peer ID already exists")
	ErrPeerIDSoftDeleted = errors.New("db: peer ID belongs to a deleted peer")
	// ErrUsernameTaken is returned by RenameUser when the target name is in use.
	ErrUsernameTaken = errors.New("db: username already exists")
	// ErrInvitationNotOpen is RedeemOrgInvitation's answer for an
	// invitation that does not exist, is used or has expired.
	ErrInvitationNotOpen = errors.New("db: invitation is not open")
	// ErrOrgUsernameTaken is RedeemOrgInvitation's answer when the
	// organization already has the username.
	ErrOrgUsernameTaken = errors.New("db: username already exists in this organization")
	// ErrInvalidUsername is returned by RenameUser for a name that fails the
	// account-name format check.
	ErrInvalidUsername = errors.New("db: invalid username")
)

// PeerMetric represents a single heartbeat metric data point. A value
// the device did not measure is nil (null in JSON). The network rates are
// bytes per second over the time the sample covers; only NeoDesk clients
// send them.
type PeerMetric struct {
	ID        int64     `json:"id"`
	PeerID    string    `json:"peer_id"`
	CPU       *float64  `json:"cpu_usage"`
	Memory    *float64  `json:"memory_usage"`
	Disk      *float64  `json:"disk_usage"`
	NetRx     *float64  `json:"net_rx_bps,omitempty"`
	NetTx     *float64  `json:"net_tx_bps,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// PeerUsage is one usage sample of a device's telemetry; nil is a value
// the device did not send.
type PeerUsage struct {
	CPU, Memory, Disk, NetRx, NetTx *float64
}

// Empty is true when the sample holds no value at all.
func (u PeerUsage) Empty() bool {
	return u.CPU == nil && u.Memory == nil && u.Disk == nil && u.NetRx == nil && u.NetTx == nil
}

// TelemetrySnapshot is the latest bounded snapshot reported by a device.
// Payload is kept as JSON so platform-specific fields can be added without
// changing the server schema for every operating system.
type TelemetrySnapshot struct {
	DeviceID    string `json:"device_id"`
	Kind        string `json:"kind"`
	SampleID    string `json:"sample_id"`
	Status      string `json:"status"`
	Payload     string `json:"payload"`
	CollectedAt string `json:"collected_at"`
	ReceivedAt  string `json:"received_at"`
}

// TelemetryCommand is a durable, device-bound command delivered by heartbeat.
// Args and Result are bounded JSON strings validated by the API handlers.
type TelemetryCommand struct {
	ID          int64  `json:"id"`
	DeviceID    string `json:"device_id"`
	Command     string `json:"command"`
	Args        string `json:"args"`
	Status      string `json:"status"`
	Result      string `json:"result,omitempty"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// DeviceToken represents a unique enrollment token for device registration.
// Dual Key System: supports both global server key (backward compatible) and
// per-device tokens for enhanced security.
type DeviceToken struct {
	ID         int64      `json:"id"`
	Token      string     `json:"token"`             // Unique enrollment token (32 chars)
	TokenHash  string     `json:"-"`                 // SHA256 hash for storage
	Name       string     `json:"name"`              // Friendly name for the token
	PeerID     string     `json:"peer_id,omitempty"` // Bound peer ID (after enrollment)
	Status     string     `json:"status"`            // pending, active, revoked, expired
	MaxUses    int        `json:"max_uses"`          // 0 = unlimited, 1 = single-use
	UseCount   int        `json:"use_count"`         // Current use count
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // Optional expiration
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"` // Admin who created the token
	Note       string     `json:"note,omitempty"`
	// CreatedByToken is the public id of the console API token the token
	// was made with, "" for none: the end of that API token ends it.
	CreatedByToken string `json:"-"`
	// FolderID is the folder (device group) a device that enrolls with
	// the token goes into, 0 for none.
	FolderID int64 `json:"folder_id,omitempty"`
	// OrgID is the organization a device that enrolls with the token
	// joins, so that its policies apply to the device; "" for none.
	OrgID string `json:"org_id,omitempty"`
	// Kind is TokenKindDevice (one computer: the first device that joins
	// binds it) or TokenKindRollout (many computers until it expires or
	// MaxUses computers joined; never bound, never a device's credential).
	// "" reads as TokenKindDevice.
	Kind string `json:"kind,omitempty"`
}

// The kinds of a device token (A278).
const (
	TokenKindDevice  = "device"
	TokenKindRollout = "rollout"
)

// IsRollout reports whether the token is a rollout token.
func (t *DeviceToken) IsRollout() bool { return t != nil && t.Kind == TokenKindRollout }

// kindOrDevice is the kind to store: TokenKindDevice when none is set.
func (t *DeviceToken) kindOrDevice() string {
	if t.Kind == "" {
		return TokenKindDevice
	}
	return t.Kind
}

// DeviceTokenStatus constants
const (
	TokenStatusPending = "pending" // Created, not yet used
	TokenStatusActive  = "active"  // Bound to a peer
	TokenStatusRevoked = "revoked" // Manually revoked
	TokenStatusExpired = "expired" // Past expiration date
)

// ChatMessage represents a persisted chat message between devices/operators.
type ChatMessage struct {
	ID             int64     `json:"id"`
	ConversationID string    `json:"conversation_id"` // "operator", device_id, or group:<id>
	FromID         string    `json:"from_id"`         // sender device_id or "operator:<name>"
	FromName       string    `json:"from_name"`       // display name
	ToID           string    `json:"to_id,omitempty"` // recipient device_id or group ID
	Text           string    `json:"text"`
	Read           bool      `json:"read"`
	CreatedAt      time.Time `json:"created_at"`
}

// ChatUnread is how many messages of one sender a reader has not read.
type ChatUnread struct {
	FromID   string
	FromName string
	Count    int
}

// ChatGroup represents a multi-device chat group.
type ChatGroup struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Members   string    `json:"members"`    // comma-separated device IDs
	CreatedBy string    `json:"created_by"` // device_id or operator name
	CreatedAt time.Time `json:"created_at"`
}

// chatGroupHasMember reports whether a comma-separated members list has id
// as one of its members.
func chatGroupHasMember(members, id string) bool {
	for _, member := range strings.Split(members, ",") {
		if strings.TrimSpace(member) == id {
			return true
		}
	}
	return false
}

// ChatContact represents a peer visible for chat (derived from peers table).
type ChatContact struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	Online      bool   `json:"online"`
	LastSeen    int64  `json:"last_seen"`
	Unread      int    `json:"unread"`
	AvatarColor string `json:"avatar_color"`
}

// HelpRequest status constants.
const (
	HelpStatusPending      = "pending"      // Raised by device, awaiting operator
	HelpStatusAcknowledged = "acknowledged" // Operator picked it up
	HelpStatusResolved     = "resolved"     // Operator closed it
	HelpStatusCancelled    = "cancelled"    // Device cancelled it
)

// HelpRequest represents a support request raised by an agent device.
type HelpRequest struct {
	ID        int64     `json:"id"`
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	Message   string    `json:"message"`
	Status    string    `json:"status"`
	HandledBy string    `json:"handled_by,omitempty"` // operator that acked/resolved
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// HelpRequestFilter narrows ListHelpRequests results. Empty fields match any.
type HelpRequestFilter struct {
	Status   string // "" = any status
	DeviceID string // "" = any device
	OrgID    string // "" = any org (org data-scoping)
	Limit    int    // 0 = default (100)
}

// Organization represents a customer/tenant entity.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	LogoURL   string    `json:"logo_url,omitempty"`
	Settings  string    `json:"settings,omitempty"` // JSON blob for org-level settings
	CreatedAt time.Time `json:"created_at"`
}

// OrgUser represents a user account within an organization.
// Can be either a standalone org-scoped user (password_hash set) or a linked
// server-level user (server_user_id set, password_hash empty).
type OrgUser struct {
	ID           string     `json:"id"`
	OrgID        string     `json:"org_id"`
	ServerUserID int64      `json:"server_user_id,omitempty"` // FK to users.id (0 = standalone org user)
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name,omitempty"`
	Email        string     `json:"email,omitempty"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"` // owner, admin, operator, user
	TOTPSecret   string     `json:"-"`
	AvatarURL    string     `json:"avatar_url,omitempty"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// OrgDevice binds a device to an organization with metadata.
type OrgDevice struct {
	OrgID          string `json:"org_id"`
	DeviceID       string `json:"device_id"`
	AssignedUserID string `json:"assigned_user_id,omitempty"`
	Department     string `json:"department,omitempty"`
	Location       string `json:"location,omitempty"`
	Building       string `json:"building,omitempty"`
	Tags           string `json:"tags,omitempty"`
}

// OrgInvitation is an invitation to a sign-in in an organization. The
// table's token column holds the SHA-256 of the invitation's code; Token
// carries the code itself only in the answer that creates the invitation.
type OrgInvitation struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"org_id"`
	Token     string     `json:"token,omitempty"`
	Email     string     `json:"email,omitempty"`
	Role      string     `json:"role"` // default: "user"
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	// CreatedByToken is the public id of the console API token the
	// invitation was made with, "" for none: the end of that API token
	// ends an invitation nobody used yet.
	CreatedByToken string `json:"-"`
}

// OrgSetting stores a single key-value pair scoped to an organization.
type OrgSetting struct {
	OrgID string `json:"org_id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// DeviceSignin is a device's saved sign-in: the account name and password
// of its operating system account, each sealed for the device with
// crypto/devicevault, and how the viewer uses them. UpdatedAt is RFC 3339
// in UTC.
type DeviceSignin struct {
	DeviceID   string
	UserNonce  string
	UserCipher string
	PassNonce  string
	PassCipher string
	KeyID      string
	// Form is what the device's sign-in screen asks for: "password" (the
	// account is shown, only its password is typed) or "name_password"
	Form      string
	Auto      bool
	UpdatedAt string
	UpdatedBy string
}

// OrgPeerCredentialReseal moves one organization's device password from
// OldKeyID to KeyID with a new nonce and ciphertext.
type OrgPeerCredentialReseal struct {
	OrgID, PeerID, OldKeyID  string
	Nonce, Ciphertext, KeyID string
}

// OrgPeerCredential is metadata for an encrypted peer password row.
// Ciphertext/nonce are never exposed via JSON APIs that list credentials.
type OrgPeerCredential struct {
	OrgID       string `json:"org_id"`
	PeerID      string `json:"peer_id"`
	Ciphertext  string `json:"-"`
	Nonce       string `json:"-"`
	KeyID       string `json:"-"`
	PasswordSet bool   `json:"password_set"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	UpdatedBy   string `json:"updated_by,omitempty"`
}

// AccessPolicy controls unattended access for a peer device.
type AccessPolicy struct {
	PeerID            string `json:"peer_id"`
	UnattendedEnabled bool   `json:"unattended_enabled"`            // Whether unattended access is allowed
	PasswordHash      string `json:"-"`                             // bcrypt hash of unattended password
	PasswordSet       bool   `json:"password_set"`                  // Whether a password is configured (computed, not stored)
	ScheduleEnabled   bool   `json:"schedule_enabled"`              // Whether access schedule is active
	ScheduleDays      string `json:"schedule_days,omitempty"`       // Comma-separated days: "mon,tue,wed,thu,fri"
	ScheduleStartTime string `json:"schedule_start_time,omitempty"` // HH:MM (24h format)
	ScheduleEndTime   string `json:"schedule_end_time,omitempty"`   // HH:MM (24h format)
	ScheduleTimezone  string `json:"schedule_timezone,omitempty"`   // IANA timezone (e.g. "Europe/Warsaw")
	AllowedOperators  string `json:"allowed_operators,omitempty"`   // Comma-separated operator usernames (empty = all)
	UpdatedAt         string `json:"updated_at,omitempty"`
	UpdatedBy         string `json:"updated_by,omitempty"` // Admin/operator who last changed the policy
}

// Organization roles as rows hold them. The routes give every new account,
// membership and invitation OrgRoleUser; the other roles are in rows
// stored earlier, where they still widen what an organization sign-in
// reads (the member list, the invitations).
const (
	OrgRoleOwner    = "owner"
	OrgRoleAdmin    = "admin"
	OrgRoleOperator = "operator"
	OrgRoleUser     = "user"
)

// AuditConnection records a remote-control session event reported by a RustDesk client.
// Mirrors the Node.js console's audit_connections table for API-port consolidation.
type AuditConnection struct {
	ID        int64  `json:"id"`
	HostID    string `json:"host_id"`
	HostUUID  string `json:"host_uuid"`
	PeerID    string `json:"peer_id"`
	PeerName  string `json:"peer_name"`
	Action    string `json:"action"`
	ConnType  int    `json:"conn_type"`
	SessionID string `json:"session_id"`
	IP        string `json:"ip"`
	CreatedAt string `json:"created_at"`
}

// AuditFile records a file-transfer event reported by a RustDesk client.
type AuditFile struct {
	ID        int64  `json:"id"`
	HostID    string `json:"host_id"`
	HostUUID  string `json:"host_uuid"`
	PeerID    string `json:"peer_id"`
	Direction int    `json:"direction"`
	Path      string `json:"path"`
	IsFile    int    `json:"is_file"`
	NumFiles  int    `json:"num_files"`
	FilesJSON string `json:"files_json"`
	IP        string `json:"ip"`
	PeerName  string `json:"peer_name"`
	CreatedAt string `json:"created_at"`
}

// AuditAlarm records a security alarm event reported by a RustDesk client.
type AuditAlarm struct {
	ID        int64  `json:"id"`
	AlarmType int    `json:"alarm_type"`
	AlarmName string `json:"alarm_name"`
	HostID    string `json:"host_id"`
	PeerID    string `json:"peer_id"`
	IP        string `json:"ip"`
	Details   string `json:"details"`
	CreatedAt string `json:"created_at"`
}

// AuditFilter holds optional filter parameters for audit list/count queries.
// A nil AlarmType means "no filter on alarm_type".
type AuditFilter struct {
	HostID    string
	PeerID    string
	Action    string
	AlarmType *int
	Limit     int
	Offset    int
}

// UserGroup represents a named group of operator/user accounts.
// Mirrors the Node.js console's user_groups table.
type UserGroup struct {
	ID          int64  `json:"id"`
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	Note        string `json:"note"`
	TeamID      string `json:"team_id"`
	MemberCount int    `json:"member_count"`
	CreatedAt   string `json:"created_at"`
}

// DeviceGroup represents a named group of devices.
// Mirrors the Node.js console's device_groups table.
type DeviceGroup struct {
	ID          int64  `json:"id"`
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	Note        string `json:"note"`
	TeamID      string `json:"team_id"`
	SourceType  string `json:"source_type"` // "manual" or "tag"
	TagFilter   string `json:"tag_filter"`
	MemberCount int    `json:"member_count"`
	CreatedAt   string `json:"created_at"`
}

// Strategy maps a user group + device group to a permission policy.
// Mirrors the Node.js console's strategies table.
type Strategy struct {
	ID              int64  `json:"id"`
	GUID            string `json:"guid"`
	Name            string `json:"name"`
	UserGroupGUID   string `json:"user_group_guid"`
	DeviceGroupGUID string `json:"device_group_guid"`
	Enabled         bool   `json:"enabled"`
	Permissions     string `json:"permissions"` // JSON blob
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// Database is the interface for all database operations.
// Designed to support SQLite (now) and PostgreSQL (future) as drop-in implementations.
type Database interface {
	// Lifecycle
	Close() error
	Migrate() error

	// Peer operations
	GetPeer(id string) (*Peer, error)
	GetPeerIDState(id string) (PeerIDState, error)
	// GetPeersByIDs returns active (non-soft-deleted) peers for the given IDs.
	// Missing IDs are omitted; an empty ids slice returns an empty map.
	GetPeersByIDs(ids []string) (map[string]*Peer, error)
	GetPeerByUUID(uuid string) (*Peer, error)
	UpsertPeer(p *Peer) error
	DeletePeer(id string) error     // soft delete
	HardDeletePeer(id string) error // permanent delete
	ListPeers(includeDeleted bool) ([]*Peer, error)
	// ListPeersPaginated returns peers with SQL LIMIT/OFFSET plus total row count.
	// limit <= 0 returns all rows (offset still applied).
	ListPeersPaginated(includeDeleted bool, limit, offset int) ([]*Peer, int, error)
	GetPeerCount() (total int, online int, err error)
	GetBannedPeerCount() (int, error)

	// Status tracking
	// source identifies the observer (signal, heartbeat, cdap, mesh, admin, …).
	// Transitions are recorded to peer_availability_events only when the feature
	// is enabled in server_config and from_status != to_status.
	UpdatePeerStatus(id string, status string, ip string, source string) error
	BatchUpdatePeerStatus(ids []string, status string, source string) error
	UpdatePeerSysinfo(id, hostname, os, version string) error
	// SetAllOffline marks every peer OFFLINE at process start. It intentionally
	// does NOT write availability events (avoids restart downtime floods).
	SetAllOffline() error

	// TouchServerInstance writes or refreshes the row of a running server
	// instance; ListServerInstances returns those seen at or after since;
	// RemoveServerInstance deletes one (cluster.InstanceStore).
	TouchServerInstance(inst ServerInstance) error
	ListServerInstances(since time.Time) ([]ServerInstance, error)
	RemoveServerInstance(name string) error

	// Availability history — optional, gated by server_config.
	GetPeerAvailabilityEvents(peerID string, from, to time.Time) ([]*PeerAvailabilityEvent, error)
	CleanupOldAvailabilityEvents(maxAge time.Duration) (int64, error)
	IsAvailabilityHistoryEnabled() bool
	AvailabilityHistoryRetentionDays() int
	InvalidateAvailabilityHistoryCache()

	// Connection sessions — server-observed PunchHole/RequestRelay + relay end.
	StartPeerConnectionSession(sess *PeerConnectionSession) (int64, error)
	EndPeerConnectionSessionByRelay(relayUUID string) error
	ListPeerConnectionSessions(hostID string, limit int) ([]*PeerConnectionSession, error)
	CleanupOldPeerConnectionSessions(maxAge time.Duration) (int64, error)

	// Peer field updates
	UpdatePeerFields(id string, fields map[string]string) error

	// Manually configured RDP/VNC targets
	CreateRemoteTarget(target *RemoteTarget) error
	GetRemoteTarget(id string) (*RemoteTarget, error)
	ListRemoteTargets(orgID string, includeDisabled bool) ([]*RemoteTarget, error)
	UpdateRemoteTarget(target *RemoteTarget) error
	DeleteRemoteTarget(id string) error

	// Ban system
	BanPeer(id string, reason string) error
	UnbanPeer(id string) error
	IsPeerBanned(id string) (bool, error)
	IsPeerSoftDeleted(id string) (bool, error)
	// RestorePeer clears the soft_deleted flag and deleted_at timestamp,
	// making a previously deleted peer visible and registrable again.
	// This is an explicit admin operation — UpsertPeer must NOT do this
	// implicitly (GHSA-3v82-3gf8-fxx8).
	RestorePeer(id string) error

	// Blocklist entries added at run time (security.Blocklist.UseStore)
	SaveBlocklistEntry(e *BlocklistEntry) error
	DeleteBlocklistEntry(kind, value string) error
	ListBlocklistEntries() ([]*BlocklistEntry, error)

	// Server events (package audit), kept for audit.RetentionDays
	AddServerEvents(events []*ServerEvent) error
	ListServerEvents(action string, limit, offset int) ([]*ServerEvent, error)
	CountServerEvents(action string) (int64, error)
	PruneServerEvents(cutoff time.Time) (int64, error)

	// ID change
	ChangePeerID(oldID, newID, reason string) error
	GetIDChangeHistory(id string) ([]*IDChangeHistory, error)
	// IsRenamedPeerID returns true if the given ID was previously used and
	// changed to a different one (appears as old_id in id_change_history).
	IsRenamedPeerID(id string) (bool, error)
	// GetLatestRenameTarget returns the most recent new_id for a renamed old_id.
	GetLatestRenameTarget(oldID string) (string, error)
	// ReleasePeerID clears id_change_history rows involving id so the ID can be reused.
	ReleasePeerID(id string) error

	// CDAP: linked device queries
	GetLinkedPeers(id string) ([]*Peer, error)

	// Tags
	UpdatePeerTags(id, tags string) error
	ListPeersByTag(tag string) ([]*Peer, error)

	// Config
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error
	CompareAndSwapConfig(key, expected, replacement string) (bool, error)
	DeleteConfig(key string) error
	ListConfigByPrefix(prefix string) ([]ServerConfig, error)

	// Users
	CreateUser(u *User) error
	GetUser(username string) (*User, error)
	GetUserByID(id int64) (*User, error)
	ListUsers() ([]*User, error)
	UpdateUser(u *User) error
	// RenameUser changes a username and cascades to every table that keys on it
	// (address books, org membership, strategy assignments, lockouts). It runs in
	// one transaction and returns ErrUsernameTaken on a collision.
	RenameUser(id int64, newUsername string) error
	DeleteUser(id int64) error
	// SetUserDisabled disables or enables an account.
	SetUserDisabled(id int64, disabled bool) error
	// AccountSignInRules reads what the web console's admins require of
	// the account's sign-in (a new password, two-factor sign-in); none
	// where the web console never made its table.
	AccountSignInRules(userID int64) (AccountSignInRules, error)
	// UpdateUserFromProvider stores the email address and display name a
	// directory or single sign-on gave at sign-in in the web console's
	// profile columns; an empty value leaves its column as it is.
	UpdateUserFromProvider(id int64, email, displayName string) error
	UpdateUserLogin(id int64) error
	UserCount() (int, error)

	// API Keys
	CreateAPIKey(k *APIKey) error
	GetAPIKeyByHash(keyHash string) (*APIKey, error)
	ListAPIKeys() ([]*APIKey, error)
	DeleteAPIKey(id int64) error
	TouchAPIKey(id int64) error

	// Device Tokens (Dual Key System)
	CreateDeviceToken(t *DeviceToken) error
	GetDeviceToken(id int64) (*DeviceToken, error)
	GetDeviceTokenByHash(tokenHash string) (*DeviceToken, error)
	GetDeviceTokenByPeerID(peerID string) (*DeviceToken, error)
	ListDeviceTokens(includeRevoked bool) ([]*DeviceToken, error)
	UpdateDeviceToken(t *DeviceToken) error
	RevokeDeviceToken(id int64) error
	// EndDeviceTokensExcept ends the device tokens of the device but the
	// device_tokens row keep: a new token for a device ends the others.
	EndDeviceTokensExcept(peerID string, keep int64) error
	BindTokenToPeer(tokenHash, peerID string) error
	IncrementTokenUse(tokenHash string) error
	// ClaimRolloutJoin takes one place of a rollout token atomically
	// (false: revoked, expired or used up); ReleaseRolloutJoin gives it
	// back when the join fails after the claim.
	ClaimRolloutJoin(id int64) (bool, error)
	ReleaseRolloutJoin(id int64) error
	ValidateToken(tokenHash string) (*DeviceToken, error) // Returns token if valid, nil if invalid/expired/revoked
	CleanupExpiredTokens() (int64, error)

	// Address Book
	GetAddressBook(username, abType string) (string, error) // Returns JSON data string; abType: "legacy" or "personal"
	SaveAddressBook(username, abType, data string) error

	// Peer Metrics (heartbeat CPU/memory/disk)
	SavePeerMetric(peerID string, cpu, memory, disk float64) error
	SavePeerUsage(peerID string, usage PeerUsage) error
	GetPeerMetrics(peerID string, limit int) ([]*PeerMetric, error)
	GetLatestPeerMetric(peerID string) (*PeerMetric, error)
	CleanupOldMetrics(maxAge time.Duration) (int64, error) // Delete metrics older than maxAge

	// NeoDesk device telemetry and heartbeat-delivered commands.
	SaveTelemetrySnapshot(snapshot *TelemetrySnapshot) error
	GetTelemetrySnapshot(deviceID, kind string) (*TelemetrySnapshot, error)
	QueueTelemetryCommand(command *TelemetryCommand) (int64, error)
	GetPendingTelemetryCommands(deviceID string, limit int) ([]*TelemetryCommand, error)
	// CompleteTelemetryCommand completes command id only when it is pending
	// or running for deviceID.
	CompleteTelemetryCommand(deviceID string, id int64, status, result string) error
	// OpenTelemetryCommands returns which of ids are commands of deviceID
	// that still take an answer (pending or running, not expired), with
	// the name of each.
	OpenTelemetryCommands(deviceID string, ids []int64) (map[int64]string, error)
	// MarkTelemetryCommandRunning notes that the device started command
	// id: it is no longer handed out, takes the final answer until
	// expiresAt.
	MarkTelemetryCommandRunning(deviceID string, id int64, expiresAt time.Time) error

	// Fleet tasks, resources, workflows and compliance (fleet.go).
	Fleet() FleetStore

	// Per-device desktop connection mode (normal <-> incoming-only).
	IssueConnectionMode(issue *ConnectionModeIssue) (*ConnectionModeCommand, bool, error)
	GetConnectionModePolicy(deviceID string) (*ConnectionModePolicy, error)
	LatestConnectionModeCommand(deviceID string) (*ConnectionModeCommand, error)
	DeliverableConnectionModeCommand(deviceID string, now time.Time) (*ConnectionModeCommand, error)
	// UnreadDeviceTickets counts the tickets the device opened in the
	// console that have something it has not read (device_tickets.go)
	UnreadDeviceTickets(deviceID string) (int, error)
	MarkConnectionModeDelivered(commandID string, now time.Time) error
	AcknowledgeConnectionMode(ack *ConnectionModeAck) (bool, error)

	// Chat Messages
	SaveChatMessage(msg *ChatMessage) (int64, error) // Returns inserted ID
	GetChatHistory(conversationID string, limit int) ([]*ChatMessage, error)
	GetChatHistoryBefore(conversationID string, beforeID int64, limit int) ([]*ChatMessage, error)
	MarkChatRead(conversationID, readerID string) error // Mark all messages as read for reader
	GetUnreadCount(deviceID string) (int, error)        // Total unread messages for device
	// GetUnreadBySender splits GetUnreadCount by sender (from_id and
	// from_name)
	GetUnreadBySender(deviceID string) ([]ChatUnread, error)
	DeleteChatHistory(conversationID string) error

	// Chat Groups
	CreateChatGroup(g *ChatGroup) error
	GetChatGroup(id string) (*ChatGroup, error)
	ListChatGroups(memberID string) ([]*ChatGroup, error) // Groups containing memberID
	UpdateChatGroup(g *ChatGroup) error
	DeleteChatGroup(id string) error

	// Help Requests
	CreateHelpRequest(r *HelpRequest) (int64, error) // Returns inserted ID
	GetHelpRequest(id int64) (*HelpRequest, error)
	ListHelpRequests(filter HelpRequestFilter) ([]*HelpRequest, error)
	UpdateHelpRequestStatus(id int64, status, handledBy string) error
	PruneHelpRequests(maxAge time.Duration) (int64, error) // Delete requests older than maxAge
	GetDeviceOrgID(deviceID string) (string, error)        // "" if device has no org

	// Organizations
	CreateOrganization(o *Organization) error
	GetOrganization(id string) (*Organization, error)
	GetOrganizationBySlug(slug string) (*Organization, error)
	ListOrganizations() ([]*Organization, error)
	UpdateOrganization(o *Organization) error
	DeleteOrganization(id string) error

	// Org Users
	CreateOrgUser(u *OrgUser) error
	GetOrgUser(id string) (*OrgUser, error)
	GetOrgUserByUsername(orgID, username string) (*OrgUser, error)
	GetOrgUserByServerUserID(orgID string, serverUserID int64) (*OrgUser, error)
	ListOrgUsers(orgID string) ([]*OrgUser, error)
	UpdateOrgUser(u *OrgUser) error
	DeleteOrgUser(id string) error
	UpdateOrgUserLogin(id string) error

	// Org User Linking
	LinkUserToOrg(orgID string, userID int64, role string) (*OrgUser, error)
	UnlinkUserFromOrg(orgID string, serverUserID int64) error
	ListUsersNotInOrg(orgID string) ([]*User, error)
	ListUserOrganizations(userID int64) ([]*Organization, error)

	// Org Devices
	AssignDeviceToOrg(d *OrgDevice) error
	UnassignDeviceFromOrg(orgID, deviceID string) error
	GetOrgDevice(orgID, deviceID string) (*OrgDevice, error)
	ListOrgDevices(orgID string) ([]*OrgDevice, error)
	UpdateOrgDevice(d *OrgDevice) error

	// Org Invitations
	CreateOrgInvitation(inv *OrgInvitation) error
	GetOrgInvitationByToken(token string) (*OrgInvitation, error)
	ListOrgInvitations(orgID string) ([]*OrgInvitation, error)
	// RedeemOrgInvitation uses the invitation whose token column is
	// tokenHash and creates user in its organization, in one transaction.
	// ErrInvitationNotOpen: no such invitation, or it is used or expired.
	// ErrOrgUsernameTaken: the organization has user's username. Neither
	// uses the invitation.
	RedeemOrgInvitation(tokenHash string, user *OrgUser) (*OrgInvitation, error)
	DeleteOrgInvitation(id string) error

	// Org Settings
	GetOrgSetting(orgID, key string) (string, error)
	SetOrgSetting(orgID, key, value string) error
	DeleteOrgSetting(orgID, key string) error
	ListOrgSettings(orgID string) ([]*OrgSetting, error)

	// Org Address Books (shared contacts for organization members)
	GetOrgAddressBook(orgID, abType string) (string, error)
	SaveOrgAddressBook(orgID, abType, data, updatedBy string) error

	// Org peer credentials — AES-GCM ciphertext in main DB
	// Saved sign-in of a device (DeviceSignin): nil when there is none;
	// Save writes every field; Delete reports whether there was one
	GetDeviceSignin(deviceID string) (*DeviceSignin, error)
	SaveDeviceSignin(d *DeviceSignin) error
	DeleteDeviceSignin(deviceID string) (bool, error)
	// Devices whose NeoDesk opens sealed sign-ins (device_sealed_signin):
	// the device reported it in its system information (source "sysinfo")
	// or was handed a sealed sign-in (source "use"); at is RFC 3339 in UTC.
	// A mark stays until the device is deleted for good, follows an ID
	// change, and outlives its saved sign-in; Mark reports whether it was
	// new.
	MarkDeviceSealedSignin(deviceID, source, at string) (bool, error)
	DeviceSealedSignin(deviceID string) (bool, error)

	// Organizations' device passwords sealed with another key than keyID
	// (full rows), and their move to keyID in one transaction: a row
	// changes only while it still has its old key id; the count is the
	// rows changed
	ListOrgPeerCredentialsNotSealedWith(keyID string) ([]*OrgPeerCredential, error)
	ResealOrgPeerCredentials(rows []OrgPeerCredentialReseal) (int, error)

	GetOrgPeerCredential(orgID, peerID string) (*OrgPeerCredential, error)
	ListOrgPeerCredentialFlags(orgID string) ([]*OrgPeerCredential, error)
	SaveOrgPeerCredential(c *OrgPeerCredential) error
	DeleteOrgPeerCredential(orgID, peerID string) error

	// Access Policies (unattended access management)
	GetAccessPolicy(peerID string) (*AccessPolicy, error)
	SaveAccessPolicy(p *AccessPolicy) error
	// SetAccessPolicyPasswordMarker records whether the device keeps a
	// local password (LOCAL_ONLY) or none, and changes nothing else of
	// its access policy. Without a policy, a device with a password gets
	// one that only carries the marker; one without a password gets none.
	SetAccessPolicyPasswordMarker(peerID string, set bool) error
	DeleteAccessPolicy(peerID string) error

	// Role Permissions (RBAC Phase 52)
	ListRolePermissions(role string) ([]*RolePermission, error)
	SetRolePermission(role, permission string, granted bool) error
	DeleteRolePermission(role, permission string) error
	HasRolePermission(role, permission string) (bool, error)

	// Org-scoped device queries (RBAC Phase 52 — data scoping)
	ListPeersForOrg(orgID string, includeDeleted bool) ([]*Peer, error)
	ListPeersForOrgPaginated(orgID string, includeDeleted bool, limit, offset int) ([]*Peer, int, error)

	// Audit logs (RustDesk client reporting — API-port consolidation Phase A)
	InsertAuditConnection(a *AuditConnection) error
	ListAuditConnections(f AuditFilter) ([]*AuditConnection, error)
	CountAuditConnections(f AuditFilter) (int, error)
	InsertAuditFile(a *AuditFile) error
	ListAuditFiles(f AuditFilter) ([]*AuditFile, error)
	CountAuditFiles(f AuditFilter) (int, error)
	InsertAuditAlarm(a *AuditAlarm) error
	ListAuditAlarms(f AuditFilter) ([]*AuditAlarm, error)
	CountAuditAlarms(f AuditFilter) (int, error)

	// User groups (operator/user grouping — API-port consolidation Phase A)
	ListUserGroups() ([]*UserGroup, error)
	GetUserGroup(guid string) (*UserGroup, error)
	CreateUserGroup(g *UserGroup) error
	UpdateUserGroup(guid string, g *UserGroup) error
	DeleteUserGroup(guid string) error

	// Device groups (device grouping — API-port consolidation Phase A)
	ListDeviceGroups() ([]*DeviceGroup, error)
	GetDeviceGroup(guid string) (*DeviceGroup, error)
	CreateDeviceGroup(g *DeviceGroup) error
	UpdateDeviceGroup(guid string, g *DeviceGroup) error
	DeleteDeviceGroup(guid string) error

	// Strategies (permission policies — API-port consolidation Phase A)
	ListStrategies() ([]*Strategy, error)
	GetStrategy(guid string) (*Strategy, error)
	CreateStrategy(s *Strategy) error
	UpdateStrategy(guid string, s *Strategy) error
	DeleteStrategy(guid string) error

	// Pro-style direct strategy assignments (device / user / device group)
	AssignStrategy(strategyGUID string, peerKeys, userKeys, groupKeys []string) error
	GetStrategyAssignmentSummary(strategyGUID string) (*StrategyAssignmentSummary, error)
	ResolvePeerAssignmentKey(ref string) (string, error)
	ResolveUserAssignmentKey(ref string) (string, error)
	ResolveDeviceGroupAssignmentKey(ref string) (string, error)
	EnsurePeerGUID(id string) (string, error)
	GetPeerIDByGUID(guid string) (string, error)
	SetStrategyEnabled(guid string, enabled bool) error
	ListProDeviceRefs(idFilter string, limit, offset int) ([]ProDeviceRef, int, error)

	// Billing / commercialization
	CreateBillingPackage(p *BillingPackage) error
	GetBillingPackage(id string) (*BillingPackage, error)
	ListBillingPackages() ([]*BillingPackage, error)
	UpdateBillingPackage(p *BillingPackage) error
	DeleteBillingPackage(id string) error

	CreateBillingOrgContract(c *BillingOrgContract) error
	GetBillingOrgContract(id string) (*BillingOrgContract, error)
	GetActiveBillingOrgContract(orgID string) (*BillingOrgContract, error)
	ListBillingOrgContracts(filter BillingContractFilter) ([]*BillingOrgContract, error)
	UpdateBillingOrgContract(c *BillingOrgContract) error

	CreateBillingContract(c *BillingContract) error
	GetBillingContract(id string) (*BillingContract, error)
	// GetActiveBillingContract returns the contract in force for a target:
	// an active or a suspended one (a suspended contract refuses
	// connections, so it must not be skipped for a group or org contract).
	GetActiveBillingContract(targetType, targetKey string) (*BillingContract, error)
	ListBillingContracts(filter BillingContractFilter) ([]*BillingContract, error)
	UpdateBillingContract(c *BillingContract) error
	DeleteBillingContract(id string) error
	CountBillingContractsByPackage(packageID string) (int, error)
	CountBillingContractsExpiringWithin(days int) (int, error)

	CreateBillingSession(s *BillingSession) error
	GetBillingSession(id string) (*BillingSession, error)
	GetBillingSessionByRelayUUID(relayUUID string) (*BillingSession, error)
	UpdateBillingSession(s *BillingSession) error
	ListBillingSessions(filter BillingSessionFilter) ([]*BillingSession, error)

	InsertBillingLedgerEntry(e *BillingSessionLedger) error
	ListBillingLedger(sessionID string) ([]*BillingSessionLedger, error)

	CreateBillingWorkReport(r *BillingWorkReport) error
	GetBillingWorkReportBySession(sessionID string) (*BillingWorkReport, error)
	ListBillingWorkReports(orgID string, limit int) ([]*BillingWorkReport, error)

	// RustDesk client sessions (DB-backed opaque tokens with sliding expiry)
	EnsureClientSessionsSchema() error
	CreateClientSession(sess *ClientSession) error
	GetClientSessionByTokenHash(tokenHash string) (*ClientSession, error)
	GetActiveClientSessionByClient(clientID, clientUUID string) (*ClientSession, error)
	TouchClientSession(id int64, expiresAt, lastUsed string) error
	RevokeClientSessionByTokenHash(tokenHash string) error
	RevokeClientSessionsForDevice(userID int64, clientID, clientUUID string) error
	CleanupExpiredClientSessions() (int64, error)

	ListBillingCurrencies() ([]*BillingCurrency, error)
	UpsertBillingCurrency(c *BillingCurrency) error
	DeleteBillingCurrency(code string) error

	UpsertBillingPeriodTotal(t *BillingPeriodTotal) error
	AddBillingPeriodUsage(contractID, packageID, periodYM, timezone string, includedUsed, overageMin int, amountOverage float64, limitSnapshot int) error
	GetBillingPeriodTotal(contractID, periodYM string) (*BillingPeriodTotal, error)
	ListBillingPeriodTotalsByPackage(packageID string) ([]*BillingPeriodTotal, error)
	ListBillingPeriodTotalsByContract(contractID string) ([]*BillingPeriodTotal, error)
}
