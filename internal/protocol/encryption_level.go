package protocol

// EncryptionLevel is the encryption level
// Default value is Unencrypted
type EncryptionLevel int

const (
	// EncryptionUnspecified is a not specified encryption level
	EncryptionUnspecified EncryptionLevel = iota
	// EncryptionInitial is the Initial encryption level
	EncryptionInitial
	// EncryptionHandshake is the Handshake encryption level
	EncryptionHandshake
	// Encryption0RTT is the 0-RTT encryption level
	Encryption0RTT
	// Encryption1RTT is the 1-RTT encryption level
	Encryption1RTT
	// Encryption1RTT is the 1-RTT encryption level
	EncryptionMulti
)

func (e EncryptionLevel) String() string {
	switch e {
	case EncryptionInitial:
		return "Initial"
	case EncryptionHandshake:
		return "Handshake"
	case Encryption0RTT:
		return "0-RTT"
	case Encryption1RTT:
		return "1-RTT"
	case EncryptionMulti:
		return "Multi encryption"
	}
	return "unknown"
}
