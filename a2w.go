package a2w

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"

    "golang.org/x/crypto/argon2"
)

var (
    InvalidHash = errors.New("the encoded hash is not in the correct format")
    IncompatibleVersion = errors.New("incompatible version of argon2")
)

type Params struct {
    memory      uint32
    iterations  uint32
    parallelism uint8
    saltLength  uint32
    keyLength   uint32
}

var Default = &Params{64 * 1024, 3, 2, 16, 32}

func salt(n uint32) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        return nil, err
    }

    return b, nil
}

func Hash(pwd string) (encodedHash string, err error) {
    salt, err := salt(Default.saltLength)
    if err != nil {
        return "", err
    }

    hash := argon2.IDKey([]byte(pwd), salt, Default.iterations, Default.memory, Default.parallelism, Default.keyLength)

    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)

    encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, Default.memory, Default.iterations, Default.parallelism, b64Salt, b64Hash)

    return encodedHash, nil
}

func Verify(pwd, encodedHash string) (match bool, err error) {
    p, salt, hash, err := decode(encodedHash)
    if err != nil {
        return false, err
    }

    otherHash := argon2.IDKey([]byte(pwd), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

    if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
        return true, nil
    }
    return false, nil
}

func decode(encodedHash string) (p *Params, salt, hash []byte, err error) {
    vals := strings.Split(encodedHash, "$")
    if len(vals) != 6 {
        return nil, nil, nil, InvalidHash
    }

    var version int
    _, err = fmt.Sscanf(vals[2], "v=%d", &version)
    if err != nil {
        return nil, nil, nil, err
    }
    if version != argon2.Version {
        return nil, nil, nil, IncompatibleVersion
    }

    p = &Params{}
    _, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
    if err != nil {
        return nil, nil, nil, err
    }

    salt, err = base64.RawStdEncoding.DecodeString(vals[4])
    if err != nil {
        return nil, nil, nil, err
    }
    p.saltLength = uint32(len(salt))

    hash, err = base64.RawStdEncoding.DecodeString(vals[5])
    if err != nil {
        return nil, nil, nil, err
    }
    p.keyLength = uint32(len(hash))

    return p, salt, hash, nil
}